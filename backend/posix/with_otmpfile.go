// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build linux
// +build linux

package posix

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sys/unix"
)

const procfddir = "/proc/self/fd"

type tmpfile struct {
	f          *os.File
	bucket     string
	objname    string
	isOTmp     bool
	size       int64
	needsChown bool
	uid        int
	gid        int
	newDirPerm fs.FileMode
}

var (
	// TODO: make this configurable
	defaultFilePerm uint32 = 0644
)

func (p *Posix) openTmpFile(dir, bucket, obj string, size int64, acct auth.Account, dofalloc bool, forceNoTmpFile bool) (*tmpfile, error) {
	uid, gid, doChown := p.getChownIDs(acct)

	if forceNoTmpFile {
		return p.openMkTemp(dir, bucket, obj, size, dofalloc, uid, gid, doChown)
	}

	// O_TMPFILE allows for a file handle to an unnamed file in the filesystem.
	// This can help reduce contention within the namespace (parent directories),
	// etc. And will auto cleanup the inode on close if we never link this
	// file descriptor into the namespace.
	// Not all filesystems support this, so fallback to CreateTemp for when
	// this is not supported.
	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, defaultFilePerm)
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}

		// O_TMPFILE not supported, try fallback
		return p.openMkTemp(dir, bucket, obj, size, dofalloc, uid, gid, doChown)
	}

	// for O_TMPFILE, filename is /proc/self/fd/<fd> to be used
	// later to link file into namespace
	f := os.NewFile(uintptr(fd), filepath.Join(procfddir, strconv.Itoa(fd)))

	tmp := &tmpfile{
		f:          f,
		bucket:     bucket,
		objname:    obj,
		isOTmp:     true,
		size:       size,
		needsChown: doChown,
		uid:        uid,
		gid:        gid,
		newDirPerm: p.newDirPerm,
	}

	// falloc is best effort, its fine if this fails
	if size > 0 && dofalloc {
		tmp.falloc()
	}

	if doChown {
		err := f.Chown(uid, gid)
		if err != nil {
			return nil, fmt.Errorf("set temp file ownership: %w", err)
		}
	}

	return tmp, nil
}

func (p *Posix) openMkTemp(dir, bucket, obj string, size int64, dofalloc bool, uid, gid int, doChown bool) (*tmpfile, error) {
	err := backend.MkdirAll(dir, uid, gid, doChown, p.newDirPerm)
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		return nil, fmt.Errorf("make temp dir: %w", err)
	}
	f, err := os.CreateTemp(dir,
		fmt.Sprintf("%x.", sha256.Sum256([]byte(obj))))
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		return nil, err
	}
	tmp := &tmpfile{
		f:          f,
		bucket:     bucket,
		objname:    obj,
		size:       size,
		needsChown: doChown,
		uid:        uid,
		gid:        gid,
	}
	// falloc is best effort, its fine if this fails
	if size > 0 && dofalloc {
		tmp.falloc()
	}

	if doChown {
		err := f.Chown(uid, gid)
		if err != nil {
			return nil, fmt.Errorf("set temp file ownership: %w", err)
		}
	}

	return tmp, nil
}

func (tmp *tmpfile) falloc() error {
	err := syscall.Fallocate(int(tmp.f.Fd()), 0, 0, tmp.size)
	if err != nil {
		return fmt.Errorf("fallocate: %v", err)
	}
	return nil
}

func (tmp *tmpfile) link() error {
	// make sure this is cleaned up in all error cases
	defer tmp.f.Close()

	// We use Linkat/Rename as the atomic operation for object puts. The
	// upload is written to a temp (or unnamed/O_TMPFILE) file to not conflict
	// with any other simultaneous uploads. The final operation is to move the
	// temp file into place for the object. This ensures the object semantics
	// of last upload completed wins and is not some combination of writes
	// from simultaneous uploads.
	objPath := filepath.Join(tmp.bucket, tmp.objname)
	err := os.Remove(objPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale path: %w", err)
	}

	dir := filepath.Dir(objPath)

	err = backend.MkdirAll(dir, tmp.uid, tmp.gid, tmp.needsChown, tmp.newDirPerm)
	if err != nil {
		return fmt.Errorf("make parent dir: %w", err)
	}

	if !tmp.isOTmp {
		// O_TMPFILE not suported, use fallback
		return tmp.fallbackLink()
	}

	procdir, err := os.Open(procfddir)
	if err != nil {
		return fmt.Errorf("open proc dir: %w", err)
	}
	defer procdir.Close()

	dirf, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent dir: %w", err)
	}
	defer dirf.Close()

	for {
		err = unix.Linkat(int(procdir.Fd()), filepath.Base(tmp.f.Name()),
			int(dirf.Fd()), filepath.Base(objPath), unix.AT_SYMLINK_FOLLOW)
		if errors.Is(err, syscall.EEXIST) {
			err := os.Remove(objPath)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove stale path: %w", err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("link tmpfile (fd %q as %q): %w",
				filepath.Base(tmp.f.Name()), objPath, err)
		}
		break
	}

	err = tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	return nil
}

func (tmp *tmpfile) fallbackLink() error {
	tempname := tmp.f.Name()
	// cleanup in case anything goes wrong, if rename succeeds then
	// this will no longer exist
	defer os.Remove(tempname)

	// reset default file mode because CreateTemp uses 0600
	tmp.f.Chmod(fs.FileMode(defaultFilePerm))

	err := tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	objPath := filepath.Join(tmp.bucket, tmp.objname)
	err = os.Rename(tempname, objPath)
	if err != nil {
		// rename only works for files within the same filesystem
		// if this fails fallback to copy
		return backend.MoveFile(tempname, objPath, fs.FileMode(defaultFilePerm))
	}

	return nil
}

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length %v", tmp.size)
	}

	n, err := tmp.f.Write(b)
	tmp.size -= int64(n)
	return n, err
}

func (tmp *tmpfile) cleanup() {
	tmp.f.Close()
}

func (tmp *tmpfile) File() *os.File {
	return tmp.f
}
