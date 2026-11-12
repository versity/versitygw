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
	"strings"
	"syscall"
	"time"

	"github.com/pkg/xattr"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sys/unix"
)

const procfddir = "/proc/self/fd"

type tmpfile struct {
	f           *os.File
	bucket      string
	objname     string
	isOTmp      bool
	procFDName  string
	useODirect  bool
	size        int64
	doChown     bool
	uid         int
	gid         int
	newDirPerm  fs.FileMode
	newFilePerm fs.FileMode
	fsync       bool
	// modTime is the modification time the file is published with,
	// the time it was last written if zero
	modTime time.Time
}

// maxTmpDirRetries bounds how many times a new object's O_TMPFILE is opened
// again in another directory after the one chosen for it was removed or
// replaced
const maxTmpDirRetries = 3

// openat opens the O_TMPFILE, a variable so that tests can make it fail
var openat = unix.Openat

// openTmpFileIn opens an O_TMPFILE in otmpDir, or a named temporary file in
// tmpDir when O_TMPFILE is disabled or not supported by the filesystem. A
// named file is never made in otmpDir, where it could be listed before it is
// published.
//
// With inherit, otmpDir is the directory the object is published in and the
// O_TMPFILE is made in it, or in its closest existing parent, so that the
// directory's default ACL applies to the file. Only an O_TMPFILE that is not
// supported falls back to the named file then: any other error is returned,
// so that a full or read-only filesystem, a quota or a permission error in
// that directory is reported, not hidden by a file made somewhere else.
func (p *Posix) openTmpFileIn(otmpDir, tmpDir, bucket, obj string, size int64, acct auth.Account, dofalloc, inherit bool, allowODirect odirectPolicy) (*tmpfile, error) {
	uid, gid, doChown := p.getChownIDs(acct)

	// The tmpfile keeps the bucket directory's path so that link() and its
	// fallbacks address it the same way as every other bucket path.
	bucket = p.BucketPath(bucket)

	if p.forceNoTmpFile {
		return p.openMkTemp(tmpDir, bucket, obj, size, dofalloc, uid, gid, doChown, allowODirect)
	}

	// A bucket whose filesystem can't set xattrs on an O_TMPFILE goes
	// straight to the named file, without opening an O_TMPFILE first.
	if v, ok := p.otmpXattr.Load(bucket); ok && !v.(bool) {
		return p.openMkTemp(tmpDir, bucket, obj, size, dofalloc, uid, gid, doChown, allowODirect)
	}

	// O_TMPFILE allows for a file handle to an unnamed file in the filesystem.
	// This can help reduce contention within the namespace (parent directories),
	// etc. And will auto cleanup the inode on close if we never link this
	// file descriptor into the namespace.
	// Not all filesystems support this, so fallback to CreateTemp for when
	// this is not supported.
	var (
		fd         int
		useODirect bool
		hasACL     bool
		err        error
	)
	if inherit {
		fd, useODirect, hasACL, err = p.openInheritingTmpFile(bucket, otmpDir, allowODirect)
	} else {
		fd, useODirect, err = p.openOTmpFile(unix.AT_FDCWD, otmpDir, allowODirect)
	}
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		if !inherit || otmpfileUnsupported(err) {
			// O_TMPFILE not supported, try fallback
			return p.openMkTemp(tmpDir, bucket, obj, size, dofalloc, uid, gid, doChown, allowODirect)
		}
		return nil, fmt.Errorf("open temp file: %w", err)
	}

	// for O_TMPFILE, filename is /proc/self/fd/<fd> to be used
	// later to link file into namespace
	f := os.NewFile(uintptr(fd), filepath.Join(procfddir, strconv.Itoa(fd)))

	// Some filesystems open an O_TMPFILE but can't set xattrs on it, which
	// the object's metadata needs. Use a named temporary file there.
	// The result is remembered per bucket, as buckets can be on different
	// filesystems, so that the probe runs once.
	if _, ok := p.meta.(meta.XattrMeta); ok {
		// Re-check after opening: a concurrent upload may have probed
		// this bucket and found it unsupported since the check above.
		v, known := p.otmpXattr.Load(bucket)
		if !known {
			err := probeTmpFileXattr(f)
			switch {
			case err == nil:
				p.otmpXattr.Store(bucket, true)
			case tmpfileXattrUnsupported(err):
				p.otmpXattr.Store(bucket, false)
				known, v = true, false
			}
		}
		if known && !v.(bool) {
			f.Close()
			return p.openMkTemp(tmpDir, bucket, obj, size, dofalloc, uid, gid, doChown, allowODirect)
		}
	}

	// The mode passed to open() is masked by the process umask. Set the
	// configured mode explicitly so new objects get the same permissions
	// regardless of umask, and regardless of whether this or the CreateTemp
	// fallback path (which also chmods) created the file.
	mode := p.newFilePerm
	if hasACL {
		// The directory's default ACL gave the file its group (or mask)
		// and other permissions, limited by the mode it was created with:
		// keep them, as setting them to newFilePerm could grant more than
		// the directory allows. The owner permissions are still set to
		// newFilePerm, so that the gateway can always write the object's
		// attributes, even when the ACL gives the owner less. On a file
		// with an ACL, chmod sets the mask, not the group entry, so the
		// named entries keep what the ACL gave them.
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("stat temp file: %w", err)
		}
		mode = fi.Mode().Perm()&^0o700 | p.newFilePerm.Perm()&0o700
	}
	err = f.Chmod(mode)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("set temp file mode: %w", err)
	}

	tmp := &tmpfile{
		f:           f,
		bucket:      bucket,
		objname:     obj,
		isOTmp:      true,
		procFDName:  strconv.Itoa(fd),
		useODirect:  useODirect,
		size:        size,
		doChown:     doChown,
		uid:         uid,
		gid:         gid,
		newDirPerm:  p.newDirPerm,
		newFilePerm: p.newFilePerm,
		fsync:       p.fsync,
	}

	// falloc is best effort, its fine if this fails
	if size > 0 && dofalloc {
		p.falloc(tmp)
	}

	if doChown {
		err := f.Chown(uid, gid)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("set temp file ownership: %w", p.chownErr(filepath.Join(bucket, obj), uid, gid, err))
		}
	}

	return tmp, nil
}

// probeTmpFileXattr sets and removes an attribute on the open O_TMPFILE, a
// variable so that tests can make it fail
var probeTmpFileXattr = origProbeTmpFileXattr

func origProbeTmpFileXattr(f *os.File) error {
	const name = "user.vgw.xattr-probe"
	if err := xattr.FSet(f, name, []byte{}); err != nil {
		return err
	}
	_ = xattr.FRemove(f, name)
	return nil
}

// tmpfileXattrUnsupported reports whether err means that xattrs can't be set
// on an O_TMPFILE, as opposed to a full, read-only or quota-limited filesystem.
func tmpfileXattrUnsupported(err error) bool {
	return errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS)
}

// openOTmpFile opens an O_TMPFILE in the directory path, relative to dirfd,
// with O_DIRECT when it is enabled and allowed, and without it when the
// filesystem does not support O_DIRECT.
func (p *Posix) openOTmpFile(dirfd int, path string, allowODirect odirectPolicy) (fd int, useODirect bool, err error) {
	openFlags := unix.O_RDWR | unix.O_TMPFILE | unix.O_CLOEXEC
	filePerm := uint32(p.newFilePerm.Perm())
	if p.enableODirect && bool(allowODirect) {
		fd, err = openat(dirfd, path, openFlags|unix.O_DIRECT, filePerm)
		if err == nil {
			return fd, true, nil
		}
		if !isODirectUnsupportedOpenErr(err) {
			return -1, false, err
		}
		warnODirectUnsupportedOnce("openTmpFile", err)
	}
	fd, err = openat(dirfd, path, openFlags, filePerm)
	return fd, false, err
}

// openInheritingTmpFile opens an O_TMPFILE in dir, the directory a new object
// is published in, or in its closest existing parent below bucketPath, and
// reports whether that directory has a default ACL. The directory is opened
// once and both the file and the ACL are taken from that handle, so they
// come from the same directory even when its path is replaced meanwhile.
// When the directory is removed or replaced before the file is made in it,
// for instance by a DeleteObject removing the parents of its last object,
// another one is chosen.
func (p *Posix) openInheritingTmpFile(bucketPath, dir string, allowODirect odirectPolicy) (fd int, useODirect, hasACL bool, err error) {
	for attempt := 0; ; attempt++ {
		var d string
		d, err = closestDir(bucketPath, dir)
		if err != nil {
			return -1, false, false, err
		}
		fd, useODirect, hasACL, err = p.openTmpFileInDir(d, allowODirect)
		if err == nil || attempt == maxTmpDirRetries || !dirGone(err) {
			return fd, useODirect, hasACL, err
		}
	}
}

// openTmpFileInDir opens an O_TMPFILE in dir and reports whether dir has a
// default ACL. The directory is opened with O_PATH, which needs no read
// permission on it: an O_TMPFILE needs only write and search permission, so
// a directory the gateway can't list, but can write to, is supported.
func (p *Posix) openTmpFileInDir(dir string, allowODirect odirectPolicy) (fd int, useODirect, hasACL bool, err error) {
	dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, false, err
	}
	defer unix.Close(dirfd)

	fd, useODirect, err = p.openOTmpFile(dirfd, ".", allowODirect)
	if err != nil {
		return -1, false, false, err
	}
	hasACL, err = hasDefaultACLFd(dirfd)
	if err != nil {
		unix.Close(fd)
		return -1, false, false, fmt.Errorf("get default ACL of %v: %w", dir, err)
	}
	return fd, useODirect, hasACL, nil
}

// otmpfileUnsupported reports whether err is the error open() returns when
// the filesystem, or the kernel, does not support O_TMPFILE.
func otmpfileUnsupported(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EISDIR)
}

// dirGone reports whether err is the error of a directory that was removed or
// replaced by a file while it was being opened.
func dirGone(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ESTALE)
}

func (p *Posix) openMkTemp(dir, bucket, obj string, size int64, dofalloc bool, uid, gid int, doChown bool, allowODirect odirectPolicy) (*tmpfile, error) {
	err := p.mkdirAll(dir, uid, gid, doChown)
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

	useODirect := false
	if p.enableODirect && bool(allowODirect) {
		name := f.Name()
		if err := f.Close(); err != nil {
			os.Remove(name)
			return nil, fmt.Errorf("close temp file before O_DIRECT reopen: %w", err)
		}

		fd, err := unix.Open(name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_DIRECT, uint32(p.newFilePerm.Perm()))
		if err == nil {
			f = os.NewFile(uintptr(fd), name)
			useODirect = true
		} else if isODirectUnsupportedOpenErr(err) {
			warnODirectUnsupportedOnce("openMkTemp", err)
			f, err = os.OpenFile(name, os.O_RDWR, 0)
			if err != nil {
				os.Remove(name)
				return nil, fmt.Errorf("reopen temp file after O_DIRECT fallback: %w", err)
			}
		} else {
			os.Remove(name)
			return nil, fmt.Errorf("open temp file with O_DIRECT: %w", err)
		}
	}

	tmp := &tmpfile{
		f:           f,
		bucket:      bucket,
		objname:     obj,
		useODirect:  useODirect,
		size:        size,
		doChown:     doChown,
		uid:         uid,
		gid:         gid,
		newDirPerm:  p.newDirPerm,
		newFilePerm: p.newFilePerm,
		fsync:       p.fsync,
	}
	// falloc is best effort, its fine if this fails
	if size > 0 && dofalloc {
		p.falloc(tmp)
	}

	if doChown {
		err := f.Chown(uid, gid)
		if err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, fmt.Errorf("set temp file ownership: %w", p.chownErr(filepath.Join(bucket, obj), uid, gid, err))
		}
	}

	return tmp, nil
}

// fallocate is swapped out by tests to simulate unsupported filesystems.
var fallocate = syscall.Fallocate

// falloc preallocates tmp, skipping bucket paths that rejected fallocate.
func (p *Posix) falloc(tmp *tmpfile) {
	if _, ok := p.fallocUnsupported.Load(tmp.bucket); ok {
		return
	}
	err := fallocate(int(tmp.f.Fd()), 0, 0, tmp.size)
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) {
		p.fallocUnsupported.Store(tmp.bucket, struct{}{})
	}
}

const (
	maxTmpFileNameRetries = 3
	initialBackoffMs      = 1
	maxBackoffMs          = 1024 // ~1 second
)

// linkatOTmpfile links the O_TMPFILE identified by procdir/fdName into dir/basename.
// Handles EEXIST by linking to a temporary name and atomically renaming it into place.
func linkatOTmpfile(procdirFd, dirFd int, fdName, basename string) error {
	err := unix.Linkat(procdirFd, fdName, dirFd, basename, unix.AT_SYMLINK_FOLLOW)
	if !errors.Is(err, syscall.EEXIST) {
		return err
	}
	// Linkat cannot overwrite an existing file; link to a temp name then rename atomically.
	for retries := 1; ; retries++ {
		tmpName := fmt.Sprintf(".%s.sgwtmp.%d", basename, time.Now().UnixNano())
		err := unix.Linkat(procdirFd, fdName, dirFd, tmpName, unix.AT_SYMLINK_FOLLOW)
		if errors.Is(err, syscall.EEXIST) && retries < maxTmpFileNameRetries {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot find free temporary file: %w", err)
		}
		err = unix.Renameat(dirFd, tmpName, dirFd, basename)
		if err != nil {
			// cleanup temp name previously linked into namespace
			_ = unix.Unlinkat(dirFd, tmpName, 0)
			return fmt.Errorf("overwriting renameat failed: %w", err)
		}
		return nil
	}
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

	dir := filepath.Dir(objPath)

	if !tmp.isOTmp {
		// O_TMPFILE not supported, use fallback
		return tmp.fallbackLink()
	}

	// the unnamed file has no path until it's linked
	err := tmp.applyModTime(filepath.Join(procfddir, tmp.procFDName))
	if err != nil {
		return fmt.Errorf("set tmpfile modification time: %w", err)
	}

	err = tmp.syncData()
	if err != nil {
		return err
	}

	procdir, err := os.Open(procfddir)
	if err != nil {
		return fmt.Errorf("open proc dir: %w", err)
	}
	defer procdir.Close()

	srcFDName := tmp.procFDName
	if srcFDName == "" {
		srcFDName = filepath.Base(tmp.f.Name())
	}

	var syncd *os.File
	err = tmp.publishInDir(dir, func() error {
		d, err := tmp.openDirForSync(dir)
		if err != nil {
			return fmt.Errorf("open parent dir: %w", err)
		}
		var dirfd int
		if d != nil {
			dirfd = int(d.Fd())
		} else {
			// O_PATH: linkat() and renameat() need write and search
			// permission on the directory, not read permission
			dirfd, err = unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("open parent dir: %w", &fs.PathError{Op: "open", Path: dir, Err: err})
			}
			defer unix.Close(dirfd)
		}

		err = linkatOTmpfile(int(procdir.Fd()), dirfd,
			srcFDName, filepath.Base(objPath))
		if err != nil {
			if d != nil {
				d.Close()
			}
			return fmt.Errorf("link tmpfile (fd %q as %q): %w",
				srcFDName, objPath, err)
		}
		syncd = d
		return nil
	})
	if err != nil {
		return err
	}

	err = tmp.f.Close()
	if err != nil {
		if syncd != nil {
			syncd.Close()
		}
		return fmt.Errorf("close tmpfile: %w", err)
	}

	return tmp.syncNamespace(syncd)
}

func (tmp *tmpfile) fallbackLink() error {
	tempname := tmp.f.Name()

	// reset default file mode because CreateTemp uses 0600
	tmp.f.Chmod(tmp.newFilePerm)

	err := tmp.applyModTime(tempname)
	if err != nil {
		tmp.f.Close()
		return fmt.Errorf("set tmpfile modification time: %w", err)
	}

	err = tmp.syncData()
	if err != nil {
		tmp.f.Close()
		return err
	}

	err = tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	objPath := filepath.Join(tmp.bucket, tmp.objname)
	var syncd *os.File
	err = tmp.publishInDir(filepath.Dir(objPath), func() error {
		d, err := tmp.openDirForSync(filepath.Dir(objPath))
		if err != nil {
			return fmt.Errorf("open parent dir: %w", err)
		}
		// rename only works for files within the same filesystem,
		// MoveFile falls back to copy otherwise
		err = backend.MoveFile(tempname, objPath, tmp.newFilePerm)
		if err != nil {
			if d != nil {
				d.Close()
			}
			return err
		}
		syncd = d
		return nil
	})
	if err != nil {
		return err
	}

	return tmp.syncNamespace(syncd)
}

func (tmp *tmpfile) cleanup() {
	tmp.f.Close()
	if !strings.HasPrefix(tmp.f.Name(), procfddir) {
		os.Remove(tmp.f.Name())
	}
}
