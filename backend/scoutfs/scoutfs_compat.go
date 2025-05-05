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

//go:build linux && amd64

package scoutfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/versity/scoutfs-go"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/s3err"
)

func New(rootdir string, opts ScoutfsOpts) (*ScoutFS, error) {
	metastore := meta.XattrMeta{}

	p, err := posix.New(rootdir, metastore, posix.PosixOpts{
		ChownUID:    opts.ChownUID,
		ChownGID:    opts.ChownGID,
		BucketLinks: opts.BucketLinks,
		NewDirPerm:  opts.NewDirPerm,
	})
	if err != nil {
		return nil, err
	}

	f, err := os.Open(rootdir)
	if err != nil {
		return nil, fmt.Errorf("open %v: %w", rootdir, err)
	}

	return &ScoutFS{
		Posix:            p,
		rootfd:           f,
		rootdir:          rootdir,
		meta:             metastore,
		chownuid:         opts.ChownUID,
		chowngid:         opts.ChownGID,
		glaciermode:      opts.GlacierMode,
		newDirPerm:       opts.NewDirPerm,
		disableNoArchive: opts.DisableNoArchive,
	}, nil
}

const procfddir = "/proc/self/fd"

type tmpfile struct {
	f          *os.File
	bucket     string
	objname    string
	size       int64
	needsChown bool
	uid        int
	gid        int
	newDirPerm fs.FileMode
}

var (
	defaultFilePerm uint32 = 0644
)

func (s *ScoutFS) openTmpFile(dir, bucket, obj string, size int64, acct auth.Account) (*tmpfile, error) {
	uid, gid, doChown := s.getChownIDs(acct)

	// O_TMPFILE allows for a file handle to an unnamed file in the filesystem.
	// This can help reduce contention within the namespace (parent directories),
	// etc. And will auto cleanup the inode on close if we never link this
	// file descriptor into the namespace.
	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, defaultFilePerm)
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		return nil, err
	}

	// for O_TMPFILE, filename is /proc/self/fd/<fd> to be used
	// later to link file into namespace
	f := os.NewFile(uintptr(fd), filepath.Join(procfddir, strconv.Itoa(fd)))

	tmp := &tmpfile{
		f:          f,
		bucket:     bucket,
		objname:    obj,
		size:       size,
		needsChown: doChown,
		uid:        uid,
		gid:        gid,
		newDirPerm: s.newDirPerm,
	}

	if doChown {
		err := f.Chown(uid, gid)
		if err != nil {
			return nil, fmt.Errorf("set temp file ownership: %w", err)
		}
	}

	return tmp, nil
}

func (tmp *tmpfile) link() error {
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
		if errors.Is(err, fs.ErrExist) {
			err := os.Remove(objPath)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove stale path: %w", err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("link tmpfile: %w", err)
		}
		break
	}

	err = tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
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

func moveData(from *os.File, to *os.File) error {
	return scoutfs.MoveData(from, to)
}

func statMore(path string) (stat, error) {
	st, err := scoutfs.StatMore(path)
	if err != nil {
		return stat{}, err
	}
	var s stat

	s.Meta_seq = st.Meta_seq
	s.Data_seq = st.Data_seq
	s.Data_version = st.Data_version
	s.Online_blocks = st.Online_blocks
	s.Offline_blocks = st.Offline_blocks
	s.Crtime_sec = st.Crtime_sec
	s.Crtime_nsec = st.Crtime_nsec

	return s, nil
}
