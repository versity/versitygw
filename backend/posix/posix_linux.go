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

	"golang.org/x/sys/unix"
)

const procfddir = "/proc/self/fd"

type tmpfile struct {
	f       *os.File
	bucket  string
	objname string
	isOTmp  bool
	size    int64
}

func openTmpFile(dir, bucket, obj string, size int64) (*tmpfile, error) {
	// O_TMPFILE allows for a file handle to an unnamed file in the filesystem.
	// This can help reduce contention within the namespace (parent directories),
	// etc. And will auto cleanup the inode on close if we never link this
	// file descriptor into the namespace.
	// Not all filesystems support this, so fallback to CreateTemp for when
	// this is not supported.
	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0666)
	if err != nil {
		// O_TMPFILE not supported, try fallback
		f, err := os.CreateTemp(dir,
			fmt.Sprintf("%x.", sha256.Sum256([]byte(obj))))
		if err != nil {
			return nil, err
		}
		tmp := &tmpfile{f: f, bucket: bucket, objname: obj, size: size}
		// falloc is best effort, its fine if this fails
		if size > 0 {
			tmp.falloc()
		}
		return tmp, nil
	}

	// for O_TMPFILE, filename is /proc/self/fd/<fd> to be used
	// later to link file into namespace
	f := os.NewFile(uintptr(fd), filepath.Join(procfddir, strconv.Itoa(fd)))

	tmp := &tmpfile{f: f, isOTmp: true, size: size}
	// falloc is best effort, its fine if this fails
	if size > 0 {
		tmp.falloc()
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

	if !tmp.isOTmp {
		// O_TMPFILE not suported, use fallback
		return tmp.fallbackLink()
	}

	procdir, err := os.Open(procfddir)
	if err != nil {
		return fmt.Errorf("open proc dir: %w", err)
	}
	defer procdir.Close()

	dir, err := os.Open(filepath.Dir(objPath))
	if err != nil {
		return fmt.Errorf("open parent dir: %w", err)
	}
	defer dir.Close()

	err = unix.Linkat(int(procdir.Fd()), filepath.Base(tmp.f.Name()),
		int(dir.Fd()), filepath.Base(objPath), unix.AT_SYMLINK_FOLLOW)
	if err != nil {
		return fmt.Errorf("link tmpfile: %w", err)
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

	err := tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	objPath := filepath.Join(tmp.bucket, tmp.objname)
	err = os.Rename(tempname, objPath)
	if err != nil {
		return fmt.Errorf("rename tmpfile: %w", err)
	}

	return nil
}

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length")
	}

	n, err := tmp.f.Write(b)
	tmp.size -= int64(n)
	return n, err
}

func (tmp *tmpfile) cleanup() {
	tmp.f.Close()
}
