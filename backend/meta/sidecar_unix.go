// Copyright 2026 Versity Software
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

//go:build !windows

package meta

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// trimVolume is a no-op on non-Windows platforms.
func trimVolume(p string) string { return p }

func isErrDirNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST)
}

func isRetryableMetaDirErr(err error, metadir string, dirInfo os.FileInfo) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESTALE) || errors.Is(err, syscall.ENOTDIR) {
		return true
	}
	// Only retry EINVAL when metadir disappeared or was replaced by a new
	// inode; do not mask a genuine EINVAL on an untouched live directory.
	if !errors.Is(err, syscall.EINVAL) {
		return false
	}
	afterInfo, statErr := os.Lstat(metadir)
	if statErr != nil {
		return errors.Is(statErr, os.ErrNotExist) || errors.Is(statErr, syscall.ESTALE) || errors.Is(statErr, syscall.ENOTDIR)
	}
	if dirInfo == nil {
		return afterInfo.IsDir()
	}
	return !os.SameFile(dirInfo, afterInfo)
}

func ignoringEINTR(fn func() error) error {
	for {
		err := fn()
		if err != syscall.EINTR {
			return err
		}
	}
}

func openDirEINTR(path string, flags int) (int, error) {
	var fd int
	err := ignoringEINTR(func() error {
		var oerr error
		fd, oerr = unix.Open(path, flags, 0)
		return oerr
	})
	return fd, err
}

func openatEINTR(dirfd int, path string, flags int) (int, error) {
	var fd int
	err := ignoringEINTR(func() error {
		var oerr error
		fd, oerr = unix.Openat(dirfd, path, flags, 0)
		return oerr
	})
	return fd, err
}

func unlinkatEINTR(dirfd int, path string, flags int) error {
	return ignoringEINTR(func() error {
		return unix.Unlinkat(dirfd, path, flags)
	})
}

// removeSidecarSubtree removes relPath beneath rootDir using descriptor-relative
// O_NOFOLLOW opens so neither external nor in-root relative symlinks are ever
// followed. It ignores ENOTEMPTY/EEXIST on directory removal caused by concurrent
// writers while surfacing real child removal errors immediately.
func removeSidecarSubtree(rootDir, relPath string) error {
	parts, err := splitSidecarRelPath(relPath)
	if err != nil || len(parts) == 0 {
		return err
	}

	curFd, err := openDirEINTR(rootDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err == syscall.ENOENT {
		return nil
	}
	if err != nil {
		return &os.PathError{Op: "open", Path: rootDir, Err: err}
	}

	for _, seg := range parts[:len(parts)-1] {
		nextFd, err := openatEINTR(curFd, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
		_ = unix.Close(curFd)
		if err == syscall.ENOENT {
			return nil
		}
		if err != nil {
			return &os.PathError{Op: "open", Path: seg, Err: err}
		}
		curFd = nextFd
	}

	err = removeAt(curFd, parts[len(parts)-1])
	_ = unix.Close(curFd)
	return err
}

func removeAt(parentFd int, name string) error {
	err := unlinkatEINTR(parentFd, name, 0)
	if err == nil || err == syscall.ENOENT {
		return nil
	}
	// Linux returns EISDIR for unlinkat on a directory; macOS/BSD return EPERM.
	if err != syscall.EISDIR && err != syscall.EPERM && err != syscall.EACCES {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	err = unlinkatEINTR(parentFd, name, unix.AT_REMOVEDIR)
	if err == nil || err == syscall.ENOENT {
		return nil
	}

	childFd, oerr := openatEINTR(parentFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if oerr == syscall.ENOENT {
		return nil
	}
	// ELOOP (Linux/macOS), EMLINK (FreeBSD O_NOFOLLOW on symlink), or ENOTDIR
	// means name is now a symlink or regular file rather than a directory:
	// unlink the entry itself without following any symlink target.
	if oerr == syscall.ELOOP || oerr == syscall.EMLINK || oerr == syscall.ENOTDIR {
		uerr := unlinkatEINTR(parentFd, name, 0)
		if uerr == nil || uerr == syscall.ENOENT {
			return nil
		}
		return &os.PathError{Op: "remove", Path: name, Err: uerr}
	}
	if oerr != nil {
		return &os.PathError{Op: "open", Path: name, Err: oerr}
	}

	f := os.NewFile(uintptr(childFd), name)
	names, rerr := f.Readdirnames(-1)
	if rerr != nil {
		_ = f.Close()
		if errors.Is(rerr, os.ErrNotExist) {
			return nil
		}
		return rerr
	}

	fd := int(f.Fd())
	for _, childName := range names {
		if cerr := removeAt(fd, childName); cerr != nil {
			_ = f.Close()
			return cerr
		}
	}

	_ = f.Close()

	err = unlinkatEINTR(parentFd, name, unix.AT_REMOVEDIR)
	if err == nil || err == syscall.ENOENT || isErrDirNotEmpty(err) {
		return nil
	}
	return &os.PathError{Op: "remove", Path: name, Err: err}
}
