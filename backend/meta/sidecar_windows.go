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

//go:build windows

package meta

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	errPathNotFound     = syscall.Errno(3)
	errAccessDenied     = syscall.Errno(5)
	errSharingViolation = syscall.Errno(32)
	errDirNotEmpty      = syscall.Errno(145)
	errDirectory        = syscall.Errno(267)
)

// trimVolume strips the Windows drive letter (e.g. "C:") and any leading
// path separator from p so it can be safely used as a sub-path component
// inside filepath.Join without becoming an absolute root.
func trimVolume(p string) string {
	return strings.TrimLeft(p[len(filepath.VolumeName(p)):], `\/`)
}

func isErrDirNotEmpty(err error) bool {
	if errors.Is(err, syscall.ENOTEMPTY) {
		return true
	}
	var sysErr syscall.Errno
	return errors.As(err, &sysErr) && sysErr == errDirNotEmpty
}

func isErrSharingViolation(err error) bool {
	var sysErr syscall.Errno
	return errors.As(err, &sysErr) && sysErr == errSharingViolation
}

func isRetryableMetaDirErr(err error, metadir string, dirInfo os.FileInfo) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		if sysErr == errPathNotFound || sysErr == errDirectory || sysErr == errSharingViolation {
			return true
		}
	}
	if errors.Is(err, os.ErrPermission) || (errors.As(err, &sysErr) && sysErr == errAccessDenied) {
		afterInfo, statErr := os.Lstat(metadir)
		if statErr != nil {
			return errors.Is(statErr, os.ErrNotExist) ||
				(errors.As(statErr, &sysErr) && (sysErr == errPathNotFound || sysErr == errDirectory))
		}
		return dirInfo != nil && !os.SameFile(dirInfo, afterInfo)
	}
	return false
}

func removeWithSharingRetry(fn func() error) error {
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || !isErrSharingViolation(err) || attempt == maxMetaDirRetries {
			return err
		}
		waitMetaDirRetry(attempt)
	}
}

// removeSidecarSubtree removes relPath beneath rootDir using os.Root handles
// and explicit per-segment symlink checks so neither external nor in-root
// relative symlinks are followed.
func removeSidecarSubtree(rootDir, relPath string) error {
	parts, err := splitSidecarRelPath(relPath)
	if err != nil || len(parts) == 0 {
		return err
	}

	cur, err := os.OpenRoot(rootDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, seg := range parts[:len(parts)-1] {
		fi, lerr := cur.Lstat(seg)
		if errors.Is(lerr, os.ErrNotExist) {
			_ = cur.Close()
			return nil
		}
		if lerr != nil {
			_ = cur.Close()
			return lerr
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			_ = cur.Close()
			return &os.PathError{Op: "open", Path: seg, Err: syscall.ELOOP}
		}
		next, err := cur.OpenRoot(seg)
		_ = cur.Close()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		openedInfo, serr := next.Stat(".")
		if serr != nil || !os.SameFile(fi, openedInfo) {
			_ = next.Close()
			if errors.Is(serr, os.ErrNotExist) {
				return nil
			}
			return &os.PathError{Op: "open", Path: seg, Err: syscall.ELOOP}
		}
		cur = next
	}

	err = removeInRoot(cur, parts[len(parts)-1])
	_ = cur.Close()
	return err
}

func removeInRoot(parent *os.Root, name string) error {
	err := removeWithSharingRetry(func() error { return parent.Remove(name) })
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}

	fi, lerr := parent.Lstat(name)
	if errors.Is(lerr, os.ErrNotExist) {
		return nil
	}
	if lerr != nil {
		return err
	}
	if !fi.IsDir() {
		rerr := removeWithSharingRetry(func() error { return parent.Remove(name) })
		if rerr == nil || errors.Is(rerr, os.ErrNotExist) {
			return nil
		}
		return rerr
	}

	child, oerr := parent.OpenRoot(name)
	if errors.Is(oerr, os.ErrNotExist) {
		return nil
	}
	if oerr != nil {
		if fi2, lerr2 := parent.Lstat(name); lerr2 == nil && !fi2.IsDir() {
			rerr := removeWithSharingRetry(func() error { return parent.Remove(name) })
			if rerr == nil || errors.Is(rerr, os.ErrNotExist) {
				return nil
			}
			return rerr
		}
		return oerr
	}

	if openedInfo, serr := child.Stat("."); serr != nil || !os.SameFile(fi, openedInfo) {
		_ = child.Close()
		if errors.Is(serr, os.ErrNotExist) {
			return nil
		}
		if fi2, lerr2 := parent.Lstat(name); lerr2 == nil && !fi2.IsDir() {
			rerr := removeWithSharingRetry(func() error { return parent.Remove(name) })
			if rerr == nil || errors.Is(rerr, os.ErrNotExist) {
				return nil
			}
			return rerr
		}
		return &os.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
	}

	d, derr := child.Open(".")
	if errors.Is(derr, os.ErrNotExist) {
		_ = child.Close()
		return nil
	}
	if derr != nil {
		_ = child.Close()
		return derr
	}
	ents, rerr := d.ReadDir(-1)
	_ = d.Close()
	if errors.Is(rerr, os.ErrNotExist) {
		_ = child.Close()
		return nil
	}
	if rerr != nil {
		_ = child.Close()
		return rerr
	}

	for _, ent := range ents {
		if cerr := removeInRoot(child, ent.Name()); cerr != nil {
			_ = child.Close()
			return cerr
		}
	}

	// Close the child directory handle before removing it from parent so
	// Windows does not fail the remove with ERROR_SHARING_VIOLATION.
	_ = child.Close()

	err = removeWithSharingRetry(func() error { return parent.Remove(name) })
	if err == nil || errors.Is(err, os.ErrNotExist) || isErrDirNotEmpty(err) {
		return nil
	}
	return err
}
