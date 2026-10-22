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

package posix

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/versity/versitygw/s3err"
)

// handleParentDirError returns ErrObjectParentIsFile when a parent of name
// is a file. A shared filesystem can also fail a lookup with ENOTDIR for a
// directory that another node is removing; name is treated as missing then.
func handleParentDirError(name string) error {
	for dir := filepath.Dir(name); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		fi, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
		}
		break
	}
	return nil
}

// isParentDirGone reports whether err from placing an entry in a directory
// means the directory, or one of its parents, is not there: it is missing
// (ENOENT), a stale handle to a directory another client removed (ESTALE),
// or a path component isn't a directory (ENOTDIR), which making the
// directory then either fixes or reports as a parent that is a file.
func isParentDirGone(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESTALE) ||
		errors.Is(err, syscall.ENOTDIR)
}

// isDirDeletePending reports whether err from making a directory means that
// the delete of a directory at its path hasn't completed yet. POSIX removes a
// directory at once.
func isDirDeletePending(error) bool {
	return false
}

// isErrNotDir reports whether err indicates that a path component is a file,
// not a directory (POSIX ENOTDIR).
func isErrNotDir(err error) bool {
	return errors.Is(err, syscall.ENOTDIR)
}

// isErrStale reports whether err is a stale file handle (ESTALE): the file,
// or a parent directory, was removed by another client of a shared
// filesystem.
func isErrStale(err error) bool {
	return errors.Is(err, syscall.ESTALE)
}

// isErrNameTooLong reports whether err indicates that a filename or path
// component is too long (POSIX ENAMETOOLONG).
func isErrNameTooLong(err error) bool {
	return errors.Is(err, syscall.ENAMETOOLONG)
}

// isErrDirNotEmpty reports whether err indicates that a directory is not empty
// (POSIX ENOTEMPTY).
func isErrDirNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY)
}

// openForRead opens an object data file for reading.
func openForRead(name string, useODirect bool) (*os.File, error) {
	return openDataRead(name, useODirect)
}
