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

package posix

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/versity/versitygw/s3err"
)

func handleParentDirError(name string) error {
	dir := filepath.Dir(name)

	// Walk up the directory hierarchy
	for dir != "." && dir != "/" {
		d, statErr := os.Stat(dir)
		if statErr == nil {
			// Path component exists
			if !d.IsDir() {
				// Found a file in the ancestor path
				return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
			}
			// Found a valid directory ancestor, parent truly doesn't exist
			break
		}
		// Continue checking parent directories
		dir = filepath.Dir(dir)
	}
	// Parent doesn't exist or is a directory, treat as ENOENT
	return nil
}

// errDirectory is Windows ERROR_DIRECTORY (267): "The directory name is invalid."
// Windows returns this when opening a path like "file/" where "file" is a regular
// file rather than a directory — the POSIX equivalent is ENOTDIR.
const errDirectory = syscall.Errno(267)

// errInvalidName is Windows ERROR_INVALID_NAME (123): "The filename, directory
// name, or volume label syntax is incorrect." Windows returns this when a path
// component exceeds the filesystem name-length limit — the POSIX equivalent is
// ENAMETOOLONG.
const errInvalidName = syscall.Errno(123)

// errDirNotEmpty is Windows ERROR_DIR_NOT_EMPTY (145): "The directory is not
// empty." — the POSIX equivalent is ENOTEMPTY.
const errDirNotEmpty = syscall.Errno(145)

// isErrNameTooLong reports whether err indicates that a filename or path
// component is too long. On Windows this covers both ENAMETOOLONG
// (ERROR_FILENAME_EXCED_RANGE, 206) and ERROR_INVALID_NAME (123), which is
// what the Windows kernel returns for a 300-character filename that exceeds
// MAX_PATH.
func isErrNameTooLong(err error) bool {
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		return sysErr == errInvalidName
	}
	return false
}

// isErrDirNotEmpty reports whether err indicates that a directory is not empty.
// On Windows this covers both ENOTEMPTY and ERROR_DIR_NOT_EMPTY (145).
func isErrDirNotEmpty(err error) bool {
	if errors.Is(err, syscall.ENOTEMPTY) {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		return sysErr == errDirNotEmpty
	}
	return false
}

// isErrNotDir reports whether err indicates that a path component is a file,
// not a directory. On Windows this covers both ENOTDIR and ERROR_DIRECTORY
// because os.Open / os.Stat do not map ERROR_DIRECTORY to ENOTDIR.
func isErrNotDir(err error) bool {
	if errors.Is(err, syscall.ENOTDIR) {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		return sysErr == errDirectory
	}
	return false
}

// openForRead opens a file for reading with FILE_SHARE_DELETE so that a
// concurrent DeleteObject (os.Remove) can succeed even while the file handle
// is held open for streaming the GET response body. Without this flag,
// Windows returns "The process cannot access the file because it is being
// used by another process" on the Remove call.
func openForRead(name string) (*os.File, error) {
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	h, err := syscall.CreateFile(
		ptr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}
