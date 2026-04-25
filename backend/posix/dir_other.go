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
	"syscall"

	"github.com/versity/versitygw/s3err"
)

func handleParentDirError(_ string) error {
	return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
}

// isErrNotDir reports whether err indicates that a path component is a file,
// not a directory (POSIX ENOTDIR).
func isErrNotDir(err error) bool {
	return errors.Is(err, syscall.ENOTDIR)
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

// openForRead opens a file for reading. On non-Windows systems, os.Open is
// sufficient because POSIX allows removing (unlinking) a file that is still
// open by another process.
func openForRead(name string) (*os.File, error) {
	return os.Open(name)
}
