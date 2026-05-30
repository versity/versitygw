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
	"os"
	"path/filepath"
	"syscall"

	"github.com/versity/versitygw/s3err"
)

func handleParentDirError(_ string) error {
	return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
}

// captureIno returns the inode number of the open file f by calling fstat.
// This is used to capture the inode of a temp upload file while its fd is
// still open, before link() closes it.  The captured inode is stored in
// tmpfile.ino and used later by SidecarToken() and didWinLink().
func captureIno(f *os.File) uint64 {
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}

// didWinLink reports whether this upload's data file is the one currently
// installed at the final object path.  It compares the inode captured just
// before link() closed the temp file against the inode of the live object.
// Only the winner should call CommitMetadata.
//
// If ino is 0 (not captured, or on an error path) this returns false so that
// metadata commit is skipped rather than potentially committing stale data.
func (tmp *tmpfile) didWinLink() bool {
	if tmp.ino == 0 {
		return false
	}
	fi, err := os.Lstat(filepath.Join(tmp.bucket, tmp.objname))
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Ino == tmp.ino
}
