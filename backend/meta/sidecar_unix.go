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
	"os"
	"syscall"
)

// fileIno returns the inode number of the open file f.  The inode is a
// stable, filesystem-unique identifier for the file's data, making it safe
// to use as part of a per-upload sidecar directory name.  Returns 0 on error.
func fileIno(f *os.File) uint64 {
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

// pathIno returns the inode number of the file at path by calling Lstat.
// Used by CommitMetadata to verify the object path still holds this upload's
// inode before each attribute rename.  Returns 0 on error.
func pathIno(path string) uint64 {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}
