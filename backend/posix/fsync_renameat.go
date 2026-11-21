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

//go:build linux || darwin || freebsd

package posix

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// renameInDirSupported reports whether renameInDir works on this platform.
const renameInDirSupported = true

// renameInDir renames src to the base name of objPath inside the directory
// handle dir, so the object lands in the directory that will be synced even
// if the path was removed and recreated meanwhile.
func renameInDir(src string, dir int, objPath string) error {
	if err := unix.Renameat(unix.AT_FDCWD, src, dir, filepath.Base(objPath)); err != nil {
		return &os.LinkError{Op: "renameat", Old: src, New: objPath, Err: err}
	}
	return nil
}
