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
	"os"
	"path/filepath"

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
