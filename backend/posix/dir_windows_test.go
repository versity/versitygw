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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemoveDir checks that removeDir removes an empty directory, also one
// named by a relative path whose absolute path is beyond MAX_PATH, and leaves
// a directory that isn't empty and a file in place.
func TestRemoveDir(t *testing.T) {
	t.Chdir(t.TempDir())
	long := filepath.Join(strings.Repeat("d", 200), strings.Repeat("e", 200))
	for _, dir := range []string{"short", long} {
		child := filepath.Join(dir, "child")
		if err := os.MkdirAll(child, 0755); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, nil, 0644); err != nil {
			t.Fatal(err)
		}

		if err := removeDir(dir); !isErrDirNotEmpty(err) {
			t.Errorf("remove non-empty dir %v: got %v, want ERROR_DIR_NOT_EMPTY", dir, err)
		}
		if err := removeDir(file); !isErrNotDir(err) {
			t.Errorf("remove file %v: got %v, want ERROR_DIRECTORY", file, err)
		}
		if _, err := os.Lstat(file); err != nil {
			t.Errorf("file %v is gone: %v", file, err)
		}
		if err := removeDir(child); err != nil {
			t.Errorf("remove empty dir %v: %v", child, err)
		}
		if _, err := os.Lstat(child); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("empty dir %v is still there: %v", child, err)
		}
	}
}
