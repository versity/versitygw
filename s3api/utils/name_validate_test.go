// Copyright 2025 Versity Software
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

package utils

import (
	"testing"

	"github.com/versity/versitygw/backend"
)

func TestIsObjectNameValid(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        bool // for a backend storing objects as files
		wantDotKeys bool // for a backend storing dot segment keys
	}{
		{"simple file", "file.txt", true, true},
		{"nested file", "dir/file.txt", true, true},
		{"absolute nested file", "/dir/file.txt", true, true},
		{"trailing slash", "dir/", true, true},
		{"slash prefix", "/file.txt", true, true},
		{"leading dot", ".hidden", true, true},
		{"three dots", "...", true, true},
		{"dots inside segments", "a..b/c.", true, true},
		{"dot slash prefix", "./file.txt", false, true},
		{"dot only", ".", false, true},
		{"dot dot only", "..", false, true},
		{"dot slash", "./", false, true},
		{"dot segment", "a/./b", false, true},
		{"dot dot segment", "a/../b", false, true},
		{"trailing dot dot", "dir/..", false, true},
		{"escapes the bucket", "../file.txt", false, true},
		{"escapes the bucket deeper", "dir/../../../file.txt", false, true},
		{"empty", "", false, false},
		{"slash only", "/", false, false},
		{"slashes only", "//", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsObjectNameValid(tt.input, backend.New()); got != tt.want {
				t.Errorf("IsObjectNameValid(%q) = %v, want %v", tt.input, got, tt.want)
			}
			if got := IsObjectNameValid(tt.input, dotSegmentBackend{}); got != tt.wantDotKeys {
				t.Errorf("IsObjectNameValid(%q) with dot segment keys = %v, want %v",
					tt.input, got, tt.wantDotKeys)
			}
		})
	}
}

// dotSegmentBackend stores keys holding "." and ".." segments, like the
// azure and s3proxy backends.
type dotSegmentBackend struct {
	backend.BackendUnsupported
}

func (dotSegmentBackend) StoresDotSegmentKeys() bool { return true }
