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

package utils_test

import (
	"testing"

	"github.com/versity/versitygw/s3api/utils"
)

func TestIsObjectNameValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// valid names
		{"simple file", "file.txt", true},
		{"nested file", "dir/file.txt", true},
		{"absolute nested file", "/dir/file.txt", true},
		{"trailing slash", "dir/", true},
		{"slash prefix", "/file.txt", true}, // treated as local after joined with bucket
		{"dot slash prefix", "./file.txt", true},

		// invalid names
		{"dot dot only", "..", false},
		{"dot only", ".", false},
		{"dot slash", "./", false},
		{"dot slash dot dot", "./..", false},
		{"cleans to dot", "./../.", false},
		{"empty", "", false},
		{"file escapes 1", "../file.txt", false},
		{"file escapes 2", "dir/../../file.txt", false},
		{"file escapes 3", "../../../file.txt", false},
		{"dir escapes 1", "../dir/", false},
		{"dir escapes 2", "dir/../../dir/", false},
		{"dir escapes 3", "../../../dir/", false},
		{"dot escapes 1", "../.", false},
		{"dot escapes 2", "dir/../../.", false},
		{"dot escapes 3", "../../../.", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.IsObjectNameValid(tt.input)
			if got != tt.want {
				t.Errorf("%v: IsObjectNameValid(%q) = %v, want %v",
					tt.name, tt.input, got, tt.want)
			}
		})
	}
}
