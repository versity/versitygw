// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4auth

import "testing"

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"equal", "abc123", "abc123", true},
		{"different content, same length", "abc123", "abc124", false},
		{"different length", "abc123", "abc1234", false},
		{"empty vs empty", "", "", true},
		{"empty vs non-empty", "", "a", false},
		{"shares a long common prefix but differs at the end", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay", false},
		{"differs only in the first byte", "xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "yaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecureCompare(tt.a, tt.b); got != tt.want {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
