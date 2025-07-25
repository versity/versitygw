// Copyright 2024 Versity Software
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

import "testing"

func TestIsValidSh256PayloadHeader(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want bool
	}{
		{"empty header", "", true},
		{"special payload type 1", "UNSIGNED-PAYLOAD", true},
		{"special payload type 2", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", true},
		{"special payload type 3", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", true},
		{"special payload type 4", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", true},
		{"special payload type 5", "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD", true},
		{"special payload type 6", "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER", true},
		{"invalid hext", "invalid_hex", false},
		{"valid hex, but not sha256", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"valid sh256", "9c56cc51b374bb0f2f8d55af2b34d2a6f8f7f42dd4bbcccbbf8e3279b6e1e6d4", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidSh256PayloadHeader(tt.hash); got != tt.want {
				t.Errorf("IsValidSh256PayloadHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
