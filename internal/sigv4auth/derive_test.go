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

import (
	"encoding/hex"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	const wantHex = "2c94c0cf5378ada6887f09bb697df8fc0affdb34ba1cdd5bda32b664bd55b73c"

	got := DeriveKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")

	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode want hex: %v", err)
	}

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("DeriveKey() = %x, want %x", got, want)
	}
}
