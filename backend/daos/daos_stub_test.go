// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

//go:build !(linux && cgo && daos)

package daos

import (
	"strings"
	"testing"
)

func TestNewStubRequiresBuildTag(t *testing.T) {
	be, err := New("pool", "container", "sys")
	if err == nil {
		t.Fatal("New returned a backend")
	}
	if be != nil {
		t.Fatalf("New returned %v with error %v", be, err)
	}
	if !strings.Contains(err.Error(), "-tags daos") {
		t.Fatalf("error %q does not name the build tag", err)
	}
}

func TestString(t *testing.T) {
	if got := (&Daos{}).String(); got != "DAOS Gateway" {
		t.Fatalf("String() = %q", got)
	}
}
