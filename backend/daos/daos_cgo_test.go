// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
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

//go:build linux && cgo && daos

package daos

import (
	"strings"
	"testing"
)

func TestTaggedNewFailsClosedWithoutAContainer(t *testing.T) {
	be, err := New("pool", "container", "sys")
	if be != nil || err == nil {
		if be != nil {
			be.Shutdown()
		}
		t.Fatalf("New returned %v, err %v", be, err)
	}
	if strings.Contains(err.Error(), "-tags daos") || strings.Contains(err.Error(), "does not serve requests") {
		t.Fatalf("tagged build is not serving: %v", err)
	}
}
