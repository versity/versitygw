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

//go:build linux && cgo

package rcserver

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

// heapSubstring returns a substring whose backing array is heap-allocated
// and whose data pointer is an interior pointer, mirroring how header
// strings reach the binding from the gateway routes.
func heapSubstring(value string) string {
	const prefix = "prefix:"
	backing := strings.Clone(prefix + value + ":suffix")
	return backing[len(prefix) : len(prefix)+len(value)]
}

// TestPrepareHeapStringsReachCValidation calls the real Prepare wrapper
// with heap-backed strings. The request uses an invalid opcode so the C
// entrypoint returns RC_E_ARG from its argument validation before the
// server handle is dereferenced; the dummy handle below is never touched.
// Before the pinnedStrIn fix this call panics at the cgo pointer check;
// after it, the C argument validation runs and the error surfaces.
func TestPrepareHeapStringsReachCValidation(t *testing.T) {
	const literalTarget = "/bucket1/obj1"
	heapTarget := heapSubstring(literalTarget)
	heapToken := heapSubstring(strings.Repeat("0", 88))
	for _, tc := range []struct {
		name, target, token string
	}{
		{"literal_control", literalTarget, ""},
		{"heap_target", heapTarget, ""},
		{"heap_token", literalTarget, heapToken},
		{"both_heap", heapTarget, heapToken},
		{"empty_control", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var svc RCSvc
			// Test-only opaque sentinel, not an initialized rc_server.
			// Op=255 returns in C argument validation before the
			// server pointer is dereferenced.
			dummy := new(uint64)
			*(*unsafe.Pointer)(unsafe.Pointer(&svc.srv)) = unsafe.Pointer(dummy)
			resp, err := svc.Prepare(PrepareRequest{
				Op:          255,
				Size:        1,
				Target:      tc.target,
				ClientToken: tc.token,
			})
			if resp != nil || !errors.Is(err, ErrArg) {
				t.Fatalf("Prepare = (%v, %v), want (nil, ErrArg)", resp, err)
			}
		})
	}
}
