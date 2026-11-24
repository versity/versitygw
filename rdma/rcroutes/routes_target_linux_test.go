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

//go:build linux && amd64 && cgo && rdma

package rcroutes

import (
	"testing"

	"github.com/versity/versitygw/backend"
)

// dotKeyBackend stores "." and ".." segments as part of the key, as
// object stores that don't map keys to files do.
type dotKeyBackend struct {
	backend.BackendUnsupported
}

func (dotKeyBackend) StoresDotSegmentKeys() bool { return true }

// acceptsTarget runs a target through the checks PREPARE applies to
// x-amz-rdma-target before authorizing it.
func acceptsTarget(target string, be backend.Backend) bool {
	bucket, key, ok := splitTarget(target)
	return ok && validTarget(bucket, key, be)
}

func TestValidTargetMatchesURIChecks(t *testing.T) {
	be := backend.BackendUnsupported{}
	tests := []struct {
		target string
		want   bool
	}{
		{"/rc-bucket/obj", true},
		{"/rc-bucket/dir/sub/obj", true},
		{"/rc-bucket/obj..name", true},
		{"/rc-bucket/..obj", true},
		{"/rc-bucket/../other-bucket/obj", false},
		{"/rc-bucket/../../obj", false},
		{"/rc-bucket/dir/../../other-bucket/obj", false},
		{"/rc-bucket/./obj", false},
		{"/rc-bucket/dir/..", false},
		{"/rc-bucket/%2e%2e/other-bucket/obj", false},
		{"/rc-bucket/dir/%2E%2E/%2E%2E/obj", false},
		{"/../obj", false},
		{"/%2e%2e/obj", false},
		{"/rc-bucket//", false},
	}
	for _, tt := range tests {
		if got := acceptsTarget(tt.target, be); got != tt.want {
			t.Errorf("target %q: accepted %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestValidTargetFollowsBackendDotSegmentKeys(t *testing.T) {
	// The URI check lets dot segments through to a backend that keeps
	// them in the key; the target check does the same.
	target := "/rc-bucket/../obj"
	if acceptsTarget(target, backend.BackendUnsupported{}) {
		t.Errorf("target %q accepted for a backend storing objects as files", target)
	}
	if !acceptsTarget(target, dotKeyBackend{}) {
		t.Errorf("target %q rejected for a backend storing dot segment keys", target)
	}
}
