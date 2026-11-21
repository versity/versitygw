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

package posix

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/versity/versitygw/backend/meta"
)

// TestSideCarDirSharingRootPrefix checks that a sidecar directory which only
// shares a string prefix with the root (e.g. /data/s3-sidecar next to
// /data/s3) is accepted, while a real subdirectory of the root is rejected.
func TestSideCarDirSharingRootPrefix(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "s3")
	sibling := filepath.Join(base, "s3-sidecar")
	inside := filepath.Join(root, "sidecar")
	for _, d := range []string{root, sibling, inside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %v: %v", d, err)
		}
	}

	t.Run("sibling sharing prefix is accepted", func(t *testing.T) {
		p, err := New(root, meta.XattrMeta{}, PosixOpts{SideCarDir: sibling, AbsolutePaths: true})
		if err != nil {
			t.Fatalf("new posix with sibling sidecar dir: %v", err)
		}
		p.Shutdown()
	})

	t.Run("subdirectory of root is rejected", func(t *testing.T) {
		p, err := New(root, meta.XattrMeta{}, PosixOpts{SideCarDir: inside, AbsolutePaths: true})
		if err == nil {
			p.Shutdown()
			t.Fatal("expected error for sidecar dir inside root")
		}
	})
}
