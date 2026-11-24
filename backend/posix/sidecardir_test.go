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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/versity/versitygw/backend/meta"
)

func mustMkdirAll(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %v: %v", d, err)
		}
	}
}

// TestSideCarDirNesting checks that the sidecar directory is accepted when it
// only shares a string prefix with the root, and rejected when it is the
// root, inside it, or contains it (also through symlinks).
func TestSideCarDirNesting(t *testing.T) {
	base := t.TempDir()
	// resolve the temp dir so symlink cases are explicit
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "s3")
	sibling := filepath.Join(base, "s3-sidecar")
	inside := filepath.Join(root, "sidecar")
	mustMkdirAll(t, root, sibling, inside)

	// symlink layout: link -> real; root via link, sidecar nested in real root
	real := filepath.Join(base, "real")
	realRoot := filepath.Join(real, "gwroot")
	realInner := filepath.Join(realRoot, "inner")
	mustMkdirAll(t, realRoot, realInner)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	tests := []struct {
		name    string
		root    string
		sidecar string
		wantErr bool
	}{
		{"sibling sharing prefix", root, sibling, false},
		{"subdirectory of root", root, inside, true},
		{"same as root", root, root, true},
		{"parent of root", root, base, true},
		{"root with trailing separator, sibling", root + string(filepath.Separator), sibling, false},
		{"root with trailing separator, inside", root + string(filepath.Separator), inside, true},
		{"symlinked root, sidecar nested in real path", filepath.Join(link, "gwroot"), realInner, true},
		{"real root, sidecar nested via symlinked path", realRoot, filepath.Join(link, "gwroot", "inner"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := meta.NewSideCar(tt.sidecar)
			if err != nil {
				t.Fatalf("new sidecar: %v", err)
			}
			p, err := New(tt.root, sc, PosixOpts{SideCarDir: tt.sidecar, AbsolutePaths: true})
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				p.Shutdown()
				return
			}
			if err == nil {
				p.Shutdown()
				t.Fatal("expected nesting error")
			}
			if !errors.Is(err, ErrDirsNested) {
				t.Fatalf("expected ErrDirsNested, got: %v", err)
			}
		})
	}
}

// TestSideCarDirRelativeRoot checks the default (non-AbsolutePaths) mode with
// root "." and a sidecar next to it.
func TestSideCarDirRelativeRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "s3")
	sibling := filepath.Join(base, "s3-sidecar")
	mustMkdirAll(t, root, sibling)

	t.Chdir(root)
	sc, err := meta.NewSideCar("../s3-sidecar")
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	p, err := New(".", sc, PosixOpts{SideCarDir: "../s3-sidecar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p.Shutdown()
}

func TestCheckDirsNotNestedMissingDir(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "s3")
	mustMkdirAll(t, root)
	if err := CheckDirsNotNested(root, filepath.Join(root, "not", "yet")); !errors.Is(err, ErrDirsNested) {
		t.Fatalf("expected ErrDirsNested, got %v", err)
	}
	if err := CheckDirsNotNested(root, filepath.Join(base, "other", "new")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
