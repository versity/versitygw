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
	"strings"
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

type dirNestingCase struct {
	name    string
	root    string
	dir     string
	wantErr bool
}

// runDirNestingCases starts the backend with each case's directory once as the
// sidecar directory and once as the versioning directory.
func runDirNestingCases(t *testing.T, tests []dirNestingCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run("sidecar/"+tt.name, func(t *testing.T) {
			sc, err := meta.NewSideCar(tt.dir)
			if err != nil {
				t.Fatalf("new sidecar: %v", err)
			}
			p, err := New(tt.root, sc, PosixOpts{SideCarDir: tt.dir, AbsolutePaths: true})
			checkDirNesting(t, p, err, tt.wantErr, "invalid sidecar directory: "+tt.dir)
		})
		t.Run("versioning/"+tt.name, func(t *testing.T) {
			p, err := New(tt.root, meta.XattrMeta{}, PosixOpts{VersioningDir: tt.dir, AbsolutePaths: true})
			checkDirNesting(t, p, err, tt.wantErr, "invalid versioning directory: "+tt.dir)
		})
	}
}

func checkDirNesting(t *testing.T, p *Posix, err error, wantErr bool, prefix string) {
	t.Helper()
	if err == nil {
		p.Shutdown()
		if wantErr {
			t.Fatal("expected nesting error")
		}
		return
	}
	if !wantErr {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, ErrDirsNested) {
		t.Fatalf("expected ErrDirsNested, got: %v", err)
	}
	if want := prefix + " " + ErrDirsNested.Error(); !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("expected error starting with %q, got: %v", want, err)
	}
}

// TestAuxDirNesting checks that the sidecar and versioning directories are
// accepted when they only share a string prefix with the root, and rejected
// when they are the root, inside it, or contain it.
func TestAuxDirNesting(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "s3")
	sibling := filepath.Join(base, "s3-sidecar")
	inside := filepath.Join(root, "sidecar")
	mustMkdirAll(t, root, sibling, inside)

	runDirNestingCases(t, []dirNestingCase{
		{"sibling sharing prefix", root, sibling, false},
		{"subdirectory of root", root, inside, true},
		{"same as root", root, root, true},
		{"parent of root", root, base, true},
		{"root with trailing separator, sibling", root + string(filepath.Separator), sibling, false},
		{"root with trailing separator, inside", root + string(filepath.Separator), inside, true},
	})
}

// TestAuxDirNestingSymlinks checks that a symlinked path segment does not hide
// the nesting.
func TestAuxDirNestingSymlinks(t *testing.T) {
	base := t.TempDir()
	// symlink layout: link -> realDir
	realDir := filepath.Join(base, "real")
	realRoot := filepath.Join(realDir, "gwroot")
	realInner := filepath.Join(realRoot, "inner")
	mustMkdirAll(t, realInner)
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	runDirNestingCases(t, []dirNestingCase{
		{"symlinked root, nested in real path", filepath.Join(link, "gwroot"), realInner, true},
		{"real root, nested via symlinked path", realRoot, filepath.Join(link, "gwroot", "inner"), true},
	})
}

// TestAuxDirNestingCaseInsensitive checks that spelling a path with a different
// case does not hide the nesting on a case-insensitive filesystem.
func TestAuxDirNestingCaseInsensitive(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "outer", "gwroot")
	inner := filepath.Join(root, "inner")
	mustMkdirAll(t, inner)
	upperRoot := filepath.Join(base, "outer", "GWROOT")
	if _, err := os.Stat(upperRoot); err != nil {
		t.Skipf("case-sensitive filesystem: %v", err)
	}

	runDirNestingCases(t, []dirNestingCase{
		{"subdirectory of root", root, filepath.Join(upperRoot, "inner"), true},
		{"same as root", root, upperRoot, true},
		{"parent of root", root, filepath.Join(base, "OUTER"), true},
	})
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
