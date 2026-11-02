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

//go:build linux

package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pkg/xattr"
)

// TestMoveFileAcrossFilesystems checks that the copy fallback keeps the data
// and the user attributes of the staged file, and removes it.
func TestMoveFileAcrossFilesystems(t *testing.T) {
	srcDir, err := os.MkdirTemp("/dev/shm", "movefile")
	if err != nil {
		t.Skipf("no /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	dstDir, err := os.MkdirTemp(".", "movefile")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dstDir) })

	src := filepath.Join(srcDir, "staged")
	dst := filepath.Join(dstDir, "object")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := xattr.Set(src, "user.etag", []byte("abc")); err != nil {
		t.Skipf("xattrs unsupported on the source filesystem: %v", err)
	}
	probe := filepath.Join(dstDir, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := xattr.Set(probe, "user.p", []byte("1")); err != nil {
		t.Skipf("xattrs unsupported on the destination filesystem: %v", err)
	}
	if err := os.Rename(src, filepath.Join(dstDir, "x")); !errors.Is(err, syscall.EXDEV) {
		t.Skipf("directories are on the same filesystem (rename: %v)", err)
	}

	if err := MoveFile(src, dst, 0o644); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("destination data: %q, %v", got, err)
	}
	val, err := xattr.Get(dst, "user.etag")
	if err != nil || string(val) != "abc" {
		t.Fatalf("destination attribute: %q, %v", val, err)
	}
	if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists: %v", err)
	}
}
