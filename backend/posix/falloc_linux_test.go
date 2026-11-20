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

package posix

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestFallocCachesUnsupported checks that a fallocate rejection is stored for
// the bucket path and that the next upload on that path skips the syscall.
func TestFallocCachesUnsupported(t *testing.T) {
	bucket := filepath.Join(t.TempDir(), "bucket")
	p := &Posix{}

	var calls int
	real := fallocate
	defer func() { fallocate = real }()
	fallocate = func(fd int, mode uint32, off, length int64) error {
		calls++
		return syscall.EOPNOTSUPP
	}

	open := func() *tmpfile {
		f, err := os.CreateTemp(t.TempDir(), "falloc")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return &tmpfile{f: f, bucket: bucket, size: 1 << 20}
	}

	p.falloc(open())
	if calls != 1 {
		t.Fatalf("first upload: %d fallocate calls, want 1", calls)
	}
	if _, ok := p.fallocUnsupported.Load(bucket); !ok {
		t.Fatal("bucket path not cached after EOPNOTSUPP")
	}

	p.falloc(open())
	if calls != 1 {
		t.Fatalf("second upload: %d fallocate calls, want 1 (skipped)", calls)
	}
}

// TestFallocSkipsCachedBucket checks on a preallocating filesystem that a
// cached path skips the call (st_blocks stays 0) while a fresh one allocates.
func TestFallocSkipsCachedBucket(t *testing.T) {
	const size = 1 << 20
	dir := t.TempDir()
	p := &Posix{}

	blocks := func(cached bool) int64 {
		bucket := filepath.Join(dir, "bucket")
		if cached {
			bucket = filepath.Join(dir, "cached")
			p.fallocUnsupported.Store(bucket, struct{}{})
		}
		f, err := os.CreateTemp(dir, "falloc")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		p.falloc(&tmpfile{f: f, bucket: bucket, size: size})
		var st syscall.Stat_t
		if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
			t.Fatal(err)
		}
		return st.Blocks
	}

	if blocks(false) == 0 {
		t.Skip("filesystem does not preallocate")
	}
	if got := blocks(true); got != 0 {
		t.Fatalf("cached bucket: st_blocks = %d, want 0", got)
	}
}
