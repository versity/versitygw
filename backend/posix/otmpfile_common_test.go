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
	"bytes"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// shortReader returns at most max bytes per Read, and errAtEOF with the final data.
type shortReader struct {
	r        io.Reader
	max      int
	errAtEOF error
}

func (s *shortReader) Read(p []byte) (int, error) {
	if len(p) > s.max {
		p = p[:s.max]
	}
	n, err := s.r.Read(p)
	if err == nil && s.errAtEOF != nil {
		if br, ok := s.r.(*bytes.Reader); ok && br.Len() == 0 {
			return n, s.errAtEOF
		}
	}
	return n, err
}

// newTestODirectTmpfile builds a tmpfile over a regular file with useODirect
// set, so alignment decisions can be observed without O_DIRECT support.
func newTestODirectTmpfile(t *testing.T, size int64) *tmpfile {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "obj"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return &tmpfile{f: f, useODirect: true, size: size}
}

func TestTmpfileCopyFromShortReads(t *testing.T) {
	tests := []struct {
		name         string
		size         int
		wantODirect  bool
		bufSize      int
		maxReadBytes int
	}{
		{"aligned size stays O_DIRECT", 4 * 1024 * 1024, true, 1024 * 1024, 7777},
		{"unaligned tail switches at end", 4*1024*1024 + 123, false, 1024 * 1024, 7777},
		{"512 aligned tail is not 4k aligned", 3*4096 + 512, false, 1024 * 1024, 7777},
		{"small unaligned object", 100, false, 1024 * 1024, 13},
		{"unaligned buffer size", 64 * 1024, true, 10000, 999},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.size)
			rand.New(rand.NewSource(1)).Read(data)

			tmp := newTestODirectTmpfile(t, int64(tc.size))
			rdr := &shortReader{r: bytes.NewReader(data), max: tc.maxReadBytes}

			n, err := tmp.copyFrom(rdr, make([]byte, tc.bufSize))
			if err != nil {
				t.Fatalf("copyFrom: %v", err)
			}
			if n != int64(tc.size) {
				t.Fatalf("copied %d, want %d", n, tc.size)
			}
			if tmp.useODirect != tc.wantODirect {
				t.Fatalf("useODirect=%v, want %v", tmp.useODirect, tc.wantODirect)
			}

			got, err := os.ReadFile(tmp.f.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("file content mismatch")
			}
		})
	}
}

func TestAlignedBuffer(t *testing.T) {
	for _, size := range []int{1, 512, 4096, 10000, 1024 * 1024} {
		b := alignedBuffer(size)
		if len(b) != size || cap(b) != size {
			t.Fatalf("size %d: len=%d cap=%d", size, len(b), cap(b))
		}
		if !isODirectMemAligned(b) {
			t.Fatalf("size %d: buffer not %d-byte aligned", size, odirectAlign)
		}
	}
}

func TestTmpfileCopyFromUnalignedMemory(t *testing.T) {
	data := make([]byte, 64*1024)
	rand.New(rand.NewSource(2)).Read(data)

	tmp := newTestODirectTmpfile(t, int64(len(data)))
	buf := alignedBuffer(32*1024 + 1)[1:]
	if isODirectMemAligned(buf) {
		t.Fatal("test buffer unexpectedly aligned")
	}

	if _, err := tmp.copyFrom(&shortReader{r: bytes.NewReader(data), max: 1000}, buf); err != nil {
		t.Fatalf("copyFrom: %v", err)
	}
	if !tmp.useODirect {
		t.Fatal("fell back to buffered I/O")
	}
	got, err := os.ReadFile(tmp.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("file content mismatch")
	}
}

func TestTmpfileCopyFromPropagatesErrorWithFinalData(t *testing.T) {
	errBad := errors.New("bad digest")
	data := make([]byte, 1024*1024)

	tmp := newTestODirectTmpfile(t, int64(len(data)))
	rdr := &shortReader{r: bytes.NewReader(data), max: 4096, errAtEOF: errBad}

	_, err := tmp.copyFrom(rdr, make([]byte, len(data)))
	if !errors.Is(err, errBad) {
		t.Fatalf("got err %v, want %v", err, errBad)
	}
}
