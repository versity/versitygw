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
	"bytes"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestODirectReaderRanges(t *testing.T) {
	const objSize = 3*1024*1024 + 777
	data := make([]byte, objSize)
	rand.New(rand.NewSource(3)).Read(data)

	path := filepath.Join(t.TempDir(), "obj")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	ranges := []struct{ off, length int64 }{
		{0, objSize},
		{0, 0},
		{1, 1},
		{4095, 2},
		{123457, 1024*1024 + 3},
		{objSize - 777, 777},
		{objSize - 1, 1},
	}

	for _, direct := range []bool{false, true} {
		for _, rg := range ranges {
			for _, useWriteTo := range []bool{false, true} {
				f, err := openDataRead(path, direct)
				if err != nil {
					t.Fatal(err)
				}
				if direct && !isODirectFile(f) {
					f.Close()
					t.Skip("O_DIRECT not supported on temp filesystem")
				}

				r := newODirectReader(f, rg.off, rg.length, 64*1024+1)
				var got bytes.Buffer
				if useWriteTo {
					_, err = r.WriteTo(&got)
				} else {
					_, err = io.Copy(&got, struct{ io.Reader }{r})
				}
				if err != nil {
					t.Fatalf("direct=%v off=%d len=%d writeTo=%v: %v", direct, rg.off, rg.length, useWriteTo, err)
				}
				if !bytes.Equal(got.Bytes(), data[rg.off:rg.off+rg.length]) {
					t.Fatalf("direct=%v off=%d len=%d writeTo=%v: content mismatch", direct, rg.off, rg.length, useWriteTo)
				}
				if direct && rg.off == 1 && rg.length == 1 && r.bufLen != odirectAlign {
					t.Fatalf("small range read %d bytes, want %d", r.bufLen, odirectAlign)
				}
				if direct && !r.direct {
					t.Fatalf("off=%d len=%d: fell back to buffered I/O", rg.off, rg.length)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestODirectReaderTruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obj")
	if err := os.WriteFile(path, make([]byte, 1000), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	r := newODirectReader(f, 0, 2000, 4096)
	defer r.Close()
	if _, err := io.Copy(io.Discard, struct{ io.Reader }{r}); err != io.ErrUnexpectedEOF {
		t.Fatalf("got %v, want %v", err, io.ErrUnexpectedEOF)
	}
}
