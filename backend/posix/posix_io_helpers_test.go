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
	"io"
	"strings"
	"testing"
)

type countingCloser struct {
	count int
}

func (c *countingCloser) Close() error {
	c.count++
	return nil
}

func TestCloseOnEOFReader(t *testing.T) {
	c := &countingCloser{}
	r := &closeOnEOFReader{r: strings.NewReader("hello"), c: c}

	buf := make([]byte, 2)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 bytes, got %v", n)
	}
	if c.count != 0 {
		t.Fatalf("expected the source to stay open before EOF, closed %v times", c.count)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(data, []byte("llo")) {
		t.Fatalf("expected the remaining data to be llo, got %s", data)
	}
	if c.count != 1 {
		t.Fatalf("expected the source to be closed once at EOF, closed %v times", c.count)
	}

	// reads past EOF don't close the source again
	if _, err := r.Read(buf); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if c.count != 1 {
		t.Fatalf("expected the source to be closed once, closed %v times", c.count)
	}
}

func TestCloseOnEOFReaderEmptySource(t *testing.T) {
	c := &countingCloser{}
	r := &closeOnEOFReader{r: strings.NewReader(""), c: c}

	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("read all: %v", err)
	}
	if c.count != 1 {
		t.Fatalf("expected the source to be closed once at EOF, closed %v times", c.count)
	}
}
