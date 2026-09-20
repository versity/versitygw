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

package utils

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/versity/versitygw/s3err"
)

// eofWithDataReader returns its payload and reports io.EOF together with the
// final bytes, the way a connection that was closed mid-body surfaces through
// fasthttp's request stream.
type eofWithDataReader struct {
	data []byte
	pos  int
}

func (r *eofWithDataReader) Read(p []byte) (int, error) {
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// oneByteReader hands out a single byte per call so the shortfall is only
// known on the very last Read.
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func TestContentLengthReader(t *testing.T) {
	incomplete := s3err.GetAPIError(s3err.ErrIncompleteBody)

	for _, tt := range []struct {
		name          string
		body          string
		contentLength int64
		newReader     func(string) io.Reader
		wantErr       error
	}{
		{
			name:          "complete body",
			body:          "hello world",
			contentLength: 11,
			wantErr:       nil,
		},
		{
			name:          "empty body",
			body:          "",
			contentLength: 0,
			wantErr:       nil,
		},
		{
			name:          "truncated body",
			body:          "hel",
			contentLength: 11,
			wantErr:       incomplete,
		},
		{
			name:          "truncated body, EOF with final bytes",
			body:          "hel",
			contentLength: 11,
			newReader:     func(s string) io.Reader { return &eofWithDataReader{data: []byte(s)} },
			wantErr:       incomplete,
		},
		{
			name:          "truncated body, one byte per read",
			body:          "hel",
			contentLength: 11,
			newReader:     func(s string) io.Reader { return &oneByteReader{data: []byte(s)} },
			wantErr:       incomplete,
		},
		{
			name:          "empty body but length announced",
			body:          "",
			contentLength: 5,
			wantErr:       incomplete,
		},
		{
			// Should not be reachable through fasthttp, but the reader must
			// not invent an error when more arrives than was announced.
			name:          "body longer than Content-Length",
			body:          "hello world",
			contentLength: 5,
			wantErr:       nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newReader := tt.newReader
			if newReader == nil {
				newReader = func(s string) io.Reader { return strings.NewReader(s) }
			}

			got, err := io.ReadAll(NewContentLengthReader(newReader(tt.body), tt.contentLength))

			if string(got) != tt.body {
				t.Errorf("data: got %q, want %q", string(got), tt.body)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			var apiErr s3err.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
			if apiErr.Code != "IncompleteBody" {
				t.Fatalf("got code %q, want IncompleteBody", apiErr.Code)
			}
		})
	}
}

// A non-EOF error from the wrapped reader must reach the caller unchanged:
// a signed payload whose body ends early already fails with
// ContentSHA256Mismatch from the checksum reader, and that error is the one
// the client should see.
func TestContentLengthReaderPassesThroughOtherErrors(t *testing.T) {
	want := s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
	r := NewContentLengthReader(&failingReader{err: want}, 100)

	_, err := io.ReadAll(r)

	var apiErr s3err.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %v, want %v", err, want)
	}
	if apiErr.Code != want.Code {
		t.Fatalf("got code %q, want %q", apiErr.Code, want.Code)
	}
}

type failingReader struct {
	err error
}

func (r *failingReader) Read(p []byte) (int, error) {
	return 0, r.err
}
