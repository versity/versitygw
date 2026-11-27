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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/versity/versitygw/s3err"
)

func TestUnsignedChunkReaderStreamsLargeChunkWithoutBuffering(t *testing.T) {
	const chunkSize int64 = 1 << 32
	body := io.MultiReader(
		strings.NewReader(fmt.Sprintf("%x\r\n", chunkSize)),
		strings.NewReader("abc"),
	)
	reader, err := NewUnsignedChunkReader(body, "", chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 3)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "abc" {
		t.Fatalf("read data = %q, want %q", got, "abc")
	}
	if reader.chunkDataLeft != chunkSize-int64(n) {
		t.Fatalf("chunkDataLeft = %d, want %d", reader.chunkDataLeft, chunkSize-int64(n))
	}
}

func TestUnsignedChunkReaderReadsAcrossChunksAndThenEOF(t *testing.T) {
	firstChunk := strings.Repeat("a", int(minChunkSize))
	body := unsignedChunkBody(firstChunk, "tail")
	reader, err := NewUnsignedChunkReader(strings.NewReader(body), "", int64(len(firstChunk)+len("tail")))
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	buf := make([]byte, 3)
	for {
		n, err := reader.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}

	expected := firstChunk + "tail"
	if got := out.String(); got != expected {
		t.Fatalf("read data length = %d, want %d", len(got), len(expected))
	}

	n, err := reader.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("second EOF read = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestUnsignedChunkReaderValidatesTrailingChecksum(t *testing.T) {
	payload := "abcdefg"
	sum := sha256.Sum256([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n%s:%s\r\n\r\n",
		len(payload), payload, checksumTypeSha256, checksum)

	reader, err := NewUnsignedChunkReader(strings.NewReader(body), checksumTypeSha256, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if string(out) != payload {
		t.Fatalf("read data = %q, want %q", out, payload)
	}
	if reader.Checksum() != checksum {
		t.Fatalf("checksum = %q, want %q", reader.Checksum(), checksum)
	}
}

func TestUnsignedChunkReaderContentLengthMismatchStopsAtDecodedLength(t *testing.T) {
	body := "b\r\nabcdefghijk\r\n0\r\n\r\n"
	reader, err := NewUnsignedChunkReader(strings.NewReader(body), "", 5)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 32)
	n, err := reader.Read(buf)
	if string(buf[:n]) != "abcde" {
		t.Fatalf("read data = %q, want %q", buf[:n], "abcde")
	}
	requireAPIErrorCode(t, err, s3err.GetAPIError(s3err.ErrContentLengthMismatch).Code)
}

func TestUnsignedChunkReaderDeclaredChunkLongerThanPayloadReturnsIncompleteBody(t *testing.T) {
	body := "B\r\ndummy data\r\n0\r\n\r\n"
	reader, err := NewUnsignedChunkReader(strings.NewReader(body), checksumTypeCrc64nvme, 10)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 32)
	n, err := reader.Read(buf)
	if string(buf[:n]) != "dummy data" {
		t.Fatalf("read data = %q, want %q", buf[:n], "dummy data")
	}
	requireAPIErrorCode(t, err, s3err.GetAPIError(s3err.ErrIncompleteBody).Code)
}

func TestUnsignedChunkReaderInvalidChunkSize(t *testing.T) {
	body := unsignedChunkBody("short", "x")
	reader, err := NewUnsignedChunkReader(strings.NewReader(body), "", int64(len("short")+len("x")))
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.ReadAll(reader)
	requireAPIErrorCode(t, err, s3err.GetAPIError(s3err.ErrInvalidChunkSize).Code)
	if reader.invalidChunkNumber != 1 {
		t.Fatalf("invalidChunkNumber = %d, want 1", reader.invalidChunkNumber)
	}
	if reader.invalidChunkSize != int64(len("short")) {
		t.Fatalf("invalidChunkSize = %d, want %d", reader.invalidChunkSize, len("short"))
	}
}

func TestUnsignedChunkReaderRejectsUnterminatedTrailer(t *testing.T) {
	for _, test := range []struct {
		name string
		head string
		fill byte
	}{
		{"bytes without a delimiter", "0\r\n", 'A'},
		{"checksum value without a delimiter", "0\r\n" + string(checksumTypeCrc32) + ":", 'A'},
		{"whitespace without a delimiter", "0\r\n", ' '},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A trailer that never reaches its '\r' has to be rejected once
			// it outgrows the read buffer. The source gives up after 1 MiB,
			// so a reader that keeps buffering fails here instead of
			// exhausting memory.
			src := &endlessSource{head: []byte(test.head), fill: test.fill, limit: 1 << 20}
			reader, err := NewUnsignedChunkReader(src, checksumTypeCrc32, 0)
			if err != nil {
				t.Fatal(err)
			}

			out, err := io.ReadAll(reader)
			if len(out) != 0 {
				t.Fatalf("read %d bytes of object data, want none", len(out))
			}
			requireAPIErrorCode(t, err, s3err.GetAPIError(s3err.ErrIncompleteBody).Code)
			if src.served > 2*maxHeaderSize {
				t.Fatalf("consumed %d body bytes before rejecting the trailer, want at most %d", src.served, 2*maxHeaderSize)
			}
		})
	}
}

func TestUnsignedChunkReaderFramingLineLimit(t *testing.T) {
	payload := "hello"
	trailer := crc32Trailer(payload)
	incompleteBody := s3err.GetAPIError(s3err.ErrIncompleteBody).Code

	// padded returns s left-padded to n bytes with pad
	padded := func(s string, pad string, n int) string {
		return strings.Repeat(pad, n-len(s)) + s
	}

	for _, test := range []struct {
		name    string
		body    string
		wantErr string
	}{
		// A framing line fits as long as it and its '\r' fit in the read
		// buffer.
		{
			name: "trailer header filling the read buffer",
			body: fmt.Sprintf("5\r\n%s\r\n0\r\n%s\r\n\r\n", payload, padded(trailer, " ", maxHeaderSize-1)),
		},
		{
			name:    "trailer header overflowing the read buffer",
			body:    fmt.Sprintf("5\r\n%s\r\n0\r\n%s\r\n\r\n", payload, padded(trailer, " ", maxHeaderSize)),
			wantErr: incompleteBody,
		},
		{
			name: "chunk size line filling the read buffer",
			body: fmt.Sprintf("%s\r\n%s\r\n0\r\n%s\r\n\r\n", padded("5", "0", maxHeaderSize-1), payload, trailer),
		},
		{
			name:    "chunk size line overflowing the read buffer",
			body:    fmt.Sprintf("%s\r\n%s\r\n0\r\n%s\r\n\r\n", padded("5", "0", maxHeaderSize), payload, trailer),
			wantErr: incompleteBody,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, err := NewUnsignedChunkReader(strings.NewReader(test.body), checksumTypeCrc32, int64(len(payload)))
			if err != nil {
				t.Fatal(err)
			}

			out, err := io.ReadAll(reader)
			if test.wantErr != "" {
				requireAPIErrorCode(t, err, test.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("read all: %v", err)
			}
			if string(out) != payload {
				t.Fatalf("read data = %q, want %q", out, payload)
			}
		})
	}
}

func TestUnsignedChunkReaderTrailer(t *testing.T) {
	payload := "hello"
	trailer := crc32Trailer(payload)
	_, checksum, _ := strings.Cut(trailer, ":")
	incompleteBody := s3err.GetAPIError(s3err.ErrIncompleteBody).Code
	malformedTrailer := s3err.GetAPIError(s3err.ErrMalformedTrailer).Code

	for _, test := range []struct {
		name         string
		checksumType checksumType
		// trailer is what follows the final "0\r\n" chunk header
		trailer      string
		wantErr      string
		wantChecksum string
	}{
		{name: "no trailer", trailer: "\r\n"},
		{name: "whitespace only trailer", trailer: " \t \r\n\r\n"},
		{name: "valid trailer", checksumType: checksumTypeCrc32, trailer: trailer + "\r\n\r\n", wantChecksum: checksum},
		{name: "valid trailer surrounded by whitespace", checksumType: checksumTypeCrc32, trailer: " \t" + trailer + "\t \r\n\r\n", wantChecksum: checksum},
		{name: "missing expected trailer", checksumType: checksumTypeCrc32, trailer: "\r\n", wantErr: malformedTrailer},
		{name: "whitespace instead of expected trailer", checksumType: checksumTypeCrc32, trailer: "  \r\n\r\n", wantErr: malformedTrailer},
		{name: "unexpected trailer", trailer: trailer + "\r\n\r\n", wantErr: malformedTrailer},
		{name: "unexpected trailer with empty key", trailer: ":" + checksum + "\r\n\r\n", wantErr: malformedTrailer},
		{name: "unsupported checksum key", checksumType: checksumTypeCrc32, trailer: "x-amz-checksum-invalid:" + checksum + "\r\n\r\n", wantErr: malformedTrailer},
		{name: "checksum key mismatch", checksumType: checksumTypeCrc32, trailer: string(checksumTypeCrc32c) + ":" + checksum + "\r\n\r\n", wantErr: malformedTrailer},
		{name: "no separator", checksumType: checksumTypeCrc32, trailer: string(checksumTypeCrc32) + "\r\n\r\n", wantErr: malformedTrailer},
		{name: "multiple separators", checksumType: checksumTypeCrc32, trailer: trailer + ":x\r\n\r\n", wantErr: malformedTrailer},
		{name: "empty checksum", checksumType: checksumTypeCrc32, trailer: string(checksumTypeCrc32) + ":\r\n\r\n", wantErr: s3err.GetInvalidTrailingChecksumHeaderErr(string(checksumTypeCrc32)).Code},
		{name: "incorrect checksum", checksumType: checksumTypeCrc32, trailer: string(checksumTypeCrc32) + ":AAAAAA==\r\n\r\n", wantErr: s3err.GetChecksumBadDigestErr("CRC32").Code},
		{name: "missing trailer section", checksumType: checksumTypeCrc32, trailer: "", wantErr: incompleteBody},
		{name: "unterminated trailer header", checksumType: checksumTypeCrc32, trailer: trailer, wantErr: incompleteBody},
		{name: "missing final delimiter", checksumType: checksumTypeCrc32, trailer: trailer + "\r\n", wantErr: incompleteBody},
		{name: "invalid trailer delimiter", checksumType: checksumTypeCrc32, trailer: trailer + "\rX\r\n", wantErr: incompleteBody},
		{name: "invalid empty trailer delimiter", trailer: "\rX", wantErr: incompleteBody},
		// a body cut short is reported before a malformed trailer header
		{name: "malformed and unterminated trailer", checksumType: checksumTypeCrc32, trailer: "invalid:" + checksum + "\r\n", wantErr: incompleteBody},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := fmt.Sprintf("5\r\n%s\r\n0\r\n%s", payload, test.trailer)
			reader, err := NewUnsignedChunkReader(strings.NewReader(body), test.checksumType, int64(len(payload)))
			if err != nil {
				t.Fatal(err)
			}

			out, err := io.ReadAll(reader)
			if test.wantErr != "" {
				requireAPIErrorCode(t, err, test.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("read all: %v", err)
			}
			if string(out) != payload {
				t.Fatalf("read data = %q, want %q", out, payload)
			}
			if got := reader.Checksum(); got != test.wantChecksum {
				t.Fatalf("checksum = %q, want %q", got, test.wantChecksum)
			}
		})
	}
}

func TestUnsignedChunkReaderAllocationsDoNotGrowWithBody(t *testing.T) {
	// The reader allocates when it is created and when it checks the trailing
	// checksum, never per chunk or per Read: decoding 64 times as many chunks
	// costs no extra allocations.
	small := unsignedChunkBodyWithChecksum(4, int(minChunkSize))
	large := unsignedChunkBodyWithChecksum(256, int(minChunkSize))
	buf := make([]byte, 4096)

	decode := func(body []byte, decodedLength int64) func() {
		return func() {
			reader, err := NewUnsignedChunkReader(bytes.NewReader(body), checksumTypeCrc32, decodedLength)
			if err != nil {
				t.Fatal(err)
			}
			for {
				_, err := reader.Read(buf)
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Fatalf("read: %v", err)
				}
			}
		}
	}

	smallAllocs := testing.AllocsPerRun(10, decode(small, 4*minChunkSize))
	largeAllocs := testing.AllocsPerRun(10, decode(large, 256*minChunkSize))
	if largeAllocs != smallAllocs {
		t.Fatalf("decoding 256 chunks allocated %v times, 4 chunks %v times; want no allocations per chunk", largeAllocs, smallAllocs)
	}
}

// endlessSource serves head followed by fill repeated without end. It fails
// once limit bytes have been served, so a test cannot hang on a regression.
type endlessSource struct {
	head   []byte
	fill   byte
	limit  int
	served int
}

func (s *endlessSource) Read(p []byte) (int, error) {
	if s.served >= s.limit {
		return 0, errors.New("endless source: read limit reached")
	}

	n := min(len(p), s.limit-s.served)
	for i := range n {
		if s.served < len(s.head) {
			p[i] = s.head[s.served]
		} else {
			p[i] = s.fill
		}
		s.served++
	}

	return n, nil
}

// crc32Trailer returns the x-amz-checksum-crc32 trailer header for payload
func crc32Trailer(payload string) string {
	sum := crc32.ChecksumIEEE([]byte(payload))
	return fmt.Sprintf("%s:%s", checksumTypeCrc32,
		base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, sum)))
}

// unsignedChunkBodyWithChecksum builds a body of count chunks of chunkSize
// bytes each, with a crc32 trailer
func unsignedChunkBodyWithChecksum(count, chunkSize int) []byte {
	chunk := strings.Repeat("a", chunkSize)
	chunks := make([]string, count)
	for i := range chunks {
		chunks[i] = chunk
	}
	body := unsignedChunkBody(chunks...)

	trailer := crc32Trailer(strings.Repeat(chunk, count))
	return []byte(strings.TrimSuffix(body, "\r\n") + trailer + "\r\n\r\n")
}

func unsignedChunkBody(chunks ...string) string {
	var b strings.Builder
	for _, chunk := range chunks {
		fmt.Fprintf(&b, "%x\r\n%s\r\n", len(chunk), chunk)
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func requireAPIErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", code)
	}
	var apiErr s3err.S3Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.BaseError().Code != code {
		t.Fatalf("APIError code = %q, want %q", apiErr.BaseError().Code, code)
	}
}
