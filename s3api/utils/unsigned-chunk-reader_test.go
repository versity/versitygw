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
	"errors"
	"fmt"
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
	var apiErr s3err.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != code {
		t.Fatalf("APIError code = %q, want %q", apiErr.Code, code)
	}
}
