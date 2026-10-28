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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/s3err"
)

const (
	testSeedSignature = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
	testRegion        = "us-east-1"
)

var (
	testSigningKey  = []byte("signing-key")
	testSigningDate = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
)

type signedTestChunk struct {
	size string
	data string
}

func TestSignedChunkReaderChunkSize(t *testing.T) {
	full := strings.Repeat("a", int(minChunkSize))
	incompleteBody := s3err.GetAPIError(s3err.ErrIncompleteBody)

	tests := []struct {
		name      string
		chunks    []signedTestChunk
		finalSize string
		wantErr   error
	}{
		{
			name:    "negative first chunk",
			chunks:  []signedTestChunk{{"-1", "hello"}},
			wantErr: incompleteBody,
		},
		{
			name:    "negative first chunk equal to its data length",
			chunks:  []signedTestChunk{{"-5", "hello"}},
			wantErr: incompleteBody,
		},
		{
			name:    "min int64 first chunk",
			chunks:  []signedTestChunk{{"-8000000000000000", "hello"}},
			wantErr: incompleteBody,
		},
		{
			name:    "negative chunk after a full chunk",
			chunks:  []signedTestChunk{{"2000", full}, {"-1", "hello"}},
			wantErr: incompleteBody,
		},
		{
			name:    "negative chunk after a short chunk",
			chunks:  []signedTestChunk{{"5", "hello"}, {"-1", "hello"}},
			wantErr: incompleteBody,
		},
		{
			name:      "negative final chunk",
			chunks:    []signedTestChunk{{"5", "hello"}},
			finalSize: "-1",
			wantErr:   incompleteBody,
		},
		{
			name:    "explicit plus sign",
			chunks:  []signedTestChunk{{"+5", "hello"}},
			wantErr: nil,
		},
		{
			name:      "negative zero final chunk",
			chunks:    []signedTestChunk{{"5", "hello"}},
			finalSize: "-0",
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cLength int64
			for _, c := range tt.chunks {
				cLength += int64(len(c.data))
			}

			body := signedChunkBody(tt.chunks, tt.finalSize)
			reader, err := NewSignedChunkReader(strings.NewReader(body), AuthData{Signature: testSeedSignature, Region: testRegion}, "", testSigningKey, testSigningDate, "", false, cLength)
			if err != nil {
				t.Fatal(err)
			}

			_, err = io.ReadAll(reader)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("read all: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("read all error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignedChunkReaderSplitHeader(t *testing.T) {
	full := strings.Repeat("a", int(minChunkSize))
	body := signedChunkBody([]signedTestChunk{{"2000", full}, {"5", "hello"}}, "")

	// every split point makes the reader stash a partial chunk header
	// or chunk data at a different position
	for i := 1; i < len(body); i++ {
		reader, err := NewSignedChunkReader(io.MultiReader(strings.NewReader(body[:i]), strings.NewReader(body[i:])), AuthData{Signature: testSeedSignature, Region: testRegion}, "", testSigningKey, testSigningDate, "", false, int64(len(full)+len("hello")))
		if err != nil {
			t.Fatal(err)
		}

		out, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("split at %v: read all: %v", i, err)
		}
		if string(out) != full+"hello" {
			t.Fatalf("split at %v: read data length = %v, want %v", i, len(out), len(full)+len("hello"))
		}
	}
}

func TestSignedChunkReaderSignatureWithDelimiter(t *testing.T) {
	// a 64 byte chunk signature with '\r\n' in the middle
	sig := strings.Repeat("0", 28) + "\r\n" + strings.Repeat("0", 34)
	header := "5;chunk-signature=" + sig + "\r\n"
	body := header + "hello\r\n0;chunk-signature=" + strings.Repeat("0", 64) + "\r\n\r\n"

	for _, split := range []int{0, 30, strings.Index(header, "\r\n") + 2, len(header) - 1} {
		var r io.Reader = strings.NewReader(body)
		if split > 0 {
			r = io.MultiReader(strings.NewReader(body[:split]), strings.NewReader(body[split:]))
		}
		reader, err := NewSignedChunkReader(r, AuthData{Signature: testSeedSignature, Region: testRegion}, "", testSigningKey, testSigningDate, "", false, 5)
		if err != nil {
			t.Fatal(err)
		}

		_, err = io.ReadAll(reader)
		requireAPIErrorCode(t, err, "SignatureDoesNotMatch")
	}
}

// signedChunkBody encodes the chunks as a STREAMING-AWS4-HMAC-SHA256-PAYLOAD
// body with valid chunk signatures. The size fields are written verbatim, so
// they don't have to match the chunk data.
func signedChunkBody(chunks []signedTestChunk, finalSize string) string {
	if finalSize == "" {
		finalSize = "0"
	}

	var b strings.Builder
	prevSig := testSeedSignature
	sign := func(data string) string {
		hsh := sha256.Sum256([]byte(data))
		strToSign := strings.Join([]string{
			streamPayloadAlgo,
			testSigningDate.Format("20060102T150405Z"),
			testSigningDate.Format("20060102") + "/" + testRegion + "/" + awsS3Service + "/" + awsV4Request,
			prevSig,
			zeroLenSig,
			hex.EncodeToString(hsh[:]),
		}, "\n")
		prevSig = hex.EncodeToString(hmac256(testSigningKey, []byte(strToSign)))
		return prevSig
	}

	for _, c := range chunks {
		b.WriteString(c.size)
		b.WriteString(";chunk-signature=")
		b.WriteString(sign(c.data))
		b.WriteString("\r\n")
		b.WriteString(c.data)
		b.WriteString("\r\n")
	}
	b.WriteString(finalSize)
	b.WriteString(";chunk-signature=")
	b.WriteString(sign(""))
	b.WriteString("\r\n\r\n")
	return b.String()
}
