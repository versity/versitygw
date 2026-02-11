// Copyright 2023 Versity Software
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

package middlewares

import (
	"bytes"
	"io"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/s3api/utils"
)

// ChecksumReader extends io.Reader with checksum-related metadata.
// It is used to differentiate normal readers from readers that can
// report a checksum and the algorithm used to produce it.
type ChecksumReader interface {
	io.Reader
	Algorithm() string
	Checksum() string
}

// NewChecksumReader wraps a stackedReader and returns a reader that
// preserves checksum behavior when the *original* bodyReader implemented
// ChecksumReader.
//
// If bodyReader already supports ChecksumReader, we wrap stackedReader
// with MockChecksumReader so that reading continues from stackedReader,
// but Algorithm() and Checksum() still delegate to the underlying reader.
//
// If bodyReader is not a ChecksumReader, we simply return stackedReader.
func NewChecksumReader(bodyReader io.Reader, stackedReader io.Reader) io.Reader {
	_, ok := bodyReader.(ChecksumReader)
	if ok {
		return &MockChecksumReader{rdr: stackedReader}
	}

	return stackedReader
}

// MockChecksumReader is a wrapper around an io.Reader that forwards Read()
// but also conditionally exposes checksum metadata if the underlying reader
// implements the ChecksumReader interface.
type MockChecksumReader struct {
	rdr io.Reader
}

// Read simply forwards data reads to the underlying reader.
func (rr *MockChecksumReader) Read(buffer []byte) (int, error) {
	return rr.rdr.Read(buffer)
}

// Algorithm returns the checksum algorithm used by the underlying reader,
// but only if the wrapped reader implements ChecksumReader.
func (rr *MockChecksumReader) Algorithm() string {
	r, ok := rr.rdr.(ChecksumReader)
	if ok {
		return r.Algorithm()
	}

	return ""
}

// Checksum returns the checksum value from the underlying reader,
// if it implements ChecksumReader. Otherwise returns an empty string.
func (rr *MockChecksumReader) Checksum() string {
	r, ok := rr.rdr.(ChecksumReader)
	if ok {
		return r.Checksum()
	}

	return ""
}

var _ ChecksumReader = &MockChecksumReader{}

func wrapBodyReader(ctx fiber.Ctx, wr func(io.Reader) io.Reader) {
	rdr, ok := utils.ContextKeyBodyReader.Get(ctx).(io.Reader)
	if !ok {
		rdr = ctx.Request().BodyStream()
		// Override the body reader with an empty reader to prevent panics
		// in case of unexpected or malformed HTTP requests.
		if rdr == nil {
			rdr = bytes.NewBuffer([]byte{})
		}
	}

	r := wr(rdr)
	// Ensure checksum behavior is stacked if the original body reader had it.
	r = NewChecksumReader(rdr, r)

	utils.ContextKeyBodyReader.Set(ctx, r)
}
