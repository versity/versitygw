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

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// ContentLengthReader turns an EOF that arrives before Content-Length bytes
// were read into an IncompleteBody error.
//
// fasthttp's request stream reports a client that closed the connection in
// the middle of a fixed-length body as a plain io.EOF (only the chunked
// transfer-encoding path is converted to io.ErrUnexpectedEOF), and io.Copy
// treats io.EOF as a normal end of stream. Without this check an aborted
// upload is committed as a complete, shorter object. aws-chunked bodies do
// not need this: their chunk readers already validate the framing.
type ContentLengthReader struct {
	r         io.Reader
	remaining int64
}

func NewContentLengthReader(r io.Reader, contentLength int64) *ContentLengthReader {
	return &ContentLengthReader{r: r, remaining: contentLength}
}

func (cr *ContentLengthReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.remaining -= int64(n)
	if cr.remaining > 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		debuglogger.Logf("request body ended %v bytes short of Content-Length", cr.remaining)
		return n, s3err.GetAPIError(s3err.ErrIncompleteBody)
	}
	return n, err
}

var _ io.Reader = &ContentLengthReader{}
