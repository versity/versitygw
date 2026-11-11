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
	"sync/atomic"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// ContentLengthRangeReader reads the file of a POST Object upload and checks
// its size against the content-length-range the upload is allowed, as it goes.
//
// The form does not state the size of the file: the file ends at a boundary,
// with fields or an epilogue possibly after it. So it is only known once the
// file is read. A file over the max is refused as soon as more than that is
// read, without reading the rest of it, and one under the min when it ends.
//
// Once the reader fails it fails every read the same way. A backend can wrap
// the error it gets from a read, so Err has the one to report.
type ContentLengthRangeReader struct {
	r io.Reader
	// min and max are the sizes the file may have. max is never more than
	// 5 GiB, what S3 takes in one upload.
	min, max int64
	// proposed is the size the request proposes for the file, see
	// MpParseResult.ProposedSize.
	proposed int64

	// What follows is read by whoever called the backend, which can still be
	// reading the file when it returns.

	// read counts the bytes read from r.
	read atomic.Int64
	// eof is set when r has reached its end.
	eof atomic.Bool
	// err is the error the reader failed with.
	err atomic.Pointer[error]
}

var _ io.Reader = (*ContentLengthRangeReader)(nil)

// NewContentLengthRangeReader returns a reader of the file r, which fails with
// EntityTooLarge when the file has more than maxSize bytes and EntityTooSmall
// when it has less than minSize. proposedSize is the size the request proposes
// for the file.
func NewContentLengthRangeReader(r io.Reader, minSize, maxSize, proposedSize int64) *ContentLengthRangeReader {
	return &ContentLengthRangeReader{
		r:        r,
		min:      minSize,
		max:      min(maxSize, maxObjSizeLimit),
		proposed: proposedSize,
	}
}

// ContentLength is the length to give a backend for the file: the size the
// request proposes, and not more than one byte over the max. The request can
// propose any size, and a backend can reserve the length it gets before it
// reads the file.
//
// The length is one over the max, so that the reader fails a file over the max
// before the backend has read as many bytes as it expects. A backend that
// sends the length it is given, as the S3 proxy does, otherwise sends a
// complete request with the first max bytes of the file, and the upstream
// stores them before the reader refuses the rest.
func (r *ContentLengthRangeReader) ContentLength() int64 {
	return min(r.proposed, r.max+1)
}

func (r *ContentLengthRangeReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}

	n, err := r.r.Read(p)
	read := r.read.Add(int64(n))

	if read > r.max {
		debuglogger.Logf("POST object file is over the allowed %d bytes", r.max)
		return 0, r.fail(s3err.GetEntityTooLargeErr(r.refusedSize(), r.max))
	}

	switch {
	case errors.Is(err, io.EOF):
		r.eof.Store(true)
		if read < r.min {
			debuglogger.Logf("POST object file has %d bytes, under the allowed %d", read, r.min)
			return 0, r.fail(s3err.GetEntityTooSmallErr(read, r.min))
		}
	case err != nil:
		r.fail(err)
	}

	return n, err
}

// refusedSize is the size to report for a file over the max. The rest of the
// file is not read to measure it: it is the file's own size if one more read
// finds its end, and else the size the request proposes, which is the file's
// for a form that ends with it.
func (r *ContentLengthRangeReader) refusedSize() int64 {
	var b [1]byte
	n, err := r.r.Read(b[:])
	read := r.read.Add(int64(n))
	if errors.Is(err, io.EOF) {
		return read
	}

	return max(r.proposed, read)
}

func (r *ContentLengthRangeReader) fail(err error) error {
	r.err.Store(&err)

	return err
}

// Err returns the error the reader failed with: EntityTooLarge or
// EntityTooSmall for a file out of its range, or the error of the reader of
// the file. It is nil if the reader did not fail.
func (r *ContentLengthRangeReader) Err() error {
	if err := r.err.Load(); err != nil {
		return *err
	}

	return nil
}

// EndedBefore reports whether the file ended with fewer than n bytes.
func (r *ContentLengthRangeReader) EndedBefore(n int64) bool {
	return r.eof.Load() && r.read.Load() < n
}
