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
// A backend is given ContentLength as the length of the file, which is only
// what the request proposes. The file can be longer, as for a body that ends
// with "--boundary" and no closing dashes. A backend that sends the length it
// is given as a request has sent a complete one once it has read that many
// bytes, and the upstream stores them. So the reader checks that the file ends
// at that length before it gives the last bytes of it, and fails it if it does
// not.
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
// for the file. If r is an MpFileReader, it tells the size of a file that is
// refused when it can do so without waiting for the client.
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

	var n int
	var err error
	if r.eof.Load() {
		// lookForEnd found the end of the file
		err = io.EOF
	} else {
		n, err = r.r.Read(p)
	}
	read := r.read.Add(int64(n))

	if err := r.tooLong(read); err != nil {
		return 0, r.fail(err)
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
	case n > 0 && read == r.ContentLength():
		// A backend can stop here, with a complete request sent. The bytes of
		// this read are not given unless the file ends here.
		if err := r.lookForEnd(); err != nil {
			return 0, err
		}
	}

	return n, err
}

// tooLong returns the error for a file of read bytes if it is too long: over
// the max, or past the length given to the backend.
func (r *ContentLengthRangeReader) tooLong(read int64) error {
	switch {
	case read > r.max:
		debuglogger.Logf("POST object file is over the allowed %d bytes", r.max)
		return s3err.GetEntityTooLargeErr(r.refusedSize(), r.max)
	case read > r.ContentLength():
		debuglogger.Logf("POST object file is over the %d bytes the request proposes", r.ContentLength())
		return s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}

	return nil
}

// lookForEnd checks that the file ends at the length given to the backend, by
// reading one byte past it. It fails the reader if the file goes on. That byte
// is never given to the backend.
func (r *ContentLengthRangeReader) lookForEnd() error {
	var b [1]byte
	n, err := io.ReadFull(r.r, b[:])
	read := r.read.Add(int64(n))

	switch {
	case n > 0:
		return r.fail(r.tooLong(read))
	case errors.Is(err, io.EOF):
		r.eof.Store(true)
		return nil
	default:
		return r.fail(err)
	}
}

// refusedSize is the size to report for a file over the max: its own if the end
// of it is in the bytes the reader of it holds, and else the size the request
// proposes, which is the file's for a form that ends with it. The rest of the
// file is not read to measure it: the client may be slow to send it.
func (r *ContentLengthRangeReader) refusedSize() int64 {
	if f, ok := r.r.(MpFileReader); ok {
		if size, ok := f.BufferedSize(); ok {
			return size
		}
	}

	return max(r.proposed, r.read.Load())
}

func (r *ContentLengthRangeReader) fail(err error) error {
	r.err.Store(&err)

	return err
}

// Err returns the error the reader failed with: EntityTooLarge or
// EntityTooSmall for a file out of its range, MalformedPOSTRequest for one
// that goes on past the length given to the backend, or the error of the
// reader of the file. It is nil if the reader did not fail.
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
