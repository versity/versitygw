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
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3err"
)

const streaingSizeLimit = 5 * 1024 * 1024 * 1024 // 5 Gib

func wrapBodyReader(ctx *fiber.Ctx, wr func(io.Reader) io.Reader) {
	r, ok := ctx.Locals("body-reader").(io.Reader)
	if !ok {
		r = ctx.Request().BodyStream()
	}

	r = wr(r)
	r = NewLimitedReader(r, streaingSizeLimit)
	ctx.Locals("body-reader", r)
}

// LimitedReader limits the amount of data read from the underlying io.Reader to a specified limit.
type LimitedReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (lr *LimitedReader) Read(data []byte) (n int, err error) {
	if lr.read > lr.limit {
		return int(lr.read), s3err.GetAPIError(s3err.ErrEntityTooLarge)
	}

	n, err = lr.r.Read(data)
	lr.read += int64(n)

	if lr.read > lr.limit {
		return n, s3err.GetAPIError(s3err.ErrEntityTooLarge)
	}

	return n, err
}

// NewLimitedReader creates a new LimitedReader instance
// with the specified limit, based on the provided io.Reader
func NewLimitedReader(r io.Reader, limit int64) io.Reader {
	return &LimitedReader{
		r:     r,
		limit: limit,
	}
}
