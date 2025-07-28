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

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/utils"
)

func wrapBodyReader(ctx *fiber.Ctx, wr func(io.Reader) io.Reader) {
	r, ok := utils.ContextKeyBodyReader.Get(ctx).(io.Reader)
	if !ok {
		r = ctx.Request().BodyStream()
		// Override the body reader with an empty reader to prevent panics
		// in case of unexpected or malformed HTTP requests.
		if r == nil {
			r = bytes.NewBuffer([]byte{})
		}
	}

	r = wr(r)
	utils.ContextKeyBodyReader.Set(ctx, r)
}
