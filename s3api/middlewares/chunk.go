// Copyright 2024 Versity Software
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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3log"
)

// ProcessChunkedBody initializes the chunked upload stream if the
// request appears to be a chunked upload
func ProcessChunkedBody(root RootUserConfig, iam auth.IAMService, logger s3log.AuditLogger, mm *metrics.Manager, region string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		decodedLength := ctx.Get("X-Amz-Decoded-Content-Length")
		if decodedLength == "" {
			return ctx.Next()
		}
		// TODO: validate content length

		authData, err := utils.ParseAuthorization(ctx.Get("Authorization"))
		if err != nil {
			return sendResponse(ctx, err, logger, mm)
		}

		acct := ctx.Locals("account").(auth.Account)
		amzdate := ctx.Get("X-Amz-Date")
		date, _ := time.Parse(iso8601Format, amzdate)

		if utils.IsBigDataAction(ctx) {
			var err error
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				var cr *utils.ChunkReader
				cr, err = utils.NewChunkReader(ctx, r, authData, region, acct.Secret, date)
				return cr
			})
			if err != nil {
				return sendResponse(ctx, err, logger, mm)
			}
			return ctx.Next()
		}

		return ctx.Next()
	}
}
