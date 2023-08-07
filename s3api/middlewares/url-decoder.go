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
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

func DecodeURL(logger s3log.AuditLogger) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		reqURL := ctx.Request().URI().String()
		decoded, err := url.Parse(reqURL)
		if err != nil {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidURI), &controllers.MetaOpts{Logger: logger})
		}
		ctx.Path(decoded.Path)
		decodedURL, err := url.QueryUnescape(reqURL)
		if err != nil {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidURI), &controllers.MetaOpts{Logger: logger})
		}
		ctx.Request().SetRequestURI(decodedURL)
		return ctx.Next()
	}
}
