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

package middlewares

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

// ApplyBucketCORSPreflightFallback handles CORS preflight (OPTIONS) requests for S3 routes
// when no per-bucket CORS configuration exists.
//
// If the bucket has no CORS configuration and fallbackOrigin is set, it responds with 204 and:
// - Access-Control-Allow-Origin: fallbackOrigin
// - Vary: Origin, Access-Control-Request-Headers, Access-Control-Request-Method
// - Access-Control-Allow-Methods: mirrors Access-Control-Request-Method (if present)
// - Access-Control-Allow-Headers: mirrors Access-Control-Request-Headers (if present)
//
// If the bucket has a CORS configuration (or fallbackOrigin is blank), it calls next so the
// standard CORS OPTIONS handler can apply bucket-specific rules.
func ApplyBucketCORSPreflightFallback(be backend.Backend, fallbackOrigin string) fiber.Handler {
	fallbackOrigin = strings.TrimSpace(fallbackOrigin)
	if fallbackOrigin == "" {
		return func(ctx *fiber.Ctx) error { return ctx.Next() }
	}

	return func(ctx *fiber.Ctx) error {
		bucket := ctx.Params("bucket")
		_, err := be.GetBucketCors(ctx.Context(), bucket)
		if err != nil {
			if s3Err, ok := err.(s3err.APIError); ok && (s3Err.Code == "NoSuchCORSConfiguration" || s3Err.Code == "NoSuchBucket") {
				if len(ctx.Response().Header.Peek("Access-Control-Allow-Origin")) == 0 {
					ctx.Response().Header.Add("Access-Control-Allow-Origin", fallbackOrigin)
				}
				if len(ctx.Response().Header.Peek("Vary")) == 0 {
					ctx.Response().Header.Add("Vary", VaryHdr)
				}

				if reqMethod := strings.TrimSpace(ctx.Get("Access-Control-Request-Method")); reqMethod != "" {
					if len(ctx.Response().Header.Peek("Access-Control-Allow-Methods")) == 0 {
						ctx.Response().Header.Add("Access-Control-Allow-Methods", reqMethod)
					}
				}

				if reqHeaders := strings.TrimSpace(ctx.Get("Access-Control-Request-Headers")); reqHeaders != "" {
					if len(ctx.Response().Header.Peek("Access-Control-Allow-Headers")) == 0 {
						ctx.Response().Header.Add("Access-Control-Allow-Headers", reqHeaders)
					}
				}

				ctx.Status(fiber.StatusNoContent)
				return nil
			}
		}

		return ctx.Next()
	}
}
