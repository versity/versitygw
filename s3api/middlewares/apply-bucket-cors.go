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
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// Vary http response header is always the same below
var VaryHdr = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"

// ApplyBucketCORS retreives the bucket CORS configuration,
// checks if origin and method meets the cors rules and
// adds the necessary response headers.
// CORS check is applied only when 'Origin' request header is present
func ApplyBucketCORS(be backend.Backend, fallbackOrigin string) fiber.Handler {
	fallbackOrigin = strings.TrimSpace(fallbackOrigin)

	return func(ctx *fiber.Ctx) error {
		bucket := ctx.Params("bucket")
		origin := ctx.Get("Origin")
		// If neither Origin is present nor a fallback is configured, skip CORS entirely.
		if origin == "" && fallbackOrigin == "" {
			return nil
		}

		// if bucket cors is not set, skip the check
		data, err := be.GetBucketCors(ctx.Context(), bucket)
		if err != nil {
			// If CORS is not configured, S3Error will have code NoSuchCORSConfiguration.
			// In this case, we can safely continue. For any other error, we should log it.
			s3Err, ok := err.(s3err.APIError)
			if ok && (s3Err.Code == "NoSuchCORSConfiguration" || s3Err.Code == "NoSuchBucket") {
				// Optional global fallback: add Access-Control-Allow-Origin for buckets
				// without a specific CORS configuration.
				if fallbackOrigin != "" {
					if len(ctx.Response().Header.Peek("Access-Control-Allow-Origin")) == 0 {
						ctx.Response().Header.Add("Access-Control-Allow-Origin", fallbackOrigin)
					}
					if len(ctx.Response().Header.Peek("Vary")) == 0 {
						ctx.Response().Header.Add("Vary", VaryHdr)
					}
					ensureExposeETag(ctx)
				}
				return nil
			}
			if !ok || s3Err.Code != "NoSuchCORSConfiguration" {
				debuglogger.Logf("failed to get bucket cors for bucket %q: %v", bucket, err)
			}
			return nil
		}

		// If Origin is missing, don't attempt per-bucket CORS evaluation.
		// (Fallback has already been handled above for buckets without CORS config.)
		if origin == "" {
			return nil
		}

		cors, err := auth.ParseCORSOutput(data)
		if err != nil {
			return nil
		}

		method := auth.CORSHTTPMethod(ctx.Get("Access-Control-Request-Method"))
		headers := ctx.Get("Access-Control-Request-Headers")

		// if request method is not specified with Access-Control-Request-Method
		// override it with the actual request method
		if method.IsEmpty() {
			method = auth.CORSHTTPMethod(ctx.Request().Header.Method())
		} else if !method.IsValid() {
			// check if allowed method is valid
			debuglogger.Logf("invalid cors method: %s", method)
			return s3err.GetInvalidCORSMethodErr(method.String())
		}

		// parse and validate headers
		parsedHeaders, err := auth.ParseCORSHeaders(headers)
		if err != nil {
			return err
		}

		allowConfig, err := cors.IsAllowed(origin, method, parsedHeaders)
		if err != nil {
			// if bucket cors rules doesn't grant access, skip
			// and don't add any response headers
			return nil
		}

		if allowConfig.MaxAge != nil {
			ctx.Response().Header.Add("Access-Control-Max-Age", fmt.Sprint(*allowConfig.MaxAge))
		}

		for key, val := range map[string]string{
			"Access-Control-Allow-Origin":      allowConfig.Origin,
			"Access-Control-Allow-Methods":     allowConfig.Methods,
			"Access-Control-Expose-Headers":    allowConfig.ExposedHeaders,
			"Access-Control-Allow-Credentials": allowConfig.AllowCredentials,
			"Access-Control-Allow-Headers":     allowConfig.AllowHeaders,
			"Vary":                             VaryHdr,
		} {
			if val != "" {
				ctx.Response().Header.Add(key, val)
			}
		}

		// Always expose ETag and user metadata headers for browser clients.
		ensureExposeETag(ctx)

		return nil
	}
}
