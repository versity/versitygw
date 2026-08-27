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

package iammiddleware

import (
	"strings"

	"github.com/gofiber/fiber/v3"
)

// corsMaxAge is how long a browser may reuse a preflight result, matching what
// IAM returns. Browsers clamp it to their own ceiling, so it is only a hint.
const corsMaxAge = "172800"

// corsExposeHeaders names the non-safelisted response headers a browser is
// allowed to read. The IAM API sets exactly two.
const corsExposeHeaders = HeaderAmznRequestID + ",Date"

// CORS answers browser preflights and stamps the CORS headers onto
// cross-origin responses, so the WebUI can call this API from its own origin.
// Register it only when the operator configured an allowed origin; left
// unregistered, the API stays usable by CLI and SDK clients but no browser.
func CORS(allowOrigin string) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		if ctx.Get(fiber.HeaderOrigin) == "" {
			// Not a browser call; IAM leaves these untouched.
			return ctx.Next()
		}

		ctx.Response().Header.Set(fiber.HeaderAccessControlAllowOrigin, allowOrigin)
		ctx.Response().Header.Set(fiber.HeaderAccessControlExposeHeaders, corsExposeHeaders)
		ctx.Response().Header.Add(fiber.HeaderVary, fiber.HeaderOrigin)

		if string(ctx.Request().Header.Method()) != fiber.MethodOptions {
			return ctx.Next()
		}

		// Preflight. Echo back what was asked for rather than enumerating the
		// SigV4 header set, which changes with every signing detail.
		if reqMethod := ctx.Get(fiber.HeaderAccessControlRequestMethod); strings.TrimSpace(reqMethod) != "" {
			ctx.Response().Header.Set(fiber.HeaderAccessControlAllowMethods, reqMethod)
		}
		if reqHeaders := ctx.Get(fiber.HeaderAccessControlRequestHeaders); strings.TrimSpace(reqHeaders) != "" {
			ctx.Response().Header.Set(fiber.HeaderAccessControlAllowHeaders, reqHeaders)
		}
		ctx.Response().Header.Set(fiber.HeaderAccessControlMaxAge, corsMaxAge)

		ctx.Status(fiber.StatusOK)
		return nil
	}
}
