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
)

// ApplyDefaultCORSPreflight responds to CORS preflight (OPTIONS) requests for routes
// that don't have per-bucket CORS configuration (e.g. admin APIs).
//
// It uses the provided fallbackOrigin as the Access-Control-Allow-Origin value.
// It mirrors Access-Control-Request-Method into Access-Control-Allow-Methods and
// mirrors Access-Control-Request-Headers into Access-Control-Allow-Headers.
func ApplyDefaultCORSPreflight(fallbackOrigin string) fiber.Handler {
	fallbackOrigin = strings.TrimSpace(fallbackOrigin)
	if fallbackOrigin == "" {
		return func(ctx *fiber.Ctx) error { return nil }
	}

	return func(ctx *fiber.Ctx) error {
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
