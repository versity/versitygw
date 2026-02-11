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

	"github.com/gofiber/fiber/v3"
)

func ensureExposeETag(ctx fiber.Ctx) {
	existing := strings.TrimSpace(string(ctx.Response().Header.Peek("Access-Control-Expose-Headers")))
	defaults := []string{"ETag"}
	if existing == "" {
		ctx.Response().Header.Add("Access-Control-Expose-Headers", strings.Join(defaults, ", "))
		return
	}

	lowerExisting := map[string]struct{}{}
	for _, part := range strings.Split(existing, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p != "" {
			lowerExisting[p] = struct{}{}
		}
	}

	updated := existing
	for _, h := range defaults {
		if _, ok := lowerExisting[strings.ToLower(h)]; ok {
			continue
		}
		updated += ", " + h
	}

	if updated != existing {
		ctx.Response().Header.Set("Access-Control-Expose-Headers", updated)
	}
}

// ApplyDefaultCORS adds a default Access-Control-Allow-Origin header to responses
// when the provided fallbackOrigin is non-empty.
//
// This is intended for routes that don't have per-bucket CORS configuration (e.g. admin APIs).
// It will not override an existing Access-Control-Allow-Origin header.
func ApplyDefaultCORS(fallbackOrigin string) fiber.Handler {
	fallbackOrigin = strings.TrimSpace(fallbackOrigin)
	if fallbackOrigin == "" {
		return func(ctx fiber.Ctx) error { return nil }
	}

	return func(ctx fiber.Ctx) error {
		if len(ctx.Response().Header.Peek("Access-Control-Allow-Origin")) == 0 {
			ctx.Response().Header.Add("Access-Control-Allow-Origin", fallbackOrigin)
		}
		if len(ctx.Response().Header.Peek("Vary")) == 0 {
			ctx.Response().Header.Add("Vary", VaryHdr)
		}
		ensureExposeETag(ctx)
		return nil
	}
}
