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
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3response"
)

// ResolveWebsiteIndex rewrites directory-like object keys to include the
// configured IndexDocument suffix when website hosting is enabled for the
// bucket. It also handles RedirectAllRequestsTo by returning a 301 redirect.
//
// This middleware should be placed in the GetObject handler chain before
// authentication and the controller.
func ResolveWebsiteIndex(be backend.Backend) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if utils.ContextKeySkip.IsSet(ctx) {
			return ctx.Next()
		}

		bucket := ctx.Params("bucket")
		if bucket == "" {
			return ctx.Next()
		}

		key := ctx.Params("*1")

		// Only process directory-like keys (empty or ending with /)
		if key != "" && !strings.HasSuffix(key, "/") {
			return ctx.Next()
		}

		// Reject path traversal attempts
		if strings.Contains(key, "..") {
			return ctx.Next()
		}

		data, err := be.GetBucketWebsite(ctx.Context(), bucket)
		if err != nil {
			// No website config: pass through to normal handling
			return ctx.Next()
		}

		var config s3response.WebsiteConfiguration
		if xmlErr := xml.Unmarshal(data, &config); xmlErr != nil {
			return ctx.Next()
		}

		// Handle RedirectAllRequestsTo
		if config.RedirectAllRequestsTo != nil {
			return redirectAll(ctx, config.RedirectAllRequestsTo, key)
		}

		// Rewrite directory-like keys to include index document suffix
		if config.IndexDocument != nil && config.IndexDocument.Suffix != "" {
			newKey := key + config.IndexDocument.Suffix
			newPath := fmt.Sprintf("/%s/%s", bucket, newKey)
			ctx.Request().URI().SetPath(newPath)
		}

		return ctx.Next()
	}
}

func redirectAll(ctx *fiber.Ctx, redirect *s3response.RedirectAllRequestsTo, key string) error {
	protocol := redirect.Protocol
	if protocol == "" {
		protocol = "https"
	}

	location := fmt.Sprintf("%s://%s/%s", protocol, redirect.HostName, key)
	ctx.Set("Location", location)
	return ctx.SendStatus(http.StatusMovedPermanently)
}
