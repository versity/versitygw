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
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3response"
)

// ResolveWebsiteIndex handles website hosting logic for the request pipeline.
// It fetches the website configuration and caches it in the context for
// downstream use (e.g., error document serving). It handles:
//   - RedirectAllRequestsTo: returns a 301 redirect
//   - Pre-request routing rules: evaluates rules without HttpErrorCodeReturnedEquals
//   - Index document rewriting: rewrites directory-like keys to append the suffix
//
// This middleware should be placed in the GetObject/HeadObject handler chain
// before authentication and the controller.
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

		// Cache the parsed config in context for the error document wrapper
		utils.ContextKeyWebsiteConfig.Set(ctx, &config)

		// Handle RedirectAllRequestsTo
		if config.RedirectAllRequestsTo != nil {
			return redirectAll(ctx, config.RedirectAllRequestsTo, key)
		}

		// Evaluate pre-request routing rules (key prefix matches, no error code condition)
		if rule := config.MatchPreRequestRule(key); rule != nil {
			return applyRoutingRuleRedirect(ctx, rule, key)
		}

		// Rewrite directory-like keys to include index document suffix
		if key == "" || strings.HasSuffix(key, "/") {
			if config.IndexDocument != nil && config.IndexDocument.Suffix != "" {
				newKey := key + config.IndexDocument.Suffix
				newPath := fmt.Sprintf("/%s/%s", bucket, newKey)
				ctx.Request().URI().SetPath(newPath)
			}
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

// applyRoutingRuleRedirect constructs a redirect response from a matched
// pre-request routing rule.
func applyRoutingRuleRedirect(ctx *fiber.Ctx, rule *s3response.RoutingRule, originalKey string) error {
	redirect := rule.Redirect

	protocol := redirect.Protocol
	if protocol == "" {
		protocol = ctx.Protocol()
	}

	host := redirect.HostName
	if host == "" {
		host = ctx.Hostname()
	}

	key := originalKey
	if redirect.ReplaceKeyWith != "" {
		key = redirect.ReplaceKeyWith
	} else if redirect.ReplaceKeyPrefixWith != "" && rule.Condition != nil && rule.Condition.KeyPrefixEquals != "" {
		key = redirect.ReplaceKeyPrefixWith + strings.TrimPrefix(originalKey, rule.Condition.KeyPrefixEquals)
	}

	httpCode := http.StatusFound // 302 default
	if redirect.HttpRedirectCode != "" {
		if code, err := strconv.Atoi(redirect.HttpRedirectCode); err == nil {
			httpCode = code
		}
	}

	location := fmt.Sprintf("%s://%s/%s", protocol, host, key)
	ctx.Set("Location", location)
	return ctx.SendStatus(httpCode)
}
