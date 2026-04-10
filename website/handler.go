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

package website

import (
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

// newHandler returns a fiber handler that serves static website content.
// It resolves the bucket name from the Host header using the configured domain,
// fetches the website configuration, and serves objects accordingly.
//
// Virtual-host routing with --website-domain example.com:
//   - Host "blog.example.com"  -> bucket "blog"
//   - Host "example.com"       -> bucket "example.com" (apex)
//
// Catch-all mode (--website-domain omitted or empty):
//   - Host "blog.example.com"  -> bucket "blog.example.com"
//   - Host "mysite.org"        -> bucket "mysite.org"
func newHandler(be backend.Backend, domain string) fiber.Handler {
	// Pre-compute the domain suffix for subdomain extraction.
	// Given domain "example.com", we look for ".example.com" suffix.
	domainSuffix := "." + domain

	return func(ctx *fiber.Ctx) error {
		host := ctx.Hostname()
		if host == "" {
			return sendError(ctx, http.StatusBadRequest, "Bad Request", "Missing Host header")
		}

		// Strip port from host if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			// Be careful with IPv6: only strip if it's not inside brackets
			if !strings.Contains(host[idx:], "]") {
				host = host[:idx]
			}
		}

		// Resolve bucket name from host
		bucket := resolveBucket(host, domain, domainSuffix)
		if bucket == "" {
			return sendError(ctx, http.StatusForbidden, "Forbidden",
				fmt.Sprintf("No bucket could be resolved from host %q", html.EscapeString(ctx.Hostname())))
		}

		// Fetch website configuration
		data, err := be.GetBucketWebsite(ctx.Context(), bucket)
		if err != nil {
			return sendError(ctx, http.StatusNotFound, "Not Found",
				fmt.Sprintf("No website configuration for bucket %q", bucket))
		}

		var config s3response.WebsiteConfiguration
		if xmlErr := xml.Unmarshal(data, &config); xmlErr != nil {
			return sendError(ctx, http.StatusInternalServerError, "Internal Server Error",
				"Invalid website configuration")
		}

		key := strings.TrimPrefix(ctx.Path(), "/")

		// Handle RedirectAllRequestsTo
		if config.RedirectAllRequestsTo != nil {
			return handleRedirectAll(ctx, config.RedirectAllRequestsTo, key)
		}

		// Evaluate pre-request routing rules
		if rule := config.MatchPreRequestRule(key); rule != nil {
			return applyRedirect(ctx, &rule.Redirect, rule.Condition, key)
		}

		// Rewrite directory-like keys to include index document suffix
		if config.IndexDocument != nil && config.IndexDocument.Suffix != "" {
			if key == "" || strings.HasSuffix(key, "/") {
				key = key + config.IndexDocument.Suffix
			}
		}

		// Fetch the object
		emptyRange := ""
		result, getErr := be.GetObject(ctx.Context(), &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &key,
			Range:  &emptyRange,
		})
		if getErr == nil && result.Body != nil {
			defer result.Body.Close()
			return serveObject(ctx, result, key)
		}

		// Object not found (or other error) — evaluate post-request routing rules
		httpErrCode := http.StatusNotFound
		errorCode := strconv.Itoa(httpErrCode)

		if rule := config.MatchPostRequestRule(key, errorCode); rule != nil {
			return applyRedirect(ctx, &rule.Redirect, rule.Condition, key)
		}

		// Serve error document if configured
		if config.ErrorDocument != nil && config.ErrorDocument.Key != "" {
			return serveErrorDocument(ctx, be, bucket, config.ErrorDocument.Key, httpErrCode)
		}

		return sendError(ctx, http.StatusNotFound, "Not Found",
			fmt.Sprintf("The specified key %q does not exist", key))
	}
}

// resolveBucket extracts the bucket name from the host header.
//
// When domain is set:
//   - If host equals the domain exactly, the bucket IS the domain (apex).
//   - If host ends with ".<domain>", the bucket is the subdomain part.
//   - Otherwise, no bucket can be resolved.
//
// When domain is empty (catch-all mode):
//   - The full hostname is used as the bucket name.
func resolveBucket(host, domain, domainSuffix string) string {
	if domain == "" {
		// Catch-all: the full hostname is the bucket name
		return host
	}

	if strings.EqualFold(host, domain) {
		return domain
	}

	lower := strings.ToLower(host)
	if strings.HasSuffix(lower, strings.ToLower(domainSuffix)) {
		sub := host[:len(host)-len(domainSuffix)]
		if sub != "" && !strings.Contains(sub, ".") {
			return sub
		}
	}

	return ""
}

// handleRedirectAll sends a 301 redirect for RedirectAllRequestsTo configuration.
func handleRedirectAll(ctx *fiber.Ctx, redirect *s3response.RedirectAllRequestsTo, key string) error {
	protocol := redirect.Protocol
	if protocol == "" {
		protocol = "https"
	}

	location := fmt.Sprintf("%s://%s/%s", protocol, redirect.HostName, key)
	ctx.Set("Location", location)
	return ctx.SendStatus(http.StatusMovedPermanently)
}

// applyRedirect constructs and sends a redirect response from a routing rule.
func applyRedirect(ctx *fiber.Ctx, redirect *s3response.Redirect, condition *s3response.RoutingRuleCondition, originalKey string) error {
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
	} else if redirect.ReplaceKeyPrefixWith != "" && condition != nil && condition.KeyPrefixEquals != "" {
		key = redirect.ReplaceKeyPrefixWith + strings.TrimPrefix(originalKey, condition.KeyPrefixEquals)
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

// serveObject writes the S3 object content to the response.
func serveObject(ctx *fiber.Ctx, result *s3.GetObjectOutput, key string) error {
	contentType := guessContentType(result, key)
	ctx.Set("Content-Type", contentType)

	if result.ETag != nil {
		ctx.Set("ETag", *result.ETag)
	}
	if result.CacheControl != nil {
		ctx.Set("Cache-Control", *result.CacheControl)
	}
	if result.ContentEncoding != nil {
		ctx.Set("Content-Encoding", *result.ContentEncoding)
	}
	if result.ContentLanguage != nil {
		ctx.Set("Content-Language", *result.ContentLanguage)
	}
	if result.ContentLength != nil {
		ctx.Set("Content-Length", strconv.FormatInt(*result.ContentLength, 10))
	}
	if result.LastModified != nil {
		ctx.Set("Last-Modified", result.LastModified.UTC().Format(http.TimeFormat))
	}

	_, err := io.Copy(ctx.Response().BodyWriter(), result.Body)
	if err != nil {
		return sendError(ctx, http.StatusInternalServerError, "Internal Server Error",
			"Failed to read object")
	}

	return nil
}

// serveErrorDocument fetches and serves the configured error document.
func serveErrorDocument(ctx *fiber.Ctx, be backend.Backend, bucket, errorDocKey string, statusCode int) error {
	emptyRange := ""
	result, err := be.GetObject(ctx.Context(), &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &errorDocKey,
		Range:  &emptyRange,
	})
	if err != nil {
		return sendError(ctx, statusCode, "Not Found", "The specified key does not exist")
	}
	if result.Body == nil {
		return sendError(ctx, statusCode, "Not Found", "The specified key does not exist")
	}
	defer result.Body.Close()

	contentType := guessContentType(result, errorDocKey)
	ctx.Set("Content-Type", contentType)

	ctx.Status(statusCode)
	_, writeErr := io.Copy(ctx.Response().BodyWriter(), result.Body)
	if writeErr != nil {
		return sendError(ctx, statusCode, "Not Found", "The specified key does not exist")
	}

	return nil
}

// guessContentType returns the content type from the GetObject result, or
// infers it from the key extension, defaulting to text/html.
func guessContentType(result *s3.GetObjectOutput, key string) string {
	if result.ContentType != nil && *result.ContentType != "" {
		return *result.ContentType
	}

	// Simple extension-based inference for common web types
	switch {
	case strings.HasSuffix(key, ".html"), strings.HasSuffix(key, ".htm"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(key, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(key, ".js"):
		return "application/javascript"
	case strings.HasSuffix(key, ".json"):
		return "application/json"
	case strings.HasSuffix(key, ".xml"):
		return "application/xml"
	case strings.HasSuffix(key, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(key, ".png"):
		return "image/png"
	case strings.HasSuffix(key, ".jpg"), strings.HasSuffix(key, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(key, ".gif"):
		return "image/gif"
	case strings.HasSuffix(key, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(key, ".txt"):
		return "text/plain; charset=utf-8"
	default:
		return "text/html; charset=utf-8"
	}
}

// sendError sends a simple HTML error page.
func sendError(ctx *fiber.Ctx, statusCode int, title, message string) error {
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	ctx.Status(statusCode)
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%d %s</title></head>
<body>
<h1>%d %s</h1>
<p>%s</p>
</body>
</html>`, statusCode, title, statusCode, title, message)
	return ctx.SendString(body)
}
