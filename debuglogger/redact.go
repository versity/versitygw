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

package debuglogger

import (
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/valyala/fasthttp"
)

// redactedValue replaces the value of a matched sensitive field entirely.
// The debug logger uses the same mask character for the partial masking
// applied to fields like AccessKeyId
const redactedValue = "****"

// sensitiveFieldNames lists header, query, and form field names (matched
// case-insensitively) whose values are bearer credentials or raw key
// material rather than diagnostic data: a JWT, a session token, a request
// signature, or an SSE-C encryption key. Anyone with log access could
// replay or reuse a logged value directly, so these are replaced with
// redactedValue everywhere a request or response is logged, in both normal
// and debug-mode logging.
var sensitiveFieldNames = map[string]bool{
	"authorization":        true,
	"x-amz-security-token": true,
	"webidentitytoken":     true,
	// The request signature itself: with the rest of a presigned URL
	// (which is not otherwise secret) this is everything needed to replay
	// the exact request until it expires.
	"x-amz-signature": true,
	// Carries the access key ID. Not secret on its own, but there's no
	// diagnostic value in logging it that isn't already available from
	// the (also masked) Authorization header, so mask it defensively too.
	"x-amz-credential": true,
	// SSE-C requests carry the raw AES-256 customer-provided encryption
	// key in these headers. The paired "...-key-md5" headers are just a
	// checksum of the key (not reversible to the key itself), so they're
	// left unmasked to help correlate requests using the same key.
	"x-amz-server-side-encryption-customer-key":             true,
	"x-amz-copy-source-server-side-encryption-customer-key": true,
}

func isSensitiveFieldName(name string) bool {
	return sensitiveFieldNames[strings.ToLower(name)]
}

// redact returns redactedValue in place of value when key names a
// credential-bearing header, query, or form field.
func redact(key, value string) string {
	if isSensitiveFieldName(key) {
		return redactedValue
	}
	return value
}

// RedactedQueryString rebuilds the request's query string with sensitive
// parameter values (see sensitiveFieldNames) replaced by redactedValue. It
// is safe to write to any log, including the default (non-debug) access
// log.
func RedactedQueryString(queryArgs *fasthttp.Args) string {
	if queryArgs.Len() == 0 {
		return ""
	}

	var b strings.Builder
	first := true
	for key, value := range queryArgs.All() {
		if !first {
			b.WriteByte('&')
		}
		first = false
		b.WriteString(url.QueryEscape(string(key)))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(redact(string(key), string(value))))
	}
	return b.String()
}

// RedactedQueryParamsTag is a logger.LogFunc that replaces the fiber logger
// middleware's built-in ${queryParams} tag with a redacted query string
// (see RedactedQueryString). Register it as a CustomTags override for
// logger.TagQueryStringParams so the default (non-debug) access log never
// writes credential-bearing query parameters such as WebIdentityToken or
// X-Amz-Security-Token.
var RedactedQueryParamsTag logger.LogFunc = func(output logger.Buffer, ctx fiber.Ctx, _ *logger.Data, _ string) (int, error) {
	return output.WriteString(RedactedQueryString(ctx.Request().URI().QueryArgs()))
}

// debugRedact is redact's counterpart for the debug logger's own
// header/query/form-field printing. Unlike redact (used by the always-on,
// non-debug access log), it honors LevelUnsafe: at that level it returns
// value unchanged so the debug output shows exactly what was on the wire.
// At LevelDebug it masks identically to redact.
func debugRedact(key, value string) string {
	if IsUnsafeEnabled() {
		return value
	}
	return redact(key, value)
}

// debugRedactedQueryString is RedactedQueryString's counterpart for the
// debug logger, using debugRedact so LevelUnsafe shows unmasked values.
func debugRedactedQueryString(queryArgs *fasthttp.Args) string {
	if queryArgs.Len() == 0 {
		return ""
	}

	var b strings.Builder
	first := true
	for key, value := range queryArgs.All() {
		if !first {
			b.WriteByte('&')
		}
		first = false
		b.WriteString(url.QueryEscape(string(key)))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(debugRedact(string(key), string(value))))
	}
	return b.String()
}
