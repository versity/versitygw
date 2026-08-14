// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4auth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/internal/httpctx"
)

// signingInputFromCtx builds a SigningInput straight from ctx's underlying
// fasthttp request. isPreSign selects between header-auth's and presigned (query) auth's
// slightly different query/header handling; see queryFromCtx/
// presignQueryFromCtx and headersFromCtx.
func signingInputFromCtx(ctx fiber.Ctx, signedHdrs []string, contentLength int64, requiredSignedHdrs []string, isPreSign bool) (SigningInput, error) {
	if err := validateRequiredSignedHeaders(signedHdrs, requiredSignedHdrs); err != nil {
		return SigningInput{}, err
	}

	headers, err := headersFromCtx(ctx, signedHdrs, requiredSignedHdrs, isPreSign)
	if err != nil {
		return SigningInput{}, err
	}

	query := queryFromCtx(ctx)
	if isPreSign {
		query = presignQueryFromCtx(ctx)
	}

	return SigningInput{
		Method:        methodFromCtx(ctx),
		Host:          hostFromCtx(ctx),
		URIPath:       uriPathFromCtx(ctx),
		Query:         query,
		Header:        headers,
		ContentLength: contentLength,
		IsPreSign:     isPreSign,
	}, nil
}

// methodFromCtx returns ctx's HTTP method from the underlying fasthttp
// request header directly
func methodFromCtx(ctx fiber.Ctx) string {
	return string(ctx.Request().Header.Method())
}

// headersFromCtx collects ctx's request headers eligible for signing: every
// header naming itself in signedHdrs, plus any header ignoredHeaders always
// signs regardless. Reads straight off the underlying fasthttp request
// (Header.All(), preserving every duplicate key exactly as sent).
func headersFromCtx(ctx fiber.Ctx, signedHdrs, requiredSignedHdrs []string, isPreSign bool) (http.Header, error) {
	headers := http.Header{}
	headersNotSigned := []string{}
	for key, value := range ctx.Request().Header.All() {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) || IsIgnoredHeader(keyStr) {
			headers.Add(keyStr, string(value))
			continue
		}
		if isRequiredSignedHeader(keyStr, requiredSignedHdrs) {
			headersNotSigned = append(headersNotSigned, strings.ToLower(keyStr))
		}
	}

	if len(headersNotSigned) != 0 {
		debuglogger.Logf("headers present in request but not included in SignedHeaders: %q", strings.Join(headersNotSigned, ", "))
		return nil, &HeadersNotSignedError{Headers: headersNotSigned}
	}

	if !isPreSign {
		for _, header := range signedHdrs {
			if headers.Get(header) == "" {
				headers.Set(header, "")
			}
		}
	}

	return headers, nil
}

// queryFromCtx returns ctx's full, unfiltered query string as url.Values —
// the header-auth path, where any existing query parameters (e.g.
// ?partNumber=2) are simply part of the canonical request, untouched.
func queryFromCtx(ctx fiber.Ctx) url.Values {
	query := url.Values{}
	for key, value := range ctx.Request().URI().QueryArgs().All() {
		query.Add(string(key), string(value))
	}
	return query
}

// presignQueryFromCtx returns ctx's query string as url.Values with the
// generated SigV4 auth parameters excluded (generatedQueryAuthParams) —
// the presign path, which must recompute and re-add its own
// X-Amz-Credential/X-Amz-SignedHeaders/X-Amz-Signature rather than sign the
// client-presented ones.
func presignQueryFromCtx(ctx fiber.Ctx) url.Values {
	query := url.Values{}
	for key, value := range ctx.Request().URI().QueryArgs().All() {
		keyStr := string(key)
		if _, ok := generatedQueryAuthParams[keyStr]; ok {
			continue
		}
		query.Add(keyStr, string(value))
	}
	return query
}

// uriPathFromCtx returns ctx's raw request path exactly as received on the
// wire (fasthttp's PathOriginal — unnormalized, unescaped-or-not exactly as
// sent, no dot-segment collapsing), "/" if empty. HostStyleParser rewrites
// PathOriginal itself to move a virtual-hosted-style request's bucket from
// the Host header into the path for routing, so the true original is read
// back from where it stashed it rather than from PathOriginal directly.
func uriPathFromCtx(ctx fiber.Ctx) string {
	path := string(ctx.Request().URI().PathOriginal())
	if httpctx.ContextKeyOriginalURIPath.IsSet(ctx) {
		path, _ = httpctx.ContextKeyOriginalURIPath.Get(ctx).(string)
	}
	if path == "" {
		return "/"
	}
	return path
}

// hostFromCtx returns ctx's Host header verbatim.
func hostFromCtx(ctx fiber.Ctx) string {
	return string(ctx.Request().Header.Host())
}
