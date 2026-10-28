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

package httpctx

import (
	"bytes"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// RequestHost returns the host ctx's request is addressed to, exactly as the
// client sent it: the authority of an absolute-form request-target
// ("GET http://host/path HTTP/1.1"), which takes precedence over the Host
// header (RFC 9112, section 3.2.2), or else the Host header. S3 resolves the
// host the same way, and both routes and signs the request with it.
//
// SigV4 signs this host, so anything deriving the bucket from the host must
// read it from here too, never from fasthttp's URI().Host(): that one may
// name another host than the signed one, as it lowercases the host, drops a
// userinfo prefix, and even takes a host out of an origin-form target like
// "//host/path#://".
func RequestHost(ctx fiber.Ctx) string {
	if _, authority, ok := absoluteForm(ctx.Request().Header.RequestURI()); ok && authority != "" {
		return authority
	}
	return string(ctx.Request().Header.Host())
}

// HasHTTPScheme reports whether ctx's request-target is an http or https URI,
// or has no scheme at all, like an origin-form one ("/path"). S3 rejects an
// absolute-form target of any other scheme.
func HasHTTPScheme(ctx fiber.Ctx) bool {
	scheme, _, ok := absoluteForm(ctx.Request().Header.RequestURI())
	return !ok || strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}

// absoluteForm splits an absolute-form request-target,
// "scheme://authority[/path][?query]", into its scheme and authority. The
// authority is empty in "http:///path", which S3 takes as having none.
func absoluteForm(target []byte) (scheme, authority string, ok bool) {
	s, rest, found := bytes.Cut(target, []byte("://"))
	if !found || !isScheme(s) {
		return "", "", false
	}
	if i := bytes.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return string(s), string(rest), true
}

// isScheme reports whether s is a URI scheme (RFC 3986, section 3.1): a
// letter followed by any letters, digits, "+", "-" and ".".
func isScheme(s []byte) bool {
	if len(s) == 0 || !isLetter(s[0]) {
		return false
	}
	for _, c := range s[1:] {
		if !isLetter(c) && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
