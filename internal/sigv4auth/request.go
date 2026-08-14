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
)

// SigningInputFromRequest extracts a SigningInput's request-shaped fields
// (Method, Host, URIPath, Query, Header, ContentLength) from a real
// *http.Request being signed for an outbound call
func SigningInputFromRequest(req *http.Request) SigningInput {
	return SigningInput{
		Method:        req.Method,
		Host:          sanitizedHost(req),
		URIPath:       getURIPath(req.URL),
		Query:         req.URL.Query(),
		Header:        req.Header,
		ContentLength: req.ContentLength,
	}
}

// sanitizedHost resolves req's effective Host header value (req.Host takes
// precedence over req.URL.Host) and strips a default port (80 for http, 443
// for https) so the canonical "host" header matches what a well-behaved
// SigV4 client signs.
func sanitizedHost(req *http.Request) string {
	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}
	port := portOnly(host)
	if port != "" && isDefaultPort(req.URL.Scheme, port) {
		return stripPort(host)
	}
	return host
}

func stripPort(hostport string) string {
	before, _, ok := strings.Cut(hostport, ":")
	if !ok {
		return hostport
	}
	if before, _, ok := strings.Cut(hostport, "]"); ok {
		return strings.TrimPrefix(before, "[")
	}
	return before
}

func portOnly(hostport string) string {
	_, after, ok := strings.Cut(hostport, ":")
	if !ok {
		return ""
	}
	if _, after, ok := strings.Cut(hostport, "]:"); ok {
		return after
	}
	if strings.Contains(hostport, "]") {
		return ""
	}
	return after
}

func isDefaultPort(scheme, port string) bool {
	if port == "" {
		return true
	}
	lowerCaseScheme := strings.ToLower(scheme)
	return (lowerCaseScheme == "http" && port == "80") || (lowerCaseScheme == "https" && port == "443")
}

// getURIPath returns the escaped URI path component of u, preferring
// u.Opaque (set when the caller pre-escaped the path) over u.EscapedPath().
func getURIPath(u *url.URL) string {
	var uriPath string

	if len(u.Opaque) > 0 {
		const schemeSep, pathSep, queryStart = "//", "/", "?"

		opaque := u.Opaque
		if idx := strings.Index(opaque, queryStart); idx >= 0 {
			opaque = opaque[:idx]
		}
		if strings.Index(opaque, schemeSep) == 0 {
			opaque = opaque[len(schemeSep):]
		}
		if idx := strings.Index(opaque, pathSep); idx >= 0 {
			uriPath = opaque[idx:]
		}
	} else {
		uriPath = u.EscapedPath()
	}

	if len(uriPath) == 0 {
		uriPath = "/"
	}

	return uriPath
}
