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

package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// Proxy headers the client address can be read from when the operator opts in
// with the client-ip-header option.
const (
	ClientIPHeaderForwardedFor = "X-Forwarded-For"
	ClientIPHeaderRealIP       = "X-Real-Ip"
)

// NormalizeClientIPHeader validates a configured client IP header and returns
// its canonical spelling. An empty value means the option is disabled.
func NormalizeClientIPHeader(header string) (string, error) {
	trimmed := strings.TrimSpace(header)
	switch {
	case trimmed == "":
		return "", nil
	case strings.EqualFold(trimmed, ClientIPHeaderForwardedFor):
		return ClientIPHeaderForwardedFor, nil
	case strings.EqualFold(trimmed, ClientIPHeaderRealIP):
		return ClientIPHeaderRealIP, nil
	default:
		return "", fmt.Errorf("invalid client IP header %q: must be %q or %q",
			header, ClientIPHeaderForwardedFor, ClientIPHeaderRealIP)
	}
}

// ClientIP returns the address to record for a request. The client IP
// middleware stores the address resolved from the configured proxy header;
// without it this is the socket peer address from ctx.IP().
func ClientIP(ctx fiber.Ctx) string {
	if ip, ok := ContextKeyClientIP.Get(ctx).(string); ok && ip != "" {
		return ip
	}
	return ctx.IP()
}

// ClientIPFromHeader resolves the client address from header, falling back to
// the socket peer address when the header is missing, empty or not a valid IP.
//
// X-Forwarded-For is a comma-separated chain, oldest hop first: the leftmost
// entry is the original client, the rightmost the proxy that opened the
// connection to the gateway. A request forwarded through two proxies therefore
// keeps the client in the first entry. X-Real-Ip carries a single address.
//
// Enabling this trusts the whole header, so the gateway must only be reachable
// through the proxy, and the outermost proxy must not pass a client-supplied
// header through unchallenged.
func ClientIPFromHeader(ctx fiber.Ctx, header string) string {
	switch {
	case strings.EqualFold(strings.TrimSpace(header), ClientIPHeaderForwardedFor):
		if ip := firstForwardedFor(ctx.Get(ClientIPHeaderForwardedFor)); ip != "" {
			return ip
		}
	case strings.EqualFold(strings.TrimSpace(header), ClientIPHeaderRealIP):
		if ip := strings.TrimSpace(ctx.Get(ClientIPHeaderRealIP)); isIP(ip) {
			return ip
		}
	}
	return ctx.IP()
}

func firstForwardedFor(value string) string {
	first, _, _ := strings.Cut(value, ",")
	first = strings.TrimSpace(first)
	if isIP(first) {
		return first
	}
	return ""
}

func isIP(s string) bool {
	return s != "" && net.ParseIP(s) != nil
}
