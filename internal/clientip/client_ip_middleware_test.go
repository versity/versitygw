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

package clientip

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The socket peer in every case below; the trusted lists decide whether it is
// allowed to speak for the client.
const clientIPSocketAddr = "198.51.100.9"

var trustedSocketPeer = netip.MustParsePrefix("198.51.100.9/32")

// clientIPRequest runs one request through a fiber app whose peer address is
// pinned, with the client IP middleware configured for trustedHeader, and
// returns the address the loggers would record.
func clientIPRequest(t *testing.T, trustedHeader string, trusted []netip.Prefix, headers func(*http.Request)) string {
	t.Helper()

	app := fiber.New()
	// app.Test serves over a placeholder connection; pin the peer address
	// before the client IP middleware reads it.
	app.Use("*", func(ctx fiber.Ctx) error {
		ctx.RequestCtx().SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP(clientIPSocketAddr), Port: 12345})
		return ctx.Next()
	})
	if trustedHeader != "" {
		app.Use("*", Middleware(trustedHeader, TrustedProxies{Prefixes: trusted}))
	}
	app.Get("/", func(ctx fiber.Ctx) error {
		return ctx.SendString(ClientIP(ctx))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if headers != nil {
		headers(req)
	}

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// header sets one header value on the request.
func header(name, value string) func(*http.Request) {
	return func(req *http.Request) { req.Header.Set(name, value) }
}

// headerLines adds the values as separate header lines, as a proxy that adds
// its own X-Forwarded-For line rather than appending to the existing one does.
func headerLines(name string, values ...string) func(*http.Request) {
	return func(req *http.Request) {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
}

func TestClientIPMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		trustedHeader string
		trusted       []netip.Prefix
		headers       func(*http.Request)
		want          string
	}{
		{
			name:          "x-real-ip from a trusted proxy",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Real-Ip", "203.0.113.7"),
			want:          "203.0.113.7",
		},
		{
			name:          "x-real-ip ipv6 is normalized",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Real-Ip", "2001:DB8::1"),
			want:          "2001:db8::1",
		},
		{
			name:          "x-forwarded-for single hop from a trusted proxy",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "203.0.113.7"),
			want:          "203.0.113.7",
		},
		{
			// The chain is walked right to left, skipping the trusted
			// proxies that appended to it, so two proxies listed in
			// trusted-proxies still resolve the original client.
			name:          "two trusted proxies resolve the client",
			trustedHeader: "X-Forwarded-For",
			trusted: []netip.Prefix{
				trustedSocketPeer,
				netip.MustParsePrefix("203.0.113.9/32"),
			},
			headers: header("X-Forwarded-For", "203.0.113.7, 203.0.113.9"),
			want:    "203.0.113.7",
		},
		{
			name:          "two trusted proxies with cidr",
			trustedHeader: "X-Forwarded-For",
			trusted: []netip.Prefix{
				netip.MustParsePrefix("198.51.100.0/24"),
				netip.MustParsePrefix("203.0.113.0/24"),
			},
			headers: header("X-Forwarded-For", "192.0.2.7, 203.0.113.9"),
			want:    "192.0.2.7",
		},
		{
			// The blocking review: the client wrote 6.6.6.6 and nginx
			// appended the real client with
			// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for.
			name:          "a forged leftmost entry is never reached",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "6.6.6.6, 203.0.113.7"),
			want:          "203.0.113.7",
		},
		{
			// Azure Application Gateway writes ip:port entries.
			name:          "ip:port entries are accepted",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "203.0.113.7:1234, 198.51.100.9"),
			want:          "203.0.113.7",
		},
		{
			name:          "bracketed ipv6 with a port is accepted",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "[2001:db8::1]:1234, 198.51.100.9"),
			want:          "2001:db8::1",
		},
		{
			name:          "ipv6 client behind a trusted proxy",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "2001:db8::1, 198.51.100.9"),
			want:          "2001:db8::1",
		},
		{
			// A proxy that adds its own line instead of appending: the
			// client's line is first, the proxy's appended line last.
			name:          "separate header lines are walked last first",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       headerLines("X-Forwarded-For", "6.6.6.6", "203.0.113.7"),
			want:          "203.0.113.7",
		},
		{
			// An untrusted peer cannot choose the logged address.
			name:          "header from an unlisted peer is ignored",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			headers:       header("X-Forwarded-For", "6.6.6.6"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip from an unlisted peer is ignored",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			headers:       header("X-Real-Ip", "6.6.6.6"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "no trusted proxies ignores the header",
			trustedHeader: "X-Forwarded-For",
			headers:       header("X-Forwarded-For", "203.0.113.7"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "the header that is not trusted is ignored",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Real-Ip", "203.0.113.7"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-forwarded-for absent falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-forwarded-for empty falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", ""),
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-forwarded-for malformed falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "unknown"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "a malformed hop stops the walk",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "unknown, 198.51.100.9"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip absent falls back to the socket address",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip empty falls back to the socket address",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Real-Ip", ""),
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip malformed falls back to the socket address",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Real-Ip", "unknown"),
			want:          clientIPSocketAddr,
		},
		{
			// A zone is free text and the access log is space-delimited, so a
			// zoned address would shift every field after RemoteIP.
			name:          "an ipv6 zone is rejected",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "::1%a b, 198.51.100.9"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "an ipv6 zone in a bracketed address is rejected",
			trustedHeader: "X-Forwarded-For",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Forwarded-For", "[fe80::1%a b]:80, 198.51.100.9"),
			want:          clientIPSocketAddr,
		},
		{
			name:          "an ipv6 zone in x-real-ip is rejected",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       header("X-Real-Ip", "::1%x"),
			want:          clientIPSocketAddr,
		},
		{
			// A proxy that adds its own line rather than replacing the
			// client's leaves the client's line first, so the last line is
			// the one the trusted proxy wrote.
			name:          "x-real-ip takes the last header line",
			trustedHeader: "X-Real-Ip",
			trusted:       []netip.Prefix{trustedSocketPeer},
			headers:       headerLines("X-Real-Ip", "6.6.6.6", "203.0.113.7"),
			want:          "203.0.113.7",
		},
		{
			// With every hop listed as a trusted proxy there is no untrusted
			// address to stop at, so the leftmost hop is logged, as nginx's
			// real_ip_recursive does.
			name:          "all hops trusted returns the leftmost hop",
			trustedHeader: "X-Forwarded-For",
			trusted: []netip.Prefix{
				trustedSocketPeer,
				netip.MustParsePrefix("203.0.113.9/32"),
				netip.MustParsePrefix("203.0.113.10/32"),
			},
			headers: header("X-Forwarded-For", "203.0.113.10, 203.0.113.9"),
			want:    "203.0.113.10",
		},
		{
			name:    "no header configured keeps the socket address",
			headers: header("X-Real-Ip", "203.0.113.7"),
			want:    clientIPSocketAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientIPRequest(t, tt.trustedHeader, tt.trusted, tt.headers)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestClientIPMiddlewareUnixPeer covers a listener bound to a unix socket path:
// fasthttp reports the peer as 0.0.0.0, so no listed proxy address matches it
// and the peer is trusted only through the explicit "unix" trusted-proxies entry.
func TestClientIPMiddlewareUnixPeer(t *testing.T) {
	request := func(t *testing.T, trusted TrustedProxies) string {
		t.Helper()

		app := fiber.New()
		app.Use("*", func(ctx fiber.Ctx) error {
			ctx.RequestCtx().SetRemoteAddr(&net.UnixAddr{Name: "/run/versitygw.sock", Net: "unix"})
			return ctx.Next()
		})
		app.Use("*", Middleware("X-Forwarded-For", trusted))
		app.Get("/", func(ctx fiber.Ctx) error {
			return ctx.SendString(ClientIP(ctx))
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.7")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(body)
	}

	t.Run("unix entry trusts the peer", func(t *testing.T) {
		assert.Equal(t, "203.0.113.7", request(t, TrustedProxies{Unix: true}))
	})
	t.Run("without the unix entry the header is ignored", func(t *testing.T) {
		// ctx.IP() is 0.0.0.0 for a non-TCP peer; that is what gets logged.
		assert.Equal(t, "0.0.0.0", request(t, TrustedProxies{Prefixes: []netip.Prefix{trustedSocketPeer}}))
	})
}
