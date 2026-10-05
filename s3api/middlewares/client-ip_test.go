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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/s3api/utils"
)

const clientIPSocketAddr = "192.0.2.1"

// clientIPRequest runs one request through a fiber app whose peer address is
// pinned, optionally with the client IP middleware configured, and returns the
// address the loggers would record.
func clientIPRequest(t *testing.T, trustedHeader, header, value string, setHeader bool) string {
	t.Helper()

	app := fiber.New()
	// app.Test serves over a placeholder connection; pin the peer address
	// before the client IP middleware reads it.
	app.Use("*", func(ctx fiber.Ctx) error {
		ctx.RequestCtx().SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP(clientIPSocketAddr), Port: 12345})
		return ctx.Next()
	})
	if trustedHeader != "" {
		app.Use("*", ClientIP(trustedHeader))
	}
	app.Get("/", func(ctx fiber.Ctx) error {
		return ctx.SendString(utils.ClientIP(ctx))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if setHeader {
		req.Header.Set(header, value)
	}

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name          string
		trustedHeader string
		header        string
		value         string
		setHeader     bool
		want          string
	}{
		{
			name:          "x-real-ip trusted",
			trustedHeader: "X-Real-Ip",
			header:        "X-Real-Ip",
			value:         "203.0.113.7",
			setHeader:     true,
			want:          "203.0.113.7",
		},
		{
			name:          "x-real-ip ipv6",
			trustedHeader: "X-Real-Ip",
			header:        "X-Real-Ip",
			value:         "2001:db8::1",
			setHeader:     true,
			want:          "2001:db8::1",
		},
		{
			name:          "x-forwarded-for trusted",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			value:         "203.0.113.7",
			setHeader:     true,
			want:          "203.0.113.7",
		},
		{
			name:          "x-forwarded-for two proxies uses the client",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			value:         "203.0.113.7, 198.51.100.9",
			setHeader:     true,
			want:          "203.0.113.7",
		},
		{
			name:          "x-forwarded-for two proxies without spaces",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			value:         "203.0.113.7,198.51.100.9",
			setHeader:     true,
			want:          "203.0.113.7",
		},
		{
			name:          "x-forwarded-for ipv6 client",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			value:         "2001:db8::1, 198.51.100.9",
			setHeader:     true,
			want:          "2001:db8::1",
		},
		{
			name:          "trusted header name is case insensitive",
			trustedHeader: "x-forwarded-for",
			header:        "X-Forwarded-For",
			value:         "203.0.113.7",
			setHeader:     true,
			want:          "203.0.113.7",
		},
		{
			name:          "x-forwarded-for absent falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-forwarded-for empty falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			setHeader:     true,
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-forwarded-for malformed falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			value:         "unknown",
			setHeader:     true,
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-forwarded-for malformed client hop falls back to the socket address",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Forwarded-For",
			value:         "unknown, 198.51.100.9",
			setHeader:     true,
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip absent falls back to the socket address",
			trustedHeader: "X-Real-Ip",
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip empty falls back to the socket address",
			trustedHeader: "X-Real-Ip",
			header:        "X-Real-Ip",
			setHeader:     true,
			want:          clientIPSocketAddr,
		},
		{
			name:          "x-real-ip malformed falls back to the socket address",
			trustedHeader: "X-Real-Ip",
			header:        "X-Real-Ip",
			value:         "203.0.113.7:8080",
			setHeader:     true,
			want:          clientIPSocketAddr,
		},
		{
			name:          "the header that is not trusted is ignored",
			trustedHeader: "X-Forwarded-For",
			header:        "X-Real-Ip",
			value:         "203.0.113.7",
			setHeader:     true,
			want:          clientIPSocketAddr,
		},
		{
			name:      "no header trusted keeps the socket address",
			header:    "X-Real-Ip",
			value:     "203.0.113.7",
			setHeader: true,
			want:      clientIPSocketAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientIPRequest(t, tt.trustedHeader, tt.header, tt.value, tt.setHeader)
			assert.Equal(t, tt.want, got)
		})
	}
}
