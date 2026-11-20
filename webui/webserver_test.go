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

package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/internal/clientip"
)

func TestNewServerRejectsUnknownClientIPHeader(t *testing.T) {
	_, err := NewServer(&ServerConfig{}, WithQuiet(), WithClientIPHeader("Forwarded"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client IP header")
}

func TestNewServerAcceptsKnownClientIPHeader(t *testing.T) {
	_, err := NewServer(&ServerConfig{},
		WithQuiet(),
		WithClientIPHeader(clientip.ClientIPHeaderRealIP),
		WithTrustedProxies(clientip.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}}),
	)
	require.NoError(t, err)
}

// TestSetupMiddlewareResolvesClientIP checks that the standalone WebUI server
// installs the client IP middleware, so its request log records the address
// from the trusted proxy header rather than the socket peer.
func TestSetupMiddlewareResolvesClientIP(t *testing.T) {
	server := &Server{
		app:            fiber.New(),
		quiet:          true,
		clientIPHeader: clientip.ClientIPHeaderForwardedFor,
		trustedProxies: clientip.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}},
	}
	server.setupMiddleware()
	server.app.Get("/client-ip", func(ctx fiber.Ctx) error {
		return ctx.SendString(clientip.ClientIP(ctx))
	})

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set(clientip.ClientIPHeaderForwardedFor, "203.0.113.7")

	resp, err := server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", string(body))
}
