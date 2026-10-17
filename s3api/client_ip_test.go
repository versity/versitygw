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

package s3api

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
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/utils"
)

// testConnPeer is the peer address fiber's app.Test serves every request from.
var testConnPeer = netip.MustParsePrefix("0.0.0.0/32")

// reportClientIP pins the peer address and returns the address the loggers
// would record for the request.
func reportClientIP(ctx fiber.Ctx) error {
	ctx.RequestCtx().SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345})
	return ctx.SendString(utils.ClientIP(ctx))
}

func TestS3ApiServerClientIPHeader(t *testing.T) {
	server, err := newTestS3ApiServer(
		WithQuiet(),
		WithClientIPHeader(utils.ClientIPHeaderRealIP),
		WithTrustedProxies(utils.TrustedProxies{Prefixes: []netip.Prefix{testConnPeer}}),
		WithRoute(http.MethodGet, "/client-ip", reportClientIP),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set(utils.ClientIPHeaderRealIP, "203.0.113.7")

	resp, err := server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", string(body))
}

func TestS3ApiServerClientIPHeaderDisabled(t *testing.T) {
	server, err := newTestS3ApiServer(
		WithQuiet(),
		WithRoute(http.MethodGet, "/client-ip", reportClientIP),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set(utils.ClientIPHeaderRealIP, "203.0.113.7")

	resp, err := server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", string(body))
}

// TestS3ApiServerClientIPHeaderUnlistedPeer checks that a peer outside
// trusted-proxies cannot choose the logged address.
func TestS3ApiServerClientIPHeaderUnlistedPeer(t *testing.T) {
	server, err := newTestS3ApiServer(
		WithQuiet(),
		WithClientIPHeader(utils.ClientIPHeaderForwardedFor),
		WithTrustedProxies(utils.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}),
		WithRoute(http.MethodGet, "/client-ip", reportClientIP),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set(utils.ClientIPHeaderForwardedFor, "6.6.6.6")

	resp, err := server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0", string(body))
}

func TestS3ApiServerRejectsUnknownClientIPHeader(t *testing.T) {
	_, err := newTestS3ApiServer(
		WithQuiet(),
		WithClientIPHeader("Forwarded"),
		WithTrustedProxies(utils.TrustedProxies{Prefixes: []netip.Prefix{testConnPeer}}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client IP header")
}

func TestS3AdminServerClientIPHeader(t *testing.T) {
	server := NewAdminServer(backend.BackendUnsupported{}, testAdminRoot, "us-east-1", testAdminIAM(), nil, controllers.S3ApiController{},
		WithAdminConcurrencyLimiter(10, 10),
		WithAdminQuiet(),
		WithAdminClientIPHeader(utils.ClientIPHeaderForwardedFor),
		WithAdminTrustedProxies(utils.TrustedProxies{Prefixes: []netip.Prefix{
			testConnPeer,
			netip.MustParsePrefix("198.51.100.9/32"),
		}}),
		WithAdminRoute(http.MethodGet, "/client-ip", reportClientIP),
	)

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.Header.Set(utils.ClientIPHeaderForwardedFor, "203.0.113.7, 198.51.100.9")

	resp, err := server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", string(body))
}

// TestS3AdminServerRejectsUnknownClientIPHeader has no error-returning
// constructor to report the invalid value, so it must surface at startup.
func TestS3AdminServerRejectsUnknownClientIPHeader(t *testing.T) {
	server := NewAdminServer(backend.BackendUnsupported{}, testAdminRoot, "us-east-1", testAdminIAM(), nil, controllers.S3ApiController{},
		WithAdminConcurrencyLimiter(10, 10),
		WithAdminQuiet(),
		WithAdminClientIPHeader("Forwarded"),
	)

	err := server.ServeMultiPort([]string{"127.0.0.1:0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client IP header")
}
