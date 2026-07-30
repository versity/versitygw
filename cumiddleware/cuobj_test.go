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

package cumiddleware

// Protocol-level tests for the cuObject RDMA header parsing middleware.
// These exercise the wire-format contract without requiring any RDMA
// hardware: the middleware only ever inspects HTTP headers and stashes
// parsed values on the request context.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

// tokenWithBufSize constructs a valid cuObj RDMA token per the
// HeaderRDMAToken wire format documented next to its definition.
func tokenWithBufSize(baseAddr uint64, bufSize uint32) string {
	return hex64(baseAddr) + ":" + hex32(bufSize) + ":01020304:0102:010203:1:0102030405060708090a0b0c0d0e0f10"
}

func hex64(v uint64) string {
	s := strconv.FormatUint(v, 16)
	for len(s) < 16 {
		s = "0" + s
	}
	return s
}

func hex32(v uint32) string {
	s := strconv.FormatUint(uint64(v), 16)
	for len(s) < 8 {
		s = "0" + s
	}
	return s
}

func newTestApp(t *testing.T) (*fiber.App, chan bool) {
	t.Helper()
	reached := make(chan bool, 1)
	app := fiber.New()
	app.Use("*", CuObjMiddleware)
	app.Post("/", func(ctx fiber.Ctx) error {
		reached <- true
		return ctx.SendStatus(http.StatusOK)
	})
	return app, reached
}

func TestCuObjMiddlewareNoHeadersPassesThrough(t *testing.T) {
	app, _ := newTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCuObjMiddlewareLegacyHeaders(t *testing.T) {
	app := fiber.New()
	app.Use("*", CuObjMiddleware)
	app.Post("/", func(ctx fiber.Ctx) error {
		rctx := ctx.RequestCtx()
		descr, ok := GetRDMADescriptor(rctx)
		assert.True(t, ok)
		assert.Equal(t, "deadbeef", descr)
		size, ok := GetRDMASize(rctx)
		assert.True(t, ok)
		assert.Equal(t, int64(4096), size)
		assert.Equal(t, uint64(4660), GetRDMARemoteStart(rctx))
		return ctx.SendStatus(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(HeaderRDMADescr, "deadbeef")
	req.Header.Set(HeaderRDMASize, "4096")
	req.Header.Set(HeaderRDMARemoteAddr, "4660")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCuObjMiddlewareTokenWithContentLength(t *testing.T) {
	app := fiber.New()
	app.Use("*", CuObjMiddleware)
	app.Post("/", func(ctx fiber.Ctx) error {
		rctx := ctx.RequestCtx()
		descr, ok := GetRDMADescriptor(rctx)
		assert.True(t, ok)
		token := tokenWithBufSize(0x1122334455667788, 0x2000)
		assert.Equal(t, token, descr)
		size, ok := GetRDMASize(rctx)
		assert.True(t, ok)
		assert.Equal(t, int64(1234), size) // from Content-Length, not the token buffer size
		assert.Equal(t, uint64(0x1122334455667788), GetRDMARemoteStart(rctx))
		return ctx.SendStatus(http.StatusOK)
	})

	token := tokenWithBufSize(0x1122334455667788, 0x2000)
	body := make([]byte, 1234)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(HeaderRDMAToken, token)
	req.ContentLength = int64(len(body))
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestCuObjMiddlewareTokenZeroBodyFallsBackToTokenSize covers a genuine RDMA
// control request that carries no HTTP body at all (Content-Length 0/unset):
// the size must fall back to the token's own registered-buffer-size field
// instead of leaving the backend with no usable size.
func TestCuObjMiddlewareTokenZeroBodyFallsBackToTokenSize(t *testing.T) {
	app := fiber.New()
	app.Use("*", CuObjMiddleware)
	app.Post("/", func(ctx fiber.Ctx) error {
		rctx := ctx.RequestCtx()
		size, ok := GetRDMASize(rctx)
		assert.True(t, ok)
		assert.Equal(t, int64(0x2000), size)
		return ctx.SendStatus(http.StatusOK)
	})

	token := tokenWithBufSize(0x1122334455667788, 0x2000)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(HeaderRDMAToken, token)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCuObjMiddlewareMalformedTokenRejected(t *testing.T) {
	app, reached := newTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(HeaderRDMAToken, "not-a-valid-token")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	select {
	case <-reached:
		t.Fatal("handler should not have been reached for a malformed token")
	default:
	}
}

func TestSetRDMAReplyHeader(t *testing.T) {
	app := fiber.New()
	app.Post("/", func(ctx fiber.Ctx) error {
		SetRDMAReplyHeader(ctx.RequestCtx(), http.StatusOK, 65536)
		return ctx.SendStatus(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, "200", resp.Header.Get(HeaderRDMAReply))
	assert.Equal(t, "65536", resp.Header.Get(HeaderRDMABytesTransferred))
}

func TestSetRDMAReplyHeaderNoopForNonFasthttpContext(t *testing.T) {
	// Must not panic when called with a plain context.Context, e.g. from a
	// unit test that injects RDMA values via InjectRDMAContext without an
	// HTTP layer.
	ctx := InjectRDMAContext(t.Context(), "descr", 10, 0)
	SetRDMAReplyHeader(ctx, http.StatusOK, 10)
}
