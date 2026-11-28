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

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/versity/versitygw/s3api"

	"github.com/versity/versitygw/cumiddleware"
	"github.com/versity/versitygw/rdma/rcdial"
)

// applyOptions runs the production option list against a fresh app
// through the server's own mount inspection, so the test observes
// the wiring the gateway actually installs.
func applyOptions(t *testing.T, app *fiber.App, opts []s3api.Option) {
	t.Helper()
	s := &s3api.S3ApiServer{}
	for _, opt := range opts {
		opt(s)
	}
	for _, mount := range s.MiddlewareMounts() {
		app.Use(mount.Prefix, mount.Handler)
	}
}

// TestV3RegistrationViaProductionOptions proves the production
// option assembly mounts the v3 middleware: the options the gateway
// builds are applied to a fiber app, and a valid token on an object
// request reaches the handler with the descriptor the backend
// adapter looks up.
func TestV3RegistrationViaProductionOptions(t *testing.T) {
	app := fiber.New()
	applyOptions(t, app, buildV3Options(""))

	var got rcdial.Token
	var dispatched bool
	app.Get("/bucket/*", func(c fiber.Ctx) error {
		tok, ok := cumiddleware.GetV3Descriptor(c.RequestCtx())
		got, dispatched = tok, ok
		return c.SendString("ok")
	})

	const token = "00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:0000000000100000"
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	req.Header.Set("x-amz-rc-rdma-token", token)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if !dispatched {
		t.Fatal("request did not reach the handler with a descriptor: production options did not mount the middleware")
	}
	if got.Length != 1<<20 {
		t.Errorf("token length = %d, want %d", got.Length, 1<<20)
	}
	if got.ListenPort != 18181 {
		t.Errorf("listen port = %d, want 18181", got.ListenPort)
	}
}

// TestV3RegistrationPlainBypasses asserts the same production wiring
// leaves descriptor-free requests untouched, the property the
// registration relies on for zero impact on ordinary traffic.
func TestV3RegistrationPlainBypasses(t *testing.T) {
	app := fiber.New()
	applyOptions(t, app, buildV3Options(""))
	app.Get("/bucket/*", func(c fiber.Ctx) error {
		if _, ok := cumiddleware.GetV3Descriptor(c.RequestCtx()); ok {
			t.Error("descriptor stored on a plain request")
		}
		return c.SendString("ok")
	})
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("plain request status = %d", resp.StatusCode)
	}
}

// TestV3RegistrationVirtualDomain passes the configured virtual
// domain through the production assembly so virtual-hosted object
// requests are recognized.
func TestV3RegistrationVirtualDomain(t *testing.T) {
	app := fiber.New()
	applyOptions(t, app, buildV3Options("s3.example.com"))
	var dispatched bool
	app.Get("/*", func(c fiber.Ctx) error {
		_, dispatched = cumiddleware.GetV3Descriptor(c.RequestCtx())
		return c.SendString("ok")
	})

	const token = "00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:0000000000100000"
	req := httptest.NewRequest(http.MethodGet, "http://mybucket.s3.example.com/key", nil)
	req.Header.Set("x-amz-rc-rdma-token", token)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if !dispatched {
		t.Error("virtual-hosted object request bypassed the descriptor")
	}
}

var _ fasthttp.RequestCtx
