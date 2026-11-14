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

	"github.com/versity/versitygw/cumiddleware"
	"github.com/versity/versitygw/rdma/rcdial"
)

// TestV3RegistrationSmoke proves the wiring shape the registration
// commit installs: the middleware stores a valid token where the
// adapter's descriptor lookup finds it, so a dispatched request
// reaches the adapter rather than the plain HTTP path. It exercises
// the real middleware and the real lookup the backend adapter uses,
// without starting the gateway itself (main's runGateway needs a
// live backend and IAM).
func TestV3RegistrationSmoke(t *testing.T) {
	app := fiber.New()
	app.Use(cumiddleware.RDMAv3Middleware)

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
		t.Fatal("request did not reach the handler with a descriptor: dispatch broken")
	}
	if got.Length != 1<<20 {
		t.Errorf("token length = %d, want %d", got.Length, 1<<20)
	}
	if got.ListenPort != 18181 {
		t.Errorf("listen port = %d, want 18181", got.ListenPort)
	}
}

// TestV3RegistrationSmokePlainBypasses asserts the same wiring leaves
// descriptor-free requests untouched, the property the registration
// relies on for zero impact on ordinary traffic.
func TestV3RegistrationSmokePlainBypasses(t *testing.T) {
	app := fiber.New()
	app.Use(cumiddleware.RDMAv3Middleware)
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

var _ fasthttp.RequestCtx
