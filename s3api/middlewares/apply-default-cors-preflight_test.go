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
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestApplyDefaultCORSPreflight_OptionsSetsPreflightHeaders(t *testing.T) {
	origin := "https://example.com"

	app := fiber.New()
	app.Options("/admin",
		ApplyDefaultCORSPreflight(origin),
		ApplyDefaultCORS(origin),
		func(c *fiber.Ctx) error { return nil },
	)

	req, err := http.NewRequest(http.MethodOptions, "/admin", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://request-origin.example")
	req.Header.Set("Access-Control-Request-Method", "PATCH")
	req.Header.Set("Access-Control-Request-Headers", "content-type,authorization")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected allow origin fallback, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "PATCH" {
		t.Fatalf("expected allow methods to mirror request, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "content-type,authorization" {
		t.Fatalf("expected allow headers to mirror request, got %q", got)
	}
}
