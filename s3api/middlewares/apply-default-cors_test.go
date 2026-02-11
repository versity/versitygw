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

	"github.com/gofiber/fiber/v3"
)

func TestApplyDefaultCORS_AddsHeaderWhenOriginSet(t *testing.T) {
	origin := "https://example.com"

	app := fiber.New()
	app.Get("/admin", ApplyDefaultCORS(origin), func(c fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	req, err := http.NewRequest(http.MethodGet, "/admin", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected fallback origin header, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "ETag" {
		t.Fatalf("expected expose headers to include ETag, got %q", got)
	}
}

func TestApplyDefaultCORS_DoesNotOverrideExistingHeader(t *testing.T) {
	origin := "https://example.com"

	app := fiber.New()
	app.Get("/admin", func(c fiber.Ctx) error {
		c.Response().Header.Add("Access-Control-Allow-Origin", "https://already-set.com")
		return nil
	}, ApplyDefaultCORS(origin), func(c fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	req, err := http.NewRequest(http.MethodGet, "/admin", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://already-set.com" {
		t.Fatalf("expected existing header to remain, got %q", got)
	}
}
