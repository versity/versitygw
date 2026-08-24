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

package iammiddleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

const testOrigin = "https://webui.example.com"

func TestCORSPreflightMirrorsRequest(t *testing.T) {
	resp := corsRequest(t, http.MethodOptions, map[string]string{
		"Origin":                         "https://some-other.example",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "authorization,x-amz-date,content-type",
	})

	// IAM answers a preflight 200 with an empty body, not 204.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("expected empty preflight body, got %q", body)
	}

	// The configured origin is returned, not the one the browser sent.
	assertHeader(t, resp, "Access-Control-Allow-Origin", testOrigin)
	assertHeader(t, resp, "Access-Control-Allow-Methods", "POST")
	assertHeader(t, resp, "Access-Control-Allow-Headers", "authorization,x-amz-date,content-type")
	assertHeader(t, resp, "Access-Control-Expose-Headers", corsExposeHeaders)
	assertHeader(t, resp, "Access-Control-Max-Age", corsMaxAge)
	assertHeader(t, resp, "Vary", "Origin")
}

// A preflight without Access-Control-Request-Method is still short-circuited,
// it just carries no allow-methods.
func TestCORSPreflightWithoutRequestMethod(t *testing.T) {
	resp := corsRequest(t, http.MethodOptions, map[string]string{
		"Origin": testOrigin,
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	assertHeader(t, resp, "Access-Control-Allow-Origin", testOrigin)
	assertHeader(t, resp, "Access-Control-Max-Age", corsMaxAge)
	assertNoHeader(t, resp, "Access-Control-Allow-Methods")
	assertNoHeader(t, resp, "Access-Control-Allow-Headers")
}

func TestCORSActualRequestOmitsPreflightHeaders(t *testing.T) {
	resp := corsRequest(t, http.MethodPost, map[string]string{
		"Origin": testOrigin,
	})

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected the handler to run, got status %d", resp.StatusCode)
	}
	assertHeader(t, resp, "Access-Control-Allow-Origin", testOrigin)
	assertHeader(t, resp, "Access-Control-Expose-Headers", corsExposeHeaders)
	assertHeader(t, resp, "Vary", "Origin")
	// Preflight-only headers must not leak onto an actual response.
	assertNoHeader(t, resp, "Access-Control-Allow-Methods")
	assertNoHeader(t, resp, "Access-Control-Allow-Headers")
	assertNoHeader(t, resp, "Access-Control-Max-Age")
}

// Without an Origin the request is not a browser call: no CORS headers.
func TestCORSWithoutOriginIsUntouched(t *testing.T) {
	resp := corsRequest(t, http.MethodPost, nil)

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected the handler to run, got status %d", resp.StatusCode)
	}
	for _, hdr := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Expose-Headers",
		"Access-Control-Max-Age",
		"Vary",
	} {
		assertNoHeader(t, resp, hdr)
	}
}

// An OPTIONS without an Origin is not a preflight and must reach the router.
func TestCORSOptionsWithoutOriginIsRouted(t *testing.T) {
	resp := corsRequest(t, http.MethodOptions, nil)

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected the handler to run, got status %d", resp.StatusCode)
	}
	assertNoHeader(t, resp, "Access-Control-Allow-Origin")
}

func corsRequest(t *testing.T, method string, headers map[string]string) *http.Response {
	t.Helper()

	app := fiber.New()
	app.Use("*", CORS(testOrigin))
	app.All("/*", func(ctx fiber.Ctx) error {
		return ctx.SendStatus(http.StatusTeapot)
	})

	req := httptest.NewRequest(method, "/", nil)
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	return resp
}

func assertHeader(t *testing.T, resp *http.Response, key, want string) {
	t.Helper()
	if got := resp.Header.Get(key); got != want {
		t.Errorf("%s: expected %q, got %q", key, want, got)
	}
}

func assertNoHeader(t *testing.T, resp *http.Response, key string) {
	t.Helper()
	if got := resp.Header.Get(key); got != "" {
		t.Errorf("%s: expected absent, got %q", key, got)
	}
}
