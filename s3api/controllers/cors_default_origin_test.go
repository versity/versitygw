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

package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3err"
)

func TestApplyBucketCORS_FallbackOrigin_NoBucketCors_NoRequestOrigin(t *testing.T) {
	origin := "https://example.com"

	mockedBackend := &BackendMock{
		GetBucketCorsFunc: func(ctx context.Context, bucket string) ([]byte, error) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)
		},
	}

	app := fiber.New()
	app.Get("/:bucket/test",
		middlewares.ApplyBucketCORS(mockedBackend, origin),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)

	req, err := http.NewRequest(http.MethodGet, "/mybucket/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin to be set to fallback, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "ETag" {
		t.Fatalf("expected Access-Control-Expose-Headers to include ETag, got %q", got)
	}
}

func TestApplyBucketCORS_FallbackOrigin_NotAppliedWhenBucketCorsExists(t *testing.T) {
	origin := "https://example.com"

	mockedBackend := &BackendMock{
		GetBucketCorsFunc: func(ctx context.Context, bucket string) ([]byte, error) {
			return []byte("not-parsed"), nil
		},
	}

	app := fiber.New()
	app.Get("/:bucket/test",
		middlewares.ApplyBucketCORS(mockedBackend, origin),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)

	req, err := http.NewRequest(http.MethodGet, "/mybucket/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no Access-Control-Allow-Origin when bucket CORS exists, got %q", got)
	}
}
