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
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

type backendWithGetBucketCors struct {
	backend.BackendUnsupported
	getBucketCors func(ctx context.Context, bucket string) ([]byte, error)
}

func (b backendWithGetBucketCors) GetBucketCors(ctx context.Context, bucket string) ([]byte, error) {
	return b.getBucketCors(ctx, bucket)
}

func TestApplyBucketCORSPreflightFallback_NoBucketCors_Responds204(t *testing.T) {
	be := backendWithGetBucketCors{
		getBucketCors: func(ctx context.Context, bucket string) ([]byte, error) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)
		},
	}

	app := fiber.New()
	app.Options("/:bucket",
		ApplyBucketCORSPreflightFallback(be, "https://example.com"),
		func(c *fiber.Ctx) error {
			// Should not be reached if fallback triggers
			return c.SendStatus(http.StatusTeapot)
		},
	)

	req, err := http.NewRequest(http.MethodOptions, "/testing", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://request-origin.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("expected allow origin fallback, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET" {
		t.Fatalf("expected allow methods to mirror request, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "content-type" {
		t.Fatalf("expected allow headers to mirror request, got %q", got)
	}
}

func TestApplyBucketCORSPreflightFallback_NoSuchBucket_Responds204(t *testing.T) {
	be := backendWithGetBucketCors{
		getBucketCors: func(ctx context.Context, bucket string) ([]byte, error) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
		},
	}

	app := fiber.New()
	app.Options("/:bucket",
		ApplyBucketCORSPreflightFallback(be, "https://example.com"),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusTeapot)
		},
	)

	req, err := http.NewRequest(http.MethodOptions, "/testing", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://request-origin.example")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("expected allow origin fallback, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "PUT" {
		t.Fatalf("expected allow methods to mirror request, got %q", got)
	}
}

func TestApplyBucketCORSPreflightFallback_BucketHasCors_CallsNext(t *testing.T) {
	be := backendWithGetBucketCors{
		getBucketCors: func(ctx context.Context, bucket string) ([]byte, error) {
			return []byte("dummy"), nil
		},
	}

	app := fiber.New()
	app.Options("/:bucket",
		ApplyBucketCORSPreflightFallback(be, "https://example.com"),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)

	req, err := http.NewRequest(http.MethodOptions, "/testing", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 from next handler, got %d", resp.StatusCode)
	}
}
