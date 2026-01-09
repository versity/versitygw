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
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3err"
)

type backendWithCorsOnly struct {
	backend.BackendUnsupported
}

func (b backendWithCorsOnly) GetBucketCors(ctx context.Context, bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)
}

func TestS3ApiRouter_ListBuckets_DefaultCORSAllowOrigin(t *testing.T) {
	origin := "https://example.com"

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backend.BackendUnsupported{},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		origin,
	)

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got == "" {
		t.Fatalf("expected Access-Control-Expose-Headers to be set")
	}
}

func TestS3ApiRouter_ListBuckets_OptionsPreflight_DefaultCORS(t *testing.T) {
	origin := "https://example.com"

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backend.BackendUnsupported{},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		origin,
	)

	req, err := http.NewRequest(http.MethodOptions, "/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", "https://client.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "authorization")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
}

func TestS3ApiRouter_PutBucketTagging_ErrorStillIncludesFallbackCORS(t *testing.T) {
	origin := "http://127.0.0.1:9090"

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backendWithCorsOnly{},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		origin,
	)

	req, err := http.NewRequest(http.MethodPut, "/testing?tagging", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", origin)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
}

func TestS3ApiRouter_PutObjectTagging_ErrorStillIncludesFallbackCORS(t *testing.T) {
	origin := "http://127.0.0.1:9090"

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backendWithCorsOnly{},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		origin,
	)

	req, err := http.NewRequest(http.MethodPut, "/testing/myobj?tagging", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", origin)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
}

func TestS3ApiRouter_CopyObject_ErrorStillIncludesFallbackCORS(t *testing.T) {
	origin := "http://127.0.0.1:9090"

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backendWithCorsOnly{},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		origin,
	)

	req, err := http.NewRequest(http.MethodPut, "/testing/myobj", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("X-Amz-Copy-Source", "srcbucket/srckey")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
}

func TestS3ApiRouter_PutObject_ErrorStillIncludesFallbackCORS(t *testing.T) {
	origin := "http://127.0.0.1:9090"

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backendWithCorsOnly{},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		origin,
	)

	req, err := http.NewRequest(http.MethodPut, "/testing/myobj", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", origin)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
}
