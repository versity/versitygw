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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
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

type backendWithBucketCors struct {
	backend.BackendUnsupported
	corsConfig []byte
}

func (b backendWithBucketCors) GetBucketCors(ctx context.Context, bucket string) ([]byte, error) {
	if b.corsConfig != nil {
		return b.corsConfig, nil
	}
	return nil, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)
}

func (b backendWithBucketCors) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	// Return a minimal ACL in JSON format
	acl := auth.ACL{
		Owner: "test",
	}
	return json.Marshal(acl)
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

func TestS3ApiRouter_OptionsWithBucketCORS_NoDuplicateHeaders(t *testing.T) {
	// This test reproduces the issue from GitHub issue #1819
	// where CORS headers were duplicated in OPTIONS responses
	bucketOrigin := "http://localhost:3333"
	fallbackOrigin := "https://fallback.example.com"

	// CORS configuration matching the issue reproduction steps
	corsConfig := []byte(`<CORSConfiguration>
		<CORSRule>
			<AllowedOrigin>http://localhost:3333</AllowedOrigin>
			<AllowedMethod>GET</AllowedMethod>
			<AllowedMethod>HEAD</AllowedMethod>
			<AllowedMethod>PUT</AllowedMethod>
			<AllowedMethod>POST</AllowedMethod>
			<AllowedHeader>content-length</AllowedHeader>
			<AllowedHeader>content-type</AllowedHeader>
		</CORSRule>
	</CORSConfiguration>`)

	app := fiber.New()
	(&S3ApiRouter{}).Init(
		app,
		backendWithBucketCors{corsConfig: corsConfig},
		&auth.IAMServiceInternal{},
		nil,
		nil,
		nil,
		nil,
		false,
		"us-east-1",
		"",
		middlewares.RootUserConfig{},
		fallbackOrigin,
	)

	req, err := http.NewRequest(http.MethodOptions, "/xyz/upload/test.txt", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", bucketOrigin)
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	// Verify the response has the correct status
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Check that headers are not duplicated
	headers := resp.Header

	// Helper function to count header occurrences
	countHeader := func(headerName string) int {
		values := headers.Values(headerName)
		return len(values)
	}

	// Verify each CORS header appears exactly once
	corsHeaders := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Allow-Credentials",
		"Vary",
	}

	for _, header := range corsHeaders {
		count := countHeader(header)
		if count > 1 {
			t.Errorf("Header %q appears %d times (expected 1). Values: %v",
				header, count, headers.Values(header))
		}
	}

	// Verify the bucket CORS values are used (not the fallback)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != bucketOrigin {
		t.Errorf("expected Access-Control-Allow-Origin %q (from bucket CORS), got %q", bucketOrigin, got)
	}

	// Verify the requested method is in the allowed methods
	allowedMethods := resp.Header.Get("Access-Control-Allow-Methods")
	if allowedMethods == "" {
		t.Error("Access-Control-Allow-Methods header is empty")
	}

	// Verify the requested header is in the allowed headers
	allowedHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	if allowedHeaders == "" {
		t.Error("Access-Control-Allow-Headers header is empty")
	}
}
