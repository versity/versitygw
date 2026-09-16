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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/middlewares"
)

func TestAdminPathPrefix(t *testing.T) {
	servers := []struct {
		name   string
		newApp func(t *testing.T, prefix string) *fiber.App
	}{
		{name: "standalone admin server", newApp: newTestAdminApp},
		{name: "admin on s3 server", newApp: newTestS3AdminApp},
	}

	tests := []struct {
		name    string
		prefix  string
		path    string
		handled bool
	}{
		{name: "no prefix", prefix: "", path: "/list-buckets", handled: true},
		{name: "prefixed route", prefix: "/admin", path: "/admin/list-buckets", handled: true},
		{name: "prefixed route with trailing slash", prefix: "/admin", path: "/admin/list-buckets/", handled: true},
		{name: "root route with prefix set", prefix: "/admin", path: "/list-buckets", handled: false},
		{name: "other prefix", prefix: "/admin", path: "/adminx/list-buckets", handled: false},
	}

	for _, srv := range servers {
		for _, tt := range tests {
			t.Run(srv.name+"/"+tt.name, func(t *testing.T) {
				app := srv.newApp(t, tt.prefix)
				resp, err := app.Test(signedAdminRequest(t, tt.path))
				if err != nil {
					t.Fatalf("app.Test: %v", err)
				}
				defer resp.Body.Close()

				// BackendUnsupported answers a signed, routed list-buckets call with 501.
				handled := resp.StatusCode == http.StatusNotImplemented
				if handled != tt.handled {
					t.Fatalf("PATCH %s with prefix %q: status %d, want handled=%v", tt.path, tt.prefix, resp.StatusCode, tt.handled)
				}
			})
		}
	}
}

func TestAdminPathPrefixExtraRoutes(t *testing.T) {
	srv := NewAdminServer(backend.BackendUnsupported{}, testAdminRoot, "us-east-1", testAdminIAM(), nil, controllers.S3ApiController{},
		WithAdminConcurrencyLimiter(10, 10),
		WithAdminQuiet(),
		WithAdminPathPrefix("/admin"),
		WithAdminRoute(http.MethodGet, "/extra", func(ctx fiber.Ctx) error {
			return ctx.SendStatus(http.StatusNoContent)
		}),
	)

	for path, want := range map[string]bool{"/admin/extra": true, "/extra": false} {
		resp, err := srv.app.Test(httptest.NewRequest(http.MethodGet, path, nil))
		if err != nil {
			t.Fatalf("app.Test %s: %v", path, err)
		}
		resp.Body.Close()
		if got := resp.StatusCode == http.StatusNoContent; got != want {
			t.Errorf("GET %s: status %d, want handled=%v", path, resp.StatusCode, want)
		}
	}
}

var testAdminRoot = middlewares.RootUserConfig{Access: "access", Secret: "secret"}

func testAdminIAM() auth.IAMService {
	return auth.NewIAMServiceSingle(auth.Account{Access: testAdminRoot.Access, Secret: testAdminRoot.Secret})
}

func newTestAdminApp(t *testing.T, prefix string) *fiber.App {
	t.Helper()
	srv := NewAdminServer(backend.BackendUnsupported{}, testAdminRoot, "us-east-1", testAdminIAM(), nil, controllers.S3ApiController{},
		WithAdminConcurrencyLimiter(10, 10),
		WithAdminQuiet(),
		WithAdminPathPrefix(prefix),
	)
	return srv.app
}

func newTestS3AdminApp(t *testing.T, prefix string) *fiber.App {
	t.Helper()
	srv, err := newTestS3ApiServer(WithQuiet(), WithAdminServer(), WithAdminServerPathPrefix(prefix))
	if err != nil {
		t.Fatalf("new s3 server: %v", err)
	}
	return srv.app
}

func signedAdminRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	sum := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(sum[:])

	req := httptest.NewRequest(http.MethodPatch, "http://localhost"+path, nil)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	creds := aws.Credentials{AccessKeyID: testAdminRoot.Access, SecretAccessKey: testAdminRoot.Secret}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, payloadHash, "s3", "us-east-1", time.Now()); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return req
}
