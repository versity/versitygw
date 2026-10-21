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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/controllers"
)

// The admin CreateBucket must check its LocationConstraint against the
// gateway region on a standalone admin port, just like it does when the admin
// API shares the s3 port.
func TestAdminCreateBucketLocationConstraint(t *testing.T) {
	const region = "eu-central-1"

	servers := []struct {
		name   string
		newApp func(t *testing.T) *fiber.App
	}{
		{name: "standalone admin server", newApp: func(t *testing.T) *fiber.App {
			iam := testAdminIAM()
			ctrl := controllers.New(backend.BackendUnsupported{}, iam, nil, nil, nil, false, false, "", 0)
			srv := NewAdminServer(backend.BackendUnsupported{}, testAdminRoot, region, iam, nil, ctrl,
				WithAdminConcurrencyLimiter(10, 10),
				WithAdminQuiet(),
			)
			return srv.app
		}},
		{name: "admin on s3 server", newApp: func(t *testing.T) *fiber.App {
			srv, err := New(backend.BackendUnsupported{}, testAdminRoot, region, testAdminIAM(), nil, nil, nil, nil,
				WithConcurrencyLimiter(10, 10),
				WithQuiet(),
				WithAdminServer(),
			)
			if err != nil {
				t.Fatalf("new s3 server: %v", err)
			}
			return srv.app
		}},
	}

	tests := []struct {
		name       string
		constraint string
		wantStatus int
		wantCode   string
	}{
		// BackendUnsupported answers a CreateBucket that passed validation with 501.
		{name: "gateway region", constraint: region, wantStatus: http.StatusNotImplemented},
		{name: "no constraint", wantStatus: http.StatusBadRequest, wantCode: "IllegalLocationConstraintException"},
		{name: "other region", constraint: "us-west-2", wantStatus: http.StatusBadRequest, wantCode: "IllegalLocationConstraintException"},
	}

	for _, srv := range servers {
		for _, tt := range tests {
			t.Run(srv.name+"/"+tt.name, func(t *testing.T) {
				body := ""
				if tt.constraint != "" {
					body = "<CreateBucketConfiguration><LocationConstraint>" + tt.constraint + "</LocationConstraint></CreateBucketConfiguration>"
				}

				resp, err := srv.newApp(t).Test(signedAdminCreateBucketRequest(t, "/test-bucket/create", region, body))
				if err != nil {
					t.Fatalf("app.Test: %v", err)
				}
				defer resp.Body.Close()

				respBody, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != tt.wantStatus {
					t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.wantStatus, respBody)
				}
				if tt.wantCode != "" && !strings.Contains(string(respBody), "<Code>"+tt.wantCode+"</Code>") {
					t.Fatalf("response %s, want error code %s", respBody, tt.wantCode)
				}
			})
		}
	}
}

func signedAdminCreateBucketRequest(t *testing.T, path, region, body string) *http.Request {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(sum[:])

	req := httptest.NewRequest(http.MethodPatch, "http://localhost"+path, strings.NewReader(body))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("X-Vgw-Owner", testAdminRoot.Access)
	creds := aws.Credentials{AccessKeyID: testAdminRoot.Access, SecretAccessKey: testAdminRoot.Secret}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, payloadHash, "s3", region, time.Now()); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return req
}
