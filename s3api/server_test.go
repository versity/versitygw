// Copyright 2023 Versity Software
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
)

func TestS3ApiServer_Serve(t *testing.T) {
	tests := []struct {
		name    string
		sa      *S3ApiServer
		wantErr bool
		port    string
	}{
		{
			name:    "Serve-invalid-tcp-address",
			wantErr: true,
			sa: &S3ApiServer{
				app:     fiber.New(),
				backend: backend.BackendUnsupported{},
				Router:  &S3ApiRouter{},
			},
			port: "localhost:notaport",
		},
		{
			name:    "Serve-invalid-tcp-address-with-certificate",
			wantErr: true,
			sa: &S3ApiServer{
				app:         fiber.New(),
				backend:     backend.BackendUnsupported{},
				Router:      &S3ApiRouter{},
				CertStorage: &utils.CertStorage{},
			},
			port: "localhost:notaport",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.sa.ServeMultiPort([]string{tt.port}); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiServer.Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWithRouteRegistersBeforeMiddleware(t *testing.T) {
	const routePath = "/custom/route"

	middlewareCalled := false
	server, err := New(
		backend.BackendUnsupported{},
		middlewares.RootUserConfig{Access: "access", Secret: "secret"},
		"us-east-1",
		auth.NewIAMServiceSingle(auth.Account{Access: "access", Secret: "secret"}),
		nil,
		nil,
		nil,
		nil,
		WithRoute(http.MethodGet, routePath, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(http.StatusNoContent)
		}),
		WithMiddleware("/", func(ctx *fiber.Ctx) error {
			middlewareCalled = true
			return ctx.SendStatus(http.StatusMisdirectedRequest)
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := server.app.Test(httptest.NewRequest(http.MethodGet, routePath, nil))
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("response close error = %v", err)
		}
	}()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if middlewareCalled {
		t.Fatal("middleware was called for top-level route")
	}
}
