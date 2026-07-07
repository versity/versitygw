// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamutil

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/httpctx"
)

func TestMatchQueryOrFormArgs(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		target      string
		body        string
		contentType string
		want        string
	}{
		{name: "query", method: http.MethodGet, target: "/any?Action=ListUsers", want: "matched"},
		{name: "empty query value is present", method: http.MethodGet, target: "/any?Action=", want: "matched"},
		{name: "form", method: http.MethodPost, target: "/any", body: "Action=ListUsers", contentType: fiber.MIMEApplicationForm, want: "matched"},
		{name: "missing", method: http.MethodGet, target: "/any", want: "fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			app.Add([]string{http.MethodGet, http.MethodPost}, "/*",
				MatchQueryOrFormArgs("Action"),
				func(ctx fiber.Ctx) error {
					if httpctx.ContextKeySkip.IsSet(ctx) {
						httpctx.ContextKeySkip.Delete(ctx)
						return ctx.Next()
					}
					return ctx.SendString("matched")
				},
			)
			app.All("*", func(ctx fiber.Ctx) error { return ctx.SendString("fallback") })

			req := httptest.NewRequest(tt.method, tt.target, bytes.NewBufferString(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if string(body) != tt.want {
				t.Fatalf("body = %q, want %q", string(body), tt.want)
			}
		})
	}
}
