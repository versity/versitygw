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
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/s3err"
)

func TestValidateResponseOverrides(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		uri     string
		wantErr error
	}{
		{
			name:   "no query",
			method: http.MethodGet,
			uri:    "/bucket/object",
		},
		{
			name:   "valid overrides",
			method: http.MethodGet,
			uri:    "/bucket/object?response-content-type=text%2Fplain&response-cache-control=no-cache",
		},
		{
			name:    "unknown override on GetObject",
			method:  http.MethodGet,
			uri:     "/bucket/object?response-invalid=value",
			wantErr: s3err.GetInvalidArgResponseOverride("response-invalid", "value"),
		},
		{
			name:    "unknown override on HeadObject",
			method:  http.MethodHead,
			uri:     "/bucket/object?response-invalid=value",
			wantErr: s3err.GetInvalidArgResponseOverride("response-invalid", "value"),
		},
		{
			name:    "unknown override on PutObject",
			method:  http.MethodPut,
			uri:     "/bucket/object?response-invalid=value",
			wantErr: s3err.GetInvalidArgResponseOverride("response-invalid", "value"),
		},
		{
			name:    "unknown override on a bucket action",
			method:  http.MethodGet,
			uri:     "/bucket?list-type=2&response-invalid",
			wantErr: s3err.GetInvalidArgResponseOverride("response-invalid", ""),
		},
		{
			name:   "unknown override on a CORS preflight",
			method: http.MethodOptions,
			uri:    "/bucket/object?response-invalid=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fctx := &fasthttp.RequestCtx{}
			fctx.Request.Header.SetMethod(tt.method)
			fctx.Request.SetRequestURI(tt.uri)
			app := fiber.New()
			ctx := app.AcquireCtx(fctx)
			defer app.ReleaseCtx(ctx)

			assert.Equal(t, tt.wantErr, ValidateResponseOverrides(ctx))
		})
	}
}
