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
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/internal/httpctx"
	"github.com/versity/versitygw/s3err"
)

func TestDecodeURL(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		wantPath string
		wantErr  error
	}{
		{
			name:     "plain path",
			uri:      "/bucket/object",
			wantPath: "/bucket/object",
		},
		{
			name:     "escaped characters",
			uri:      "/bucket/my%20object%2Bkey",
			wantPath: "/bucket/my object+key",
		},
		{
			name:     "escaped percent is decoded once",
			uri:      "/bucket/100%2541",
			wantPath: "/bucket/100%41",
		},
		{
			name:     "dot segments stay in the key",
			uri:      "/bucket/./a/../b/.",
			wantPath: "/bucket/./a/../b/.",
		},
		{
			name:     "escaped dot segments are decoded",
			uri:      "/bucket/q/%2e%2E/r",
			wantPath: "/bucket/q/../r",
		},
		{
			name:     "dot dot climbing to the root",
			uri:      "/bucket/../key",
			wantPath: "/bucket/../key",
		},
		{
			name:     "empty segments climbed over",
			uri:      "/bucket/x//../../key",
			wantPath: "/bucket/x//../../key",
		},
		{
			name:    "dot dot above the root",
			uri:     "/bucket/../../key",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:    "dot dot above the root without a bucket",
			uri:     "/..",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:    "empty segments don't count",
			uri:     "/bucket//../../key",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:     "backslash dot dot climbing to the root",
			uri:      "/bucket/..%5Ckey",
			wantPath: "/bucket/..\\key",
		},
		{
			name:    "backslash separated dot dot above the root",
			uri:     "/bucket/x%5C..%5C..%5C..%5Ckey",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:    "escaped dot dot above the root",
			uri:     "/bucket/.%2e/%2E%2E/key",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:    "invalid escape",
			uri:     "/bucket/(*&^%&())",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:    "truncated escape",
			uri:     "/bucket/object%2",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:     "absolute-form",
			uri:      "http://s3.example.test/bucket/my%20object",
			wantPath: "/bucket/my object",
		},
		{
			name:     "absolute-form of an uppercase https scheme",
			uri:      "HTTPS://s3.example.test/bucket/object",
			wantPath: "/bucket/object",
		},
		{
			name:    "absolute-form of a non-http scheme",
			uri:     "ftp://s3.example.test/bucket/object",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// net/http refuses to build a request with a malformed escape,
			// so the raw uri is set on the fasthttp request directly
			fctx := &fasthttp.RequestCtx{}
			fctx.Request.SetRequestURI(tt.uri)
			app := fiber.NewWithCustomCtx(httpctx.NewCtx)
			ctx := app.AcquireCtx(fctx)
			defer app.ReleaseCtx(ctx)

			err := DecodeURL(ctx)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantPath, ctx.Path())
			assert.Equal(t, tt.wantPath, string(ctx.Request().URI().PathOriginal()))
		})
	}
}
