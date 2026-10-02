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
			name:    "invalid escape",
			uri:     "/bucket/(*&^%&())",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
		{
			name:    "truncated escape",
			uri:     "/bucket/object%2",
			wantErr: s3err.GetAPIError(s3err.ErrInvalidURI),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// net/http refuses to build a request with a malformed escape,
			// so the raw uri is set on the fasthttp request directly
			fctx := &fasthttp.RequestCtx{}
			fctx.Request.SetRequestURI(tt.uri)
			app := fiber.New()
			ctx := app.AcquireCtx(fctx)
			defer app.ReleaseCtx(ctx)

			err := DecodeURL(ctx)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantPath, ctx.Path())
		})
	}
}
