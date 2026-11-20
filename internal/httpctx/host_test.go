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

package httpctx

import (
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestRequestHost(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		host       string
		wantHost   string
		wantScheme bool
	}{
		{"origin-form", "/bucket/key", "s3.example.test", "s3.example.test", true},
		{"origin-form keeps the host as sent", "/bucket/key", "S3.Example.Test:443", "S3.Example.Test:443", true},
		{"absolute-form", "http://s3.example.test/bucket/key", "s3.example.test", "s3.example.test", true},
		{"absolute-form host wins over the Host header", "http://bucket.s3.example.test:7070/key", "s3.example.test:7070", "bucket.s3.example.test:7070", true},
		{"absolute-form keeps the host as sent", "HTTPS://Bucket.S3.Example.Test:443/key", "s3.example.test", "Bucket.S3.Example.Test:443", true},
		{"absolute-form keeps a userinfo", "http://s3.example.test@bucket.s3.example.test/key", "s3.example.test", "s3.example.test@bucket.s3.example.test", true},
		{"absolute-form without a path", "http://bucket.s3.example.test", "s3.example.test", "bucket.s3.example.test", true},
		{"absolute-form host ends at the query", "http://bucket.s3.example.test?a=b/c", "s3.example.test", "bucket.s3.example.test", true},
		{"absolute-form host ends at the fragment", "http://bucket.s3.example.test#a/b", "s3.example.test", "bucket.s3.example.test", true},
		{"absolute-form with an empty host", "http:///bucket/key", "s3.example.test", "s3.example.test", true},
		{"absolute-form of a non-http scheme", "ftp://bucket.s3.example.test/key", "s3.example.test", "bucket.s3.example.test", false},
		{"origin-form starting with a host", "//bucket.s3.example.test/key#://", "s3.example.test", "s3.example.test", true},
		{"origin-form with :// in the path", "/bucket/a://b", "s3.example.test", "s3.example.test", true},
		{"not a scheme before ://", "a/b://bucket.s3.example.test/key", "s3.example.test", "s3.example.test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fctx := &fasthttp.RequestCtx{}
			fctx.Request.SetRequestURI(tt.target)
			fctx.Request.Header.SetHost(tt.host)
			app := fiber.NewWithCustomCtx(NewCtx)
			ctx := app.AcquireCtx(fctx)
			defer app.ReleaseCtx(ctx)

			assert.Equal(t, tt.wantHost, RequestHost(ctx))
			assert.Equal(t, tt.wantScheme, HasHTTPScheme(ctx))
		})
	}
}
