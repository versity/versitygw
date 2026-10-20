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
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

func TestCtxPathOverride(t *testing.T) {
	tests := []struct {
		name       string
		override   string
		wantRoute  string
		wantBucket string
	}{
		{"plain object", "/bucket/key", "object", "bucket"},
		{"bucket", "/bucket", "bucket", "bucket"},
		{"bucket trailing slash", "/bucket/", "bucket", "bucket"},
		{"dot key", "/bucket/.", "object", "bucket"},
		{"dot dot key", "/bucket/..", "object", "bucket"},
		{"dot slash key", "/bucket/./", "object", "bucket"},
		{"dot dot inside key", "/bucket/a/../b", "object", "bucket"},
		{"dot dot climbing to the bucket", "/bucket/a/../../b", "object", "bucket"},
		{"escape of an unreserved character", "/bucket/100%41", "object", "bucket"},
		{"escape of a dot", "/bucket/%2e%2e/key", "object", "bucket"},
		{"stray percent", "/bucket/100%", "object", "bucket"},
		{"dot bucket", "/./key", "object", "."},
		{"utf-8 key", "/bucket/ключ/../ü", "object", "bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var route, bucket, path, uriPath string
			record := func(name string) fiber.Handler {
				return func(ctx fiber.Ctx) error {
					route, bucket, path = name, ctx.Params("bucket"), ctx.Path()
					uriPath = string(ctx.Request().URI().PathOriginal())
					return nil
				}
			}

			app := fiber.NewWithCustomCtx(NewCtx)
			app.Use(func(ctx fiber.Ctx) error {
				ctx.Path(tt.override)
				return ctx.Next()
			})
			app.Put("/:bucket", record("bucket"))
			app.Put("/:bucket/*", record("object"))

			resp, err := app.Test(httptest.NewRequest(fiber.MethodPut, "/any/path", nil))
			assert.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode, string(body))

			assert.Equal(t, tt.wantRoute, route)
			assert.Equal(t, tt.wantBucket, bucket)
			assert.Equal(t, tt.override, path)
			assert.Equal(t, tt.override, uriPath)
		})
	}
}

func TestCtxPathBeforeOverride(t *testing.T) {
	var path string
	app := fiber.NewWithCustomCtx(NewCtx)
	app.Put("/:bucket/*", func(ctx fiber.Ctx) error {
		path = ctx.Path()
		return nil
	})

	_, err := app.Test(httptest.NewRequest(fiber.MethodPut, "/bucket/a/../b", nil))
	assert.NoError(t, err)
	// without an override Path is fiber's normalized path
	assert.Equal(t, "/bucket/b", path)
}
