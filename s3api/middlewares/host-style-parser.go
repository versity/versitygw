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

package middlewares

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/httpctx"
)

// HostStyleParser is a middleware which parses the bucket name
// from the 'Host' header and appends in the request URL path
func HostStyleParser(virtualDomain string) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		host := string(ctx.Request().Host())
		// the host should match this pattern: '<bucket_name>.<virtual_domain>'
		bucket, _, found := strings.Cut(host, "."+virtualDomain)
		if !found || bucket == "" {
			return ctx.Next()
		}
		// SigV4 verification signs the request's original, on-the-wire path,
		// not the bucket-prefixed one used for routing here — save it
		// before ctx.Path() below overwrites fasthttp's URI.PathOriginal too.
		httpctx.ContextKeyOriginalURIPath.Set(ctx, string(ctx.Request().URI().PathOriginal()))

		path := ctx.Path()
		if path == "/" {
			// omit the trailing / for bucket operations
			path = ""
		}
		pathStyleUrl := fmt.Sprintf("/%v%v", bucket, path)
		ctx.Path(pathStyleUrl)

		return ctx.Next()
	}
}
