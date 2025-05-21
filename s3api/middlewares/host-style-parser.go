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

	"github.com/gofiber/fiber/v2"
)

// HostStyleParser is a middleware which parses the bucket name
// from the 'Host' header and appends in the request URL path
func HostStyleParser(virtualDomain string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		host := string(ctx.Request().Host())
		// the host should match this pattern: '<bucket_name>.<virtual_domain>'
		bucket, _, found := strings.Cut(host, "."+virtualDomain)
		if !found || bucket == "" {
			return ctx.Next()
		}
		path := ctx.Path()
		pathStyleUrl := fmt.Sprintf("/%v%v", bucket, path)
		ctx.Path(pathStyleUrl)

		return ctx.Next()
	}
}
