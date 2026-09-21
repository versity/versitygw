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
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/s3api/utils"
)

// ClientIP resolves the client address for logging from the given proxy
// header and stores it in the request context. Requests that carry no usable
// value keep the socket peer address.
func ClientIP(header string) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		utils.ContextKeyClientIP.Set(ctx, utils.ClientIPFromHeader(ctx, header))
		return ctx.Next()
	}
}
