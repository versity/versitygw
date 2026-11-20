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

package clientip

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/versity/versitygw/internal/httpctx"
)

// Middleware resolves the client address for logging from the given proxy
// header, honouring it only when the connection peer is a trusted proxy, and
// stores it in the request context. Requests from an untrusted peer, or with
// no usable header value, keep the socket peer address.
func Middleware(header string, trusted TrustedProxies) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		httpctx.ContextKeyClientIP.Set(ctx, ClientIPFromHeader(ctx, header, trusted))
		return ctx.Next()
	}
}

// Tag writes the address resolved by Middleware, falling back to the socket
// peer address when no proxy header is configured. Register it as the
// logger.TagIP custom tag so the request log uses the same address as the
// access logs.
func Tag(output logger.Buffer, ctx fiber.Ctx, _ *logger.Data, _ string) (int, error) {
	return output.WriteString(ClientIP(ctx))
}
