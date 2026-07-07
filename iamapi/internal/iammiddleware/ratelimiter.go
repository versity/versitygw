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

package iammiddleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/iamerr"
	"golang.org/x/sync/semaphore"
)

// RateLimiter returns a middleware that limits concurrent in-flight requests to
// limit. Excess requests receive a Throttling error response immediately.
func RateLimiter(limit int) fiber.Handler {
	sem := semaphore.NewWeighted(int64(limit))

	return func(ctx fiber.Ctx) error {
		requestID := EnsureRequestID(ctx)

		if !sem.TryAcquire(1) {
			err := iamerr.GetAPIError(iamerr.ErrThrottling)
			ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
			return ctx.Status(err.StatusCode()).Send(err.XMLBody(requestID))
		}
		defer sem.Release(1)
		return ctx.Next()
	}
}
