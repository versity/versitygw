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
	"github.com/google/uuid"
	"github.com/versity/versitygw/internal/httpctx"
)

const HeaderAmznRequestID = "x-amzn-RequestId"

// RequestIDs is a middleware that ensures every request has a request ID set
// and returned in the response header.
func RequestIDs() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		EnsureRequestID(ctx)
		return ctx.Next()
	}
}

// EnsureRequestID returns the existing request ID from the context, or
// generates and stores a new one if none exists. It always sets the
// x-amzn-RequestId response header.
func EnsureRequestID(ctx fiber.Ctx) string {
	requestID, _ := httpctx.ContextKeyRequestID.Get(ctx).(string)
	if requestID == "" {
		requestID = uuid.NewString()
		httpctx.ContextKeyRequestID.Set(ctx, requestID)
	}

	ctx.Response().Header.Set(HeaderAmznRequestID, requestID)
	return requestID
}
