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
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/internal/httpctx"
)

// DebugLogger returns a middleware that logs full request and response details
// when debug logging is enabled.
func DebugLogger() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		debuglogger.LogFiberRequestDetails(ctx)
		err := ctx.Next()
		debuglogger.LogFiberResponseDetails(ctx)
		return err
	}
}

// StackTraceHandler stores the panic value in the request context so that the
// global error handler can distinguish panics from regular errors.
func StackTraceHandler(ctx fiber.Ctx, e any) {
	httpctx.ContextKeyStack.Set(ctx, e)
}
