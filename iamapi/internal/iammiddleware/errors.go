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
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/internal/httpctx"
)

// GlobalErrorHandler is the fiber error handler for the IAM API server. It
// translates APIError values into XML responses and logs unexpected errors.
func GlobalErrorHandler(ctx fiber.Ctx, er error) error {
	requestID := EnsureRequestID(ctx)
	ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)

	var apiErr iamerr.APIError
	if errors.As(er, &apiErr) {
		return ctx.Status(apiErr.StatusCode()).Send(apiErr.XMLBody(requestID))
	}

	if httpctx.ContextKeyStack.IsSet(ctx) {
		debuglogger.Panic(er)
	} else {
		debuglogger.InternalError(er)
	}

	err := iamerr.GetAPIError(iamerr.ErrInternalFailure)
	return ctx.Status(err.StatusCode()).Send(err.XMLBody(requestID))
}
