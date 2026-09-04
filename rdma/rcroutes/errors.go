// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

package rcroutes

import (
	"errors"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// ErrRouteNotImplemented is the platform-stub answer of the
// control routes on builds without the RC data plane.
type ErrRouteNotImplemented struct{}

func (ErrRouteNotImplemented) Error() string {
	return "RDMA not supported on this platform"
}

// isRouteNotImplemented reports whether err is the platform-stub
// answer of the control routes. The marker type is shared, so
// every build classifies it the same way.
func isRouteNotImplemented(err error) bool {
	var ni ErrRouteNotImplemented
	return errors.As(err, &ni)
}

// WriteRouteError renders err as the terminal S3-style XML response
// of an RC control route. The production S3 error handler converts
// ordinary Fiber errors into a generic 500 response, so the route
// must send its final status and body itself. Errors that already
// carry S3 semantics (authentication, authorization, object
// backend) keep their status and code; anything else is mapped to
// a protocol error without exposing internal detail. The gateway
// auth adapter uses it for the same reason.
func WriteRouteError(ctx fiber.Ctx, err error) error {
	requestID, hostID := utils.EnsureRequestIDs(ctx)

	apiErr := routeError(err)
	if apiErr.HTTPStatusCode == fiber.StatusInternalServerError {
		logInternalRouteError(ctx, err)
	}
	if isRouteNotImplemented(err) {
		apiErr = s3err.APIError{
			Code:           "NotImplemented",
			Description:    "RDMA is not supported on this platform",
			HTTPStatusCode: fiber.StatusNotImplemented,
		}
	}

	ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
	return ctx.Status(apiErr.HTTPStatusCode).
		Send(apiErr.XMLBody(requestID, hostID))
}

// routeError resolves err to its S3-style response. Errors that
// already carry S3 semantics (authentication, authorization,
// object backend) keep their status and code; RC transport errors
// map to the closest protocol error.
func routeError(err error) s3err.APIError {
	var s3Err s3err.S3Error
	if errors.As(err, &s3Err) {
		return s3Err.BaseError()
	}

	code, status, description := routeErrorDetails(err)
	return s3err.APIError{
		Code:           code,
		Description:    description,
		HTTPStatusCode: status,
	}
}

// logInternalRouteError keeps a server-side trace of unexpected
// failures. The wire response stays generic; without this the
// terminal serializer would hide the production diagnostics the
// global error handler used to log.
func logInternalRouteError(ctx fiber.Ctx, err error) {
	debuglogger.InternalError(err)
}

// routeErrorDetails maps a non-S3 route error to its protocol
// error code, HTTP status, and description.
func routeErrorDetails(err error) (code string, status int, description string) {
	switch {
	case isRouteBadRequest(err):
		return "InvalidRdmaRequest", fiber.StatusBadRequest,
			"Invalid RDMA control request"
	case isRouteNotFound(err):
		return "NoSuchRdmaSession", fiber.StatusNotFound,
			"No such RDMA session"
	case isRouteConflict(err):
		return "RdmaSessionConflict", fiber.StatusConflict,
			"RDMA session state conflict"
	case isRouteLimit(err):
		return "RdmaResourceLimit", fiber.StatusTooManyRequests,
			"RDMA resource limit reached"
	case isRouteBadGateway(err):
		return "RdmaTransferFailed", fiber.StatusBadGateway,
			"RDMA transfer failed"
	case isRouteUnavailable(err):
		return "RdmaServiceUnavailable", fiber.StatusServiceUnavailable,
			"RDMA service is shutting down"
	default:
		return s3err.GetAPIError(s3err.ErrInternalError).Code,
			fiber.StatusInternalServerError, "Internal Error"
	}
}
