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

	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// writeRouteError renders err as the terminal S3-style XML response
// of an RC control route. The production S3 error handler converts
// ordinary Fiber errors into a generic 500 response, so the route
// must send its final status and body itself. Errors that already
// carry S3 semantics (authentication, authorization, object
// backend) keep their status and code; anything else is mapped to
// a protocol error without exposing internal detail.
func writeRouteError(ctx fiber.Ctx, err error) error {
	requestID, hostID := utils.EnsureRequestIDs(ctx)

	var apiErr s3err.APIError
	switch e := classifyRouteError(err).(type) {
	case s3err.S3Error:
		apiErr = e.BaseError()
	case s3err.APIError:
		apiErr = e
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

// classifyRouteError resolves err to a value implementing
// s3err.S3Error. S3-aware errors pass through unchanged; RC
// transport errors are mapped to the closest protocol error.
func classifyRouteError(err error) s3err.S3Error {
	var s3Err s3err.S3Error
	if errors.As(err, &s3Err) {
		return s3Err
	}

	code, status, description := routeErrorDetails(err)
	return s3err.APIError{
		Code:           code,
		Description:    description,
		HTTPStatusCode: status,
	}
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
