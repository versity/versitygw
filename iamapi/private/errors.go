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

package private

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
)

// Error codes carried in the JSON error body's "code" field. The S3
// gateway maps them to distinct S3 errors — CodeNoSuchIdentity to
// InvalidAccessKeyId, CodeInvalidToken to InvalidToken — so an end user
// gets an accurate diagnosis instead of one catch-all. Without them every
// 403 looks identical on the wire, and a gateway whose own IAM-client
// credential was rotated would tell the *user* their access key doesn't
// exist.
const (
	CodeNoSuchIdentity = "NoSuchIdentity"
	CodeInvalidToken   = "InvalidToken"
	CodeBadRequest     = "BadRequest"
)

// privateAPIError is a minimal local error for failures (like a malformed
// request body) that don't map to any of iamerr's AWS-IAM-specific error
// codes — this protocol is plain JSON, not the rest of iamapi's
// AWS-Query/XML wire format, so there's no need to force every error
// through iamerr.APIError's XML-rendering machinery.
type privateAPIError struct {
	status  int
	code    string
	message string
}

func (e *privateAPIError) Error() string   { return e.message }
func (e *privateAPIError) StatusCode() int { return e.status }
func (e *privateAPIError) Code() string    { return e.code }

var (
	errMalformedRequestBody = &privateAPIError{
		status:  http.StatusBadRequest,
		code:    CodeBadRequest,
		message: "malformed request body",
	}
	errNoSuchIdentity = &privateAPIError{
		status:  http.StatusForbidden,
		code:    CodeNoSuchIdentity,
		message: "no identity for the given access key id",
	}
	errInvalidSessionToken = &privateAPIError{
		status:  http.StatusForbidden,
		code:    CodeInvalidToken,
		message: "the given session token is missing, invalid, or does not belong to the given access key id",
	}
)

// mapResolveError translates iamutil's identity-resolution sentinels into
// the wire errors this protocol reports. Anything unrecognized falls through
// unchanged and renders as a 500, which is the correct signal: it is a fault
// in the IAM service, not a problem with the caller's identity.
func mapResolveError(err error) error {
	switch {
	case errors.Is(err, iamutil.ErrIdentityNotFound):
		return errNoSuchIdentity
	case errors.Is(err, iamutil.ErrInvalidSessionToken):
		return errInvalidSessionToken
	default:
		return err
	}
}

// coder is implemented by errors carrying a stable machine-readable code
// for the "code" field of the JSON error body.
type coder interface {
	Code() string
}

// statusCoder is satisfied by both iamerr.APIError (used by
// iammiddleware.VerifyRootOnlySigV4) and privateAPIError, so errorHandler
// can extract the right HTTP status from either without depending on
// iamerr's XML-specific interface methods.
type statusCoder interface {
	StatusCode() int
}

// errorHandler renders any error as a small JSON body with the matching
// HTTP status (defaulting to 500 for an error with no known status) and,
// where the error carries one, a machine-readable code the S3 gateway
// dispatches on.
func (p *PrivateAPI) errorHandler(ctx fiber.Ctx, err error) error {
	status := http.StatusInternalServerError
	if sc, ok := err.(statusCoder); ok {
		status = sc.StatusCode()
	} else {
		debuglogger.InternalError(err)
	}

	body := map[string]string{"error": err.Error()}
	if c, ok := err.(coder); ok {
		body["code"] = c.Code()
	}

	ctx.Status(status)
	return ctx.JSON(body)
}
