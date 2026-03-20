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

package s3err

import (
	"fmt"
	"net/http"
)

// Factory for building AuthorizationHeaderMalformed errors.
func malformedAuthError(format string, args ...any) APIError {
	return APIError{
		Code:           "AuthorizationHeaderMalformed",
		Description:    fmt.Sprintf("The authorization header is malformed; %s", fmt.Sprintf(format, args...)),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

type malformedAuthErrors struct{}

func (malformedAuthErrors) InvalidDateFormat(s string) APIError {
	return malformedAuthError(
		"incorrect date format %q. This date in the credential must be in the format \"yyyyMMdd\".",
		s,
	)
}

func (malformedAuthErrors) MalformedCredential() APIError {
	return malformedAuthError(
		"the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
	)
}

func (malformedAuthErrors) MissingCredential() APIError {
	return malformedAuthError("missing Credential.")
}

func (malformedAuthErrors) MissingSignature() APIError {
	return malformedAuthError("missing Signature.")
}

func (malformedAuthErrors) MissingSignedHeaders() APIError {
	return malformedAuthError("missing SignedHeaders.")
}

func (malformedAuthErrors) IncorrectTerminal(s string) APIError {
	return malformedAuthError("incorrect terminal %q. This endpoint uses \"aws4_request\".", s)
}

func (malformedAuthErrors) IncorrectRegion(expected, actual string) APIError {
	return malformedAuthError("the region %q is wrong; expecting %q", actual, expected)
}

func (malformedAuthErrors) IncorrectService(s string) APIError {
	return malformedAuthError("incorrect service %q. This endpoint belongs to \"s3\".", s)
}

func (malformedAuthErrors) MalformedComponent(s string) APIError {
	return malformedAuthError("the authorization component %q is malformed.", s)
}

func (malformedAuthErrors) MissingComponents() APIError {
	return malformedAuthError(
		"the authorization header requires three components: Credential, SignedHeaders, and Signature.",
	)
}

func (malformedAuthErrors) DateMismatch() APIError {
	return malformedAuthError(
		"The authorization header is malformed; Invalid credential date. Date is not the same as X-Amz-Date.",
	)
}

var MalformedAuth malformedAuthErrors
