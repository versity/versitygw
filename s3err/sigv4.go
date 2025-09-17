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
		HTTPStatusCode: http.StatusForbidden,
	}
}

var MalformedAuth = struct {
	InvalidDateFormat    func(string) APIError
	MalformedCredential  func() APIError
	MissingCredential    func() APIError
	MissingSignature     func() APIError
	MissingSignedHeaders func() APIError
	InvalidTerminal      func(string) APIError
	IncorrectRegion      func(expected, actual string) APIError
	IncorrectService     func(string) APIError
	MalformedComponent   func(string) APIError
	MissingComponents    func() APIError
	DateMismatch         func() APIError
}{
	InvalidDateFormat: func(s string) APIError {
		return malformedAuthError("incorrect date format %q. This date in the credential must be in the format \"yyyyMMdd\".", s)
	},
	MalformedCredential: func() APIError {
		return malformedAuthError("the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".")
	},
	MissingCredential: func() APIError {
		return malformedAuthError("missing Credential.")
	},
	MissingSignature: func() APIError {
		return malformedAuthError("missing Signature.")
	},
	MissingSignedHeaders: func() APIError {
		return malformedAuthError("missing SignedHeaders.")
	},
	InvalidTerminal: func(s string) APIError {
		return malformedAuthError("incorrect terminal %q. This endpoint uses \"aws4_request\".", s)
	},
	IncorrectRegion: func(expected, actual string) APIError {
		return malformedAuthError("the region %q is wrong; expecting %q", actual, expected)
	},
	IncorrectService: func(s string) APIError {
		return malformedAuthError("incorrect service %q. This endpoint belongs to \"s3\".", s)
	},
	MalformedComponent: func(s string) APIError {
		return malformedAuthError("the authorization component %q is malformed.", s)
	},
	MissingComponents: func() APIError {
		return malformedAuthError("the authorization header requires three components: Credential, SignedHeaders, and Signature.")
	},
	DateMismatch: func() APIError {
		return malformedAuthError("The authorization header is malformed; Invalid credential date. Date is not the same as X-Amz-Date.")
	},
}
