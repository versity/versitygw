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

// Factory for building AuthorizationQueryParametersError errors.
func authQueryParamError(format string, args ...any) APIError {
	return APIError{
		Code:           "AuthorizationQueryParametersError",
		Description:    fmt.Sprintf(format, args...),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

type queryAuthErrors struct{}

func (queryAuthErrors) UnsupportedAlgorithm() APIError {
	return authQueryParamError(`X-Amz-Algorithm only supports "AWS4-HMAC-SHA256 and AWS4-ECDSA-P256-SHA256"`)
}

func (queryAuthErrors) MalformedCredential() APIError {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; expecting "<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request".`)
}

func (queryAuthErrors) IncorrectService(s string) APIError {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; incorrect service %q. This endpoint belongs to "s3".`, s)
}

func (queryAuthErrors) IncorrectRegion(expected, actual string) APIError {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; the region %q is wrong; expecting %q`, actual, expected)
}

func (queryAuthErrors) IncorrectTerminal(s string) APIError {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; incorrect terminal %q. This endpoint uses "aws4_request".`, s)
}

func (queryAuthErrors) InvalidDateFormat(s string) APIError {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; incorrect date format %q. This date in the credential must be in the format "yyyyMMdd".`, s)
}

func (queryAuthErrors) DateMismatch(expected, actual string) APIError {
	return authQueryParamError(`Invalid credential date %q. This date is not the same as X-Amz-Date: %q.`, expected, actual)
}

func (queryAuthErrors) ExpiresTooLarge() APIError {
	return authQueryParamError("X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires must be less than 604800 seconds")
}

func (queryAuthErrors) ExpiresNegative() APIError {
	return authQueryParamError("X-Amz-Expires must be non-negative")
}

func (queryAuthErrors) ExpiresNumber() APIError {
	return authQueryParamError("X-Amz-Expires should be a number")
}

func (queryAuthErrors) MissingRequiredParams() APIError {
	return authQueryParamError("Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.")
}

func (queryAuthErrors) InvalidXAmzDateFormat() APIError {
	return authQueryParamError(`X-Amz-Date must be in the ISO8601 Long Format "yyyyMMdd'T'HHmmss'Z'"`)
}

// a custom non-AWS error
func (queryAuthErrors) OnlyHMACSupported() APIError {
	return authQueryParamError("X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\"")
}

func (queryAuthErrors) SecurityTokenNotSupported() APIError {
	return authQueryParamError("Authorization with X-Amz-Security-Token is not supported")
}

var QueryAuthErrors queryAuthErrors
