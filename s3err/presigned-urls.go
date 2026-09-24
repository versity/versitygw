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
	"encoding/xml"
	"fmt"
	"net/http"
)

// AuthQueryParamError is returned when the Signature V4 query parameters of a
// presigned URL are malformed. Produces a <Region> field in the XML response
// when the expected gateway region is known.
type AuthQueryParamError struct {
	APIError
	Region string
}

func (e AuthQueryParamError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string
		Message   string
		Region    string `xml:",omitempty"`
		RequestID string `xml:"RequestId,omitempty"`
		HostID    string `xml:"HostId,omitempty"`
	}{
		Code:      e.Code,
		Message:   e.Description,
		Region:    e.Region,
		RequestID: requestID,
		HostID:    hostID,
	})
}

func (e AuthQueryParamError) HTMLBody(requestID, hostID string) []byte {
	// Region is only set for the credential region mismatch; every other
	// query parameter error leaves it out.
	if e.Region == "" {
		return e.APIError.encodeHTMLResponse(requestID, hostID)
	}

	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "Region", Value: e.Region},
	)
}

// ExpectedRegion implements RegionMismatchError.
func (e AuthQueryParamError) ExpectedRegion() string { return e.Region }

func (e AuthQueryParamError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

// Factory for building AuthorizationQueryParametersError errors.
func authQueryParamError(format string, args ...any) AuthQueryParamError {
	return AuthQueryParamError{
		APIError: APIError{
			Code:           "AuthorizationQueryParametersError",
			Description:    fmt.Sprintf(format, args...),
			HTTPStatusCode: http.StatusBadRequest,
		},
	}
}

type queryAuthErrors struct{}

func (queryAuthErrors) UnsupportedAlgorithm() S3Error {
	return authQueryParamError(`X-Amz-Algorithm only supports "AWS4-HMAC-SHA256 and AWS4-ECDSA-P256-SHA256"`)
}

func (queryAuthErrors) MalformedCredential(_ string) S3Error {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; expecting "<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request".`)
}

func (queryAuthErrors) IncorrectService(_, s string) S3Error {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; incorrect service %q. This endpoint belongs to "s3".`, s)
}

func (queryAuthErrors) IncorrectRegion(expected, actual string) S3Error {
	err := authQueryParamError(`Error parsing the X-Amz-Credential parameter; the region '%s' is wrong; expecting '%s'`, actual, expected)
	err.Region = expected
	return err
}

func (queryAuthErrors) IncorrectTerminal(_, s string) S3Error {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; incorrect terminal %q. This endpoint uses "aws4_request".`, s)
}

func (queryAuthErrors) InvalidDateFormat(_, s string) S3Error {
	return authQueryParamError(`Error parsing the X-Amz-Credential parameter; incorrect date format %q. This date in the credential must be in the format "yyyyMMdd".`, s)
}

func (queryAuthErrors) DateMismatch(expected, actual string) S3Error {
	return authQueryParamError(`Invalid credential date %q. This date is not the same as X-Amz-Date: %q.`, expected, actual)
}

func (queryAuthErrors) ExpiresTooLarge() S3Error {
	return authQueryParamError("X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires must be less than 604800 seconds")
}

func (queryAuthErrors) ExpiresNegative() S3Error {
	return authQueryParamError("X-Amz-Expires must be non-negative")
}

func (queryAuthErrors) ExpiresNumber() S3Error {
	return authQueryParamError("X-Amz-Expires should be a number")
}

func (queryAuthErrors) MissingRequiredParams() S3Error {
	return authQueryParamError("Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.")
}

func (queryAuthErrors) InvalidXAmzDateFormat() S3Error {
	return authQueryParamError(`X-Amz-Date must be in the ISO8601 Long Format "yyyyMMdd'T'HHmmss'Z'"`)
}

// a custom non-AWS error
func (queryAuthErrors) OnlyHMACSupported() S3Error {
	return authQueryParamError("X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\"")
}

var QueryAuthErrors queryAuthErrors
