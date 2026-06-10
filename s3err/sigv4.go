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

// MalformedAuthError is returned when a Signature V4 authorization header is malformed.
// Produces a <Region> field in the XML response when the expected gateway region is known.
type MalformedAuthError struct {
	APIError
	Region string
}

func (e MalformedAuthError) XMLBody(requestID, hostID string) []byte {
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

func (e MalformedAuthError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "Region", Value: e.Region},
	)
}

func (e MalformedAuthError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

// Factory for building AuthorizationHeaderMalformed errors.
func malformedAuthError(format string, args ...any) MalformedAuthError {
	return MalformedAuthError{
		APIError: APIError{
			Code:           "AuthorizationHeaderMalformed",
			Description:    fmt.Sprintf("The authorization header is malformed; %s", fmt.Sprintf(format, args...)),
			HTTPStatusCode: http.StatusBadRequest,
		},
	}
}

type malformedAuthErrors struct{}

func (malformedAuthErrors) InvalidDateFormat(_, s string) S3Error {
	return malformedAuthError(
		"incorrect date format %q. This date in the credential must be in the format \"yyyyMMdd\".",
		s,
	)
}

func (malformedAuthErrors) MalformedCredential(_ string) S3Error {
	return malformedAuthError(
		"the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
	)
}

func (malformedAuthErrors) MissingCredential() S3Error {
	return malformedAuthError("missing Credential.")
}

func (malformedAuthErrors) MissingSignature() S3Error {
	return malformedAuthError("missing Signature.")
}

func (malformedAuthErrors) MissingSignedHeaders() S3Error {
	return malformedAuthError("missing SignedHeaders.")
}

func (malformedAuthErrors) IncorrectTerminal(_, s string) S3Error {
	return malformedAuthError("incorrect terminal %q. This endpoint uses \"aws4_request\".", s)
}

func (malformedAuthErrors) IncorrectRegion(expected, actual string) S3Error {
	err := malformedAuthError("the region %q is wrong; expecting %q", actual, expected)
	err.Region = expected
	return err
}

func (malformedAuthErrors) IncorrectService(_, s string) S3Error {
	return malformedAuthError("incorrect service %q. This endpoint belongs to \"s3\".", s)
}

func (malformedAuthErrors) MalformedComponent(s string) S3Error {
	return malformedAuthError("the authorization component %q is malformed.", s)
}

func (malformedAuthErrors) MissingComponents() S3Error {
	return malformedAuthError(
		"the authorization header requires three components: Credential, SignedHeaders, and Signature.",
	)
}

func (malformedAuthErrors) DateMismatch() S3Error {
	return malformedAuthError(
		"The authorization header is malformed; Invalid credential date. Date is not the same as X-Amz-Date.",
	)
}

var MalformedAuth malformedAuthErrors
