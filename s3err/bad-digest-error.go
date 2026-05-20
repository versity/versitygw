// Copyright 2026 Versity Software
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

import "encoding/xml"

// BadDigestError is returned when the Content-MD5 does not match the received data.
// Produces <CalculatedDigest> and <ExpectedDigest> fields in the XML response.
type BadDigestError struct {
	APIError
	CalculatedDigest string
	ExpectedDigest   string
}

func (e BadDigestError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName          xml.Name `xml:"Error"`
		Code             string
		Message          string
		CalculatedDigest string `xml:",omitempty"`
		ExpectedDigest   string `xml:",omitempty"`
		RequestID        string `xml:"RequestId,omitempty"`
		HostID           string `xml:"HostId,omitempty"`
	}{
		Code:             e.Code,
		Message:          e.Description,
		CalculatedDigest: e.CalculatedDigest,
		ExpectedDigest:   e.ExpectedDigest,
		RequestID:        requestID,
		HostID:           hostID,
	})
}

func (e BadDigestError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetBadDigestErr(calculated, expected string) BadDigestError {
	return BadDigestError{
		APIError:         GetAPIError(ErrBadDigest),
		CalculatedDigest: calculated,
		ExpectedDigest:   expected,
	}
}
