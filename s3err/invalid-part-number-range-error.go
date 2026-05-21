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

// InvalidPartNumberRangeError is returned when the requested part number exceeds
// the number of parts available for the object.
// Produces <ActualPartCount> and <PartNumberRequested> fields in the XML response.
type InvalidPartNumberRangeError struct {
	APIError
	ActualPartCount     int32
	PartNumberRequested int32
}

func (e InvalidPartNumberRangeError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName             xml.Name `xml:"Error"`
		Code                string
		Message             string
		ActualPartCount     int32
		PartNumberRequested int32
		RequestID           string `xml:"RequestId,omitempty"`
		HostID              string `xml:"HostId,omitempty"`
	}{
		Code:                e.Code,
		Message:             e.Description,
		ActualPartCount:     e.ActualPartCount,
		PartNumberRequested: e.PartNumberRequested,
		RequestID:           requestID,
		HostID:              hostID,
	})
}

func (e InvalidPartNumberRangeError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetInvalidPartNumberRangeErr(actualPartCount, partNumberRequested int32) InvalidPartNumberRangeError {
	return InvalidPartNumberRangeError{
		APIError:            GetAPIError(ErrInvalidPartNumberRange),
		ActualPartCount:     actualPartCount,
		PartNumberRequested: partNumberRequested,
	}
}
