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

// EntityTooSmallError is returned when the proposed upload is smaller than the minimum allowed size.
// Produces <ProposedSize> and <MinSizeAllowed> fields in the XML response.
type EntityTooSmallError struct {
	APIError
	ProposedSize   int64
	MinSizeAllowed int64
}

func (e EntityTooSmallError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName        xml.Name `xml:"Error"`
		Code           string
		Message        string
		ProposedSize   int64  `xml:",omitempty"`
		MinSizeAllowed int64  `xml:",omitempty"`
		RequestID      string `xml:"RequestId,omitempty"`
		HostID         string `xml:"HostId,omitempty"`
	}{
		Code:           e.Code,
		Message:        e.Description,
		ProposedSize:   e.ProposedSize,
		MinSizeAllowed: e.MinSizeAllowed,
		RequestID:      requestID,
		HostID:         hostID,
	})
}

func (e EntityTooSmallError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetEntityTooSmallErr(proposedSize, minSizeAllowed int64) EntityTooSmallError {
	return EntityTooSmallError{
		APIError:       GetAPIError(ErrEntityTooSmall),
		ProposedSize:   proposedSize,
		MinSizeAllowed: minSizeAllowed,
	}
}
