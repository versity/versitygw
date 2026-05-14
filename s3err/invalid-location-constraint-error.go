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

// InvalidLocationConstraintError is returned when an invalid location constraint is provided.
// Produces a <LocationConstraint> field in the XML response.
type InvalidLocationConstraintError struct {
	APIError
	LocationConstraint string
}

func (e InvalidLocationConstraintError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName            xml.Name `xml:"Error"`
		Code               string
		Message            string
		LocationConstraint string
		RequestID          string `xml:"RequestId,omitempty"`
		HostID             string `xml:"HostId,omitempty"`
	}{
		Code:               e.Code,
		Message:            e.Description,
		LocationConstraint: e.LocationConstraint,
		RequestID:          requestID,
		HostID:             hostID,
	})
}

func (e InvalidLocationConstraintError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetInvalidLocationConstraintErr(constraint string) InvalidLocationConstraintError {
	return InvalidLocationConstraintError{
		APIError:           GetAPIError(ErrInvalidLocationConstraint),
		LocationConstraint: constraint,
	}
}
