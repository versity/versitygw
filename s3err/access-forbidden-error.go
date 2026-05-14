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

// AccessForbiddenError is returned when a CORS request is not allowed.
// Produces <Method> and <ResourceType> fields in the XML response.
type AccessForbiddenError struct {
	APIError
	Method       string
	ResourceType ResourceType
}

func (e AccessForbiddenError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName      xml.Name `xml:"Error"`
		Code         string
		Message      string
		Method       string       `xml:",omitempty"`
		ResourceType ResourceType `xml:",omitempty"`
		RequestID    string       `xml:"RequestId,omitempty"`
		HostID       string       `xml:"HostId,omitempty"`
	}{
		Code:         e.Code,
		Message:      e.Description,
		Method:       e.Method,
		ResourceType: e.ResourceType,
		RequestID:    requestID,
		HostID:       hostID,
	})
}

func (e AccessForbiddenError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetAccessForbiddenErr(code ErrorCode, method string, resourceType ResourceType) AccessForbiddenError {
	return AccessForbiddenError{
		APIError:     GetAPIError(code),
		Method:       method,
		ResourceType: resourceType,
	}
}
