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

import (
	"encoding/xml"
	"strings"
)

// MethodNotAllowedError is returned when an HTTP method is not permitted on a resource.
// Produces <Method> and <ResourceType> fields in the XML response.
// AllowedMethods is used to populate the HTTP Allow: response header.
type MethodNotAllowedError struct {
	APIError
	Method         string
	ResourceType   ResourceType
	AllowedMethods []string
}

func (mna *MethodNotAllowedError) AllowedMethodsString() string {
	return strings.Join(mna.AllowedMethods, ", ")
}

func (e MethodNotAllowedError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName      xml.Name `xml:"Error"`
		Code         string
		Message      string
		Method       string
		ResourceType ResourceType
		RequestID    string `xml:"RequestId,omitempty"`
		HostID       string `xml:"HostId,omitempty"`
	}{
		Code:         e.Code,
		Message:      e.Description,
		Method:       e.Method,
		ResourceType: e.ResourceType,
		RequestID:    requestID,
		HostID:       hostID,
	})
}

func (e MethodNotAllowedError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "Method", Value: e.Method},
		ErrorField{Name: "ResourceType", Value: e.ResourceType},
	)
}

func (e MethodNotAllowedError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetMethodNotAllowedErr(method string, resourceType ResourceType, allowed []string) MethodNotAllowedError {
	return MethodNotAllowedError{
		APIError:       GetAPIError(ErrMethodNotAllowed),
		Method:         method,
		ResourceType:   resourceType,
		AllowedMethods: allowed,
	}
}
