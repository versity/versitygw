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

// MetadataTooLargeError is returned when the request metadata headers exceed the allowed size.
// Produces <Size> and <MaxSizeAllowed> fields in the XML response.
type MetadataTooLargeError struct {
	APIError
	Size           int
	MaxSizeAllowed int
}

func (e MetadataTooLargeError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName        xml.Name `xml:"Error"`
		Code           string
		Message        string
		Size           int    `xml:",omitempty"`
		MaxSizeAllowed int    `xml:",omitempty"`
		RequestID      string `xml:"RequestId,omitempty"`
		HostID         string `xml:"HostId,omitempty"`
	}{
		Code:           e.Code,
		Message:        e.Description,
		Size:           e.Size,
		MaxSizeAllowed: e.MaxSizeAllowed,
		RequestID:      requestID,
		HostID:         hostID,
	})
}

func (e MetadataTooLargeError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "Size", Value: e.Size},
		ErrorField{Name: "MaxSizeAllowed", Value: e.MaxSizeAllowed},
	)
}

func (e MetadataTooLargeError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetMetadataTooLargeErr(size, maxSizeAllowed int) MetadataTooLargeError {
	return MetadataTooLargeError{
		APIError:       GetAPIError(ErrMetadataTooLarge),
		Size:           size,
		MaxSizeAllowed: maxSizeAllowed,
	}
}
