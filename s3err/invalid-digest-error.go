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

// InvalidDigestError is returned when the Content-MD5 header value is invalid.
// Produces a <Content-MD5> field in the XML response.
type InvalidDigestError struct {
	APIError
	ContentMD5 string
}

func (e InvalidDigestError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName    xml.Name `xml:"Error"`
		Code       string
		Message    string
		ContentMD5 string `xml:"Content-MD5"`
		RequestID  string `xml:"RequestId,omitempty"`
		HostID     string `xml:"HostId,omitempty"`
	}{
		Code:       e.Code,
		Message:    e.Description,
		ContentMD5: e.ContentMD5,
		RequestID:  requestID,
		HostID:     hostID,
	})
}

func (e InvalidDigestError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "Content-MD5", Value: e.ContentMD5},
	)
}

func (e InvalidDigestError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetInvalidDigestErr(contentMD5 string) InvalidDigestError {
	return InvalidDigestError{
		APIError:   GetAPIError(ErrInvalidDigest),
		ContentMD5: contentMD5,
	}
}
