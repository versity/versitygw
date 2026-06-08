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

// MaxMessageLengthExceeded is returned when the request size exceeds the maximum limit
// Produces the <MaxMessageLengthBytes> field in the XML response.
type MaxMessageLengthExceeded struct {
	APIError
	MaxMessageLengthBytes int64
}

func (e MaxMessageLengthExceeded) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName               xml.Name `xml:"Error"`
		Code                  string
		Message               string
		MaxMessageLengthBytes int64  `xml:",omitempty"`
		RequestID             string `xml:"RequestId,omitempty"`
		HostID                string `xml:"HostId,omitempty"`
	}{
		Code:                  e.Code,
		Message:               e.Description,
		MaxMessageLengthBytes: e.MaxMessageLengthBytes,
		RequestID:             requestID,
		HostID:                hostID,
	})
}

func (e MaxMessageLengthExceeded) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "MaxMessageLengthBytes", Value: e.MaxMessageLengthBytes},
	)
}

func (e MaxMessageLengthExceeded) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetMaxMessageLengthExceeded(maxMessageLengthBytes int64) MaxMessageLengthExceeded {
	return MaxMessageLengthExceeded{
		APIError:              GetAPIError(ErrMaxMessageLengthExceeded),
		MaxMessageLengthBytes: maxMessageLengthBytes,
	}
}
