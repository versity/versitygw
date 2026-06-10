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

// ExpiredPresignedURLError is returned when the presigned url is expired
// Produces <ServerTime>, <X-Amz-Expires> and <Expires> fields in the XML response.
type ExpiredPresignedURLError struct {
	APIError
	ServerTime  string
	XAmzExpires int
	Expires     string
}

func (e ExpiredPresignedURLError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName     xml.Name `xml:"Error"`
		Code        string
		Message     string
		ServerTime  string `xml:",omitempty"`
		XAmzExpires int    `xml:"X-Amz-Expires,omitempty"`
		Expires     string `xml:",omitempty"`
		RequestID   string `xml:"RequestId,omitempty"`
		HostID      string `xml:"HostId,omitempty"`
	}{
		Code:        e.Code,
		Message:     e.Description,
		ServerTime:  e.ServerTime,
		XAmzExpires: e.XAmzExpires,
		Expires:     e.Expires,
		RequestID:   requestID,
		HostID:      hostID,
	})
}

func (e ExpiredPresignedURLError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "ServerTime", Value: e.ServerTime},
		ErrorField{Name: "X-Amz-Expires", Value: e.XAmzExpires},
		ErrorField{Name: "Expires", Value: e.Expires},
	)
}

func (e ExpiredPresignedURLError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetExpiredPresignedURLError(XAmzExpires int, expires, serverTime string) ExpiredPresignedURLError {
	return ExpiredPresignedURLError{
		APIError:    GetAPIError(ErrExpiredPresignRequest),
		XAmzExpires: XAmzExpires,
		Expires:     expires,
		ServerTime:  serverTime,
	}
}
