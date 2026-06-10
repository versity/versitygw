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
)

// RequestTimeTooSkewedError is returned when the request timestamp is too far from server time.
// Produces <RequestTime>, <ServerTime>, and <MaxAllowedSkewMilliseconds> fields.
type RequestTimeTooSkewedError struct {
	APIError
	RequestTime                string
	ServerTime                 string
	MaxAllowedSkewMilliseconds int
}

func (e RequestTimeTooSkewedError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName                    xml.Name `xml:"Error"`
		Code                       string
		Message                    string
		RequestTime                string
		ServerTime                 string
		MaxAllowedSkewMilliseconds int
		RequestID                  string `xml:"RequestId,omitempty"`
		HostID                     string `xml:"HostId,omitempty"`
	}{
		Code:                       e.Code,
		Message:                    e.Description,
		RequestTime:                e.RequestTime,
		ServerTime:                 e.ServerTime,
		MaxAllowedSkewMilliseconds: e.MaxAllowedSkewMilliseconds,
		RequestID:                  requestID,
		HostID:                     hostID,
	})
}

func (e RequestTimeTooSkewedError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "RequestTime", Value: e.RequestTime},
		ErrorField{Name: "ServerTime", Value: e.ServerTime},
		ErrorField{Name: "MaxAllowedSkewMilliseconds", Value: e.MaxAllowedSkewMilliseconds},
	)
}

func (e RequestTimeTooSkewedError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetRequestTimeTooSkewedErr(requestTime, serverTime string, maxAllowedMilliseconds int) RequestTimeTooSkewedError {
	return RequestTimeTooSkewedError{
		APIError:                   GetAPIError(ErrRequestTimeTooSkewed),
		RequestTime:                requestTime,
		ServerTime:                 serverTime,
		MaxAllowedSkewMilliseconds: maxAllowedMilliseconds,
	}
}
