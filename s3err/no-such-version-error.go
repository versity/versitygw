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

// NoSuchVersionError is returned when the specified version does not exist.
// Produces <Key> and <VersionId> fields in the XML response.
type NoSuchVersionError struct {
	APIError
	Key       string
	VersionId string
}

func (e NoSuchVersionError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string
		Message   string
		Key       string `xml:",omitempty"`
		VersionId string `xml:",omitempty"`
		RequestID string `xml:"RequestId,omitempty"`
		HostID    string `xml:"HostId,omitempty"`
	}{
		Code:      e.Code,
		Message:   e.Description,
		Key:       e.Key,
		VersionId: e.VersionId,
		RequestID: requestID,
		HostID:    hostID,
	})
}

func (e NoSuchVersionError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "Key", Value: e.Key},
		ErrorField{Name: "VersionId", Value: e.VersionId},
	)
}

func (e NoSuchVersionError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetNoSuchVersionErr(key, versionId string) NoSuchVersionError {
	return NoSuchVersionError{
		APIError:  GetAPIError(ErrNoSuchVersion),
		Key:       key,
		VersionId: versionId,
	}
}
