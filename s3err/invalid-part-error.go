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

// InvalidPartError is returned when one or more specified parts cannot be found.
// Produces <UploadId>, <PartNumber>, and <ETag> fields in the XML response.
type InvalidPartError struct {
	APIError
	UploadId   string
	PartNumber int32
	ETag       string
}

func (e InvalidPartError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName    xml.Name `xml:"Error"`
		Code       string
		Message    string
		UploadId   string `xml:",omitempty"`
		PartNumber int32  `xml:",omitempty"`
		ETag       string `xml:",omitempty"`
		RequestID  string `xml:"RequestId,omitempty"`
		HostID     string `xml:"HostId,omitempty"`
	}{
		Code:       e.Code,
		Message:    e.Description,
		UploadId:   e.UploadId,
		PartNumber: e.PartNumber,
		ETag:       e.ETag,
		RequestID:  requestID,
		HostID:     hostID,
	})
}

func (e InvalidPartError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetInvalidPartErr(uploadId string, partNumber int32, etag string) InvalidPartError {
	return InvalidPartError{
		APIError:   GetAPIError(ErrInvalidPart),
		UploadId:   uploadId,
		PartNumber: partNumber,
		ETag:       etag,
	}
}
