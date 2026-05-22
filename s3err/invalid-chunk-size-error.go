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

// InvalidChunkSizeError is returned when a chunk size in a streaming upload is invalid.
// Produces <Chunk> and <BadChunkSize> fields in the XML response.
type InvalidChunkSizeError struct {
	APIError
	Chunk        int
	BadChunkSize int64
}

func (e InvalidChunkSizeError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName      xml.Name `xml:"Error"`
		Code         string
		Message      string
		Chunk        int    `xml:",omitempty"`
		BadChunkSize int64  `xml:",omitempty"`
		RequestID    string `xml:"RequestId,omitempty"`
		HostID       string `xml:"HostId,omitempty"`
	}{
		Code:         e.Code,
		Message:      e.Description,
		Chunk:        e.Chunk,
		BadChunkSize: e.BadChunkSize,
		RequestID:    requestID,
		HostID:       hostID,
	})
}

func (e InvalidChunkSizeError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetInvalidChunkSizeErr(chunk int, badChunkSize int64) InvalidChunkSizeError {
	return InvalidChunkSizeError{
		APIError:     GetAPIError(ErrInvalidChunkSize),
		Chunk:        chunk,
		BadChunkSize: badChunkSize,
	}
}
