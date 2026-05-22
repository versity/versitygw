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

// ContentSHA256MismatchError is returned when the x-amz-content-sha256 header does not match
// the computed hash of the request payload.
// Produces <ClientComputedContentSHA256> and <S3ComputedContentSHA256> fields.
type ContentSHA256MismatchError struct {
	APIError
	ClientComputedContentSHA256 string
	S3ComputedContentSHA256     string
}

func (e ContentSHA256MismatchError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName                     xml.Name `xml:"Error"`
		Code                        string
		Message                     string
		ClientComputedContentSHA256 string `xml:",omitempty"`
		S3ComputedContentSHA256     string `xml:",omitempty"`
		RequestID                   string `xml:"RequestId,omitempty"`
		HostID                      string `xml:"HostId,omitempty"`
	}{
		Code:                        e.Code,
		Message:                     e.Description,
		ClientComputedContentSHA256: e.ClientComputedContentSHA256,
		S3ComputedContentSHA256:     e.S3ComputedContentSHA256,
		RequestID:                   requestID,
		HostID:                      hostID,
	})
}

func (e ContentSHA256MismatchError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetContentSHA256MismatchErr(clientHash, s3Hash string) ContentSHA256MismatchError {
	return ContentSHA256MismatchError{
		APIError:                    GetAPIError(ErrContentSHA256Mismatch),
		ClientComputedContentSHA256: clientHash,
		S3ComputedContentSHA256:     s3Hash,
	}
}
