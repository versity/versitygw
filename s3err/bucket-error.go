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

// BucketError is returned for errors that include the bucket name.
// Produces a <BucketName> field in the XML response.
type BucketError struct {
	APIError
	BucketName string
}

func (e BucketError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName    xml.Name `xml:"Error"`
		Code       string
		Message    string
		BucketName string
		RequestID  string `xml:"RequestId,omitempty"`
		HostID     string `xml:"HostId,omitempty"`
	}{
		Code:       e.Code,
		Message:    e.Description,
		BucketName: e.BucketName,
		RequestID:  requestID,
		HostID:     hostID,
	})
}

func (e BucketError) HTMLBody(requestID, hostID string) []byte {
	return e.APIError.encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "BucketName", Value: e.BucketName},
	)
}

func (e BucketError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

// GetBucketErr creates a BucketError for the given error code and bucket name.
// Use for: ErrNoSuchBucketPolicy, ErrOwnershipControlsNotFound, ErrBucketNotEmpty,
// ErrNoSuchCORSConfiguration, and similar errors that should include the bucket name.
func GetBucketErr(code ErrorCode, bucket string) BucketError {
	return BucketError{
		APIError:   GetAPIError(code),
		BucketName: bucket,
	}
}
