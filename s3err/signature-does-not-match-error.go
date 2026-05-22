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

// SignatureDoesNotMatchError is returned when request signature verification fails.
// Produces diagnostic fields to help callers debug the mismatch.
type SignatureDoesNotMatchError struct {
	APIError
	AWSAccessKeyId        string
	StringToSign          string
	SignatureProvided     string
	StringToSignBytes     string
	CanonicalRequest      string
	CanonicalRequestBytes string
}

func (e SignatureDoesNotMatchError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName               xml.Name `xml:"Error"`
		Code                  string
		Message               string
		AWSAccessKeyId        string `xml:",omitempty"`
		StringToSign          string `xml:",omitempty"`
		SignatureProvided     string `xml:",omitempty"`
		StringToSignBytes     string `xml:",omitempty"`
		CanonicalRequest      string `xml:",omitempty"`
		CanonicalRequestBytes string `xml:",omitempty"`
		RequestID             string `xml:"RequestId,omitempty"`
		HostID                string `xml:"HostId,omitempty"`
	}{
		Code:                  e.Code,
		Message:               e.Description,
		AWSAccessKeyId:        e.AWSAccessKeyId,
		StringToSign:          e.StringToSign,
		SignatureProvided:     e.SignatureProvided,
		StringToSignBytes:     e.StringToSignBytes,
		CanonicalRequest:      e.CanonicalRequest,
		CanonicalRequestBytes: e.CanonicalRequestBytes,
		RequestID:             requestID,
		HostID:                hostID,
	})
}

func (e SignatureDoesNotMatchError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetSignatureDoesNotMatchErr(accessKeyId, stringToSign, signatureProvided, stringToSignBytes, canonicalRequest, canonicalRequestBytes string) SignatureDoesNotMatchError {
	return SignatureDoesNotMatchError{
		APIError:              GetAPIError(ErrSignatureDoesNotMatch),
		AWSAccessKeyId:        accessKeyId,
		StringToSign:          stringToSign,
		SignatureProvided:     signatureProvided,
		StringToSignBytes:     stringToSignBytes,
		CanonicalRequest:      canonicalRequest,
		CanonicalRequestBytes: canonicalRequestBytes,
	}
}
