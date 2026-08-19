// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4auth

import (
	"crypto/hmac"
	"crypto/sha256"
)

// DeriveKey computes the SigV4 signing key (kSigning) for a secret access
// key and a request's credential scope:
//
//	kDate    = HMAC-SHA256("AWS4"+secret, yyyymmdd)
//	kRegion  = HMAC-SHA256(kDate, region)
//	kService = HMAC-SHA256(kRegion, service)
//	kSigning = HMAC-SHA256(kService, "aws4_request")
//
// This is the one artifact that's safe to hand across a process boundary: a
// standalone IAM service can compute and return it without ever exposing
// the secret itself. Every SigV4 consumer in this codebase (header auth,
// presigned/query auth, POST-policy, chunked upload) is built on top of this
// single implementation rather than each deriving its own key.
func DeriveKey(secret, yyyymmdd, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(yyyymmdd))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte(Terminal))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
