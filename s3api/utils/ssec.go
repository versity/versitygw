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

package utils

import (
	"crypto/md5"
	"encoding/base64"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

const (
	ssecAlgorithmHdr    = "X-Amz-Server-Side-Encryption-Customer-Algorithm"
	ssecKeyHdr          = "X-Amz-Server-Side-Encryption-Customer-Key"
	ssecKeyMD5Hdr       = "X-Amz-Server-Side-Encryption-Customer-Key-Md5"
	srcSSECAlgorithmHdr = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm"
	srcSSECKeyHdr       = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"
	srcSSECKeyMD5Hdr    = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5"
)

// SSECHeaders holds the SSE-C (server-side encryption with
// customer-provided keys) request values. Unset values are nil.
type SSECHeaders struct {
	Algorithm *string
	Key       *string
	KeyMD5    *string
}

// ValidateSSEHeaders rejects SSE-C combined with another encryption method
// and encryption methods that this gateway cannot honor.
func ValidateSSEHeaders(ssec SSECHeaders, serverSideEncryption string) error {
	if serverSideEncryption == "" {
		return nil
	}
	if ssec.Algorithm != nil || ssec.Key != nil || ssec.KeyMD5 != nil {
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECIncompatibleEncryption, serverSideEncryption)
	}
	switch serverSideEncryption {
	case "AES256", "aws:kms", "aws:kms:dsse":
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	default:
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgSSEInvalidEncryptionMethod, "")
	}
}

// ExtractSSECHeaders reads SSE-C request headers without validating them.
func ExtractSSECHeaders(ctx fiber.Ctx) SSECHeaders {
	return SSECHeaders{
		Algorithm: GetStringPtr(ctx.Get(ssecAlgorithmHdr)),
		Key:       GetStringPtr(ctx.Get(ssecKeyHdr)),
		KeyMD5:    GetStringPtr(ctx.Get(ssecKeyMD5Hdr)),
	}
}

// ParseSSECHeaders extracts and validates the
// x-amz-server-side-encryption-customer-* request headers.
func ParseSSECHeaders(ctx fiber.Ctx) (SSECHeaders, error) {
	h := ExtractSSECHeaders(ctx)
	return h, h.validate(false)
}

// ParseCopySourceSSECHeaders extracts and validates the
// x-amz-copy-source-server-side-encryption-customer-* request headers.
func ParseCopySourceSSECHeaders(ctx fiber.Ctx) (SSECHeaders, error) {
	h := SSECHeaders{
		Algorithm: GetStringPtr(ctx.Get(srcSSECAlgorithmHdr)),
		Key:       GetStringPtr(ctx.Get(srcSSECKeyHdr)),
		KeyMD5:    GetStringPtr(ctx.Get(srcSSECKeyMD5Hdr)),
	}
	return h, h.validate(true)
}

// ParseSSECFields extracts and validates the SSE-C values from POST object
// form fields, whose names are expected to be lowercased.
func ParseSSECFields(fields map[string]string) (SSECHeaders, error) {
	h := SSECHeaders{
		Algorithm: GetStringPtr(fields[strings.ToLower(ssecAlgorithmHdr)]),
		Key:       GetStringPtr(fields[strings.ToLower(ssecKeyHdr)]),
		KeyMD5:    GetStringPtr(fields[strings.ToLower(ssecKeyMD5Hdr)]),
	}
	return h, h.validate(false)
}

// validate requires either none or a complete, consistent set of SSE-C
// values. copySource selects the x-amz-copy-source-* argument names.
func (h SSECHeaders) validate(copySource bool) error {
	if h.Algorithm == nil && h.Key == nil && h.KeyMD5 == nil {
		return nil
	}

	src := ""
	if copySource {
		src = "copy source "
	}

	invalidArg := func(code s3err.InvalidArgErrorCode) error {
		err := s3err.GetInvalidArgumentErr(code, "")
		err.ArgumentName = "x-amz-server-side-encryption"
		return err
	}

	if h.Algorithm == nil {
		debuglogger.Logf("SSE-C request missing %scustomer algorithm", src)
		return invalidArg(s3err.InvalidArgSSECMissingAlgorithm)
	}
	if *h.Algorithm != "AES256" {
		debuglogger.Logf("invalid SSE-C %scustomer algorithm: %q", src, *h.Algorithm)
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECInvalidAlgorithm, *h.Algorithm)
	}
	if h.Key == nil {
		debuglogger.Logf("SSE-C request missing %scustomer key", src)
		return invalidArg(s3err.InvalidArgSSECMissingKey)
	}
	key, err := base64.StdEncoding.DecodeString(*h.Key)
	if err != nil || len(key) != 32 {
		debuglogger.Logf("invalid SSE-C %scustomer key", src)
		return invalidArg(s3err.InvalidArgSSECInvalidKey)
	}
	if h.KeyMD5 == nil {
		debuglogger.Logf("SSE-C request missing %scustomer key MD5", src)
		return invalidArg(s3err.InvalidArgSSECMissingKeyMD5)
	}
	sum := md5.Sum(key)
	if *h.KeyMD5 != base64.StdEncoding.EncodeToString(sum[:]) {
		debuglogger.Logf("SSE-C %scustomer key MD5 mismatch", src)
		return invalidArg(s3err.InvalidArgSSECKeyMD5Mismatch)
	}
	return nil
}
