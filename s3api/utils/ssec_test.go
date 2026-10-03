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
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/versity/versitygw/s3err"
)

func TestSSECHeadersValidate(t *testing.T) {
	rawKey := bytes.Repeat([]byte{0x42}, 32)
	sum := md5.Sum(rawKey)
	key := base64.StdEncoding.EncodeToString(rawKey)
	keyMD5 := base64.StdEncoding.EncodeToString(sum[:])
	shortKey := base64.StdEncoding.EncodeToString(rawKey[:16])
	shortSum := md5.Sum(rawKey[:16])
	shortKeyMD5 := base64.StdEncoding.EncodeToString(shortSum[:])

	invalidArg := func(code s3err.InvalidArgErrorCode) error {
		err := s3err.GetInvalidArgumentErr(code, "")
		err.ArgumentName = "x-amz-server-side-encryption"
		return err
	}

	tests := []struct {
		name       string
		headers    SSECHeaders
		copySource bool
		want       error
	}{
		{name: "none", headers: SSECHeaders{}},
		{name: "complete", headers: SSECHeaders{Algorithm: GetStringPtr("AES256"), Key: &key, KeyMD5: &keyMD5}},
		{name: "algorithm only", headers: SSECHeaders{Algorithm: GetStringPtr("AES256")},
			want: invalidArg(s3err.InvalidArgSSECMissingKey)},
		{name: "key only", headers: SSECHeaders{Key: &key},
			want: invalidArg(s3err.InvalidArgSSECMissingAlgorithm)},
		{name: "md5 only", headers: SSECHeaders{KeyMD5: &keyMD5},
			want: invalidArg(s3err.InvalidArgSSECMissingAlgorithm)},
		{name: "missing md5", headers: SSECHeaders{Algorithm: GetStringPtr("AES256"), Key: &key},
			want: invalidArg(s3err.InvalidArgSSECMissingKeyMD5)},
		{name: "invalid algorithm", headers: SSECHeaders{Algorithm: GetStringPtr("AES128"), Key: &key, KeyMD5: &keyMD5},
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECInvalidAlgorithm, "AES128")},
		{name: "lowercase algorithm", headers: SSECHeaders{Algorithm: GetStringPtr("aes256"), Key: &key, KeyMD5: &keyMD5},
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECInvalidAlgorithm, "aes256")},
		{name: "short key", headers: SSECHeaders{Algorithm: GetStringPtr("AES256"), Key: &shortKey, KeyMD5: &shortKeyMD5},
			want: invalidArg(s3err.InvalidArgSSECInvalidKey)},
		{name: "key not base64", headers: SSECHeaders{Algorithm: GetStringPtr("AES256"), Key: GetStringPtr("not-base64!"), KeyMD5: &keyMD5},
			want: invalidArg(s3err.InvalidArgSSECInvalidKey)},
		{name: "md5 mismatch", headers: SSECHeaders{Algorithm: GetStringPtr("AES256"), Key: &key, KeyMD5: &shortKeyMD5},
			want: invalidArg(s3err.InvalidArgSSECKeyMD5Mismatch)},
		{name: "copy source missing key", headers: SSECHeaders{Algorithm: GetStringPtr("AES256")}, copySource: true,
			want: invalidArg(s3err.InvalidArgSSECMissingKey)},
		{name: "copy source invalid algorithm", headers: SSECHeaders{Algorithm: GetStringPtr("AES128")}, copySource: true,
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECInvalidAlgorithm, "AES128")},
		{name: "copy source md5 mismatch", headers: SSECHeaders{Algorithm: GetStringPtr("AES256"), Key: &key, KeyMD5: &shortKeyMD5}, copySource: true,
			want: invalidArg(s3err.InvalidArgSSECKeyMD5Mismatch)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.headers.validate(tt.copySource)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %v, got nil", tt.want)
			}
			if !errors.Is(err, tt.want) && err.Error() != tt.want.Error() {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateSSEHeaders(t *testing.T) {
	ssec := SSECHeaders{
		Algorithm: GetStringPtr("AES256"),
		Key:       GetStringPtr("key"),
		KeyMD5:    GetStringPtr("md5"),
	}
	tests := []struct {
		name                 string
		headers              SSECHeaders
		serverSideEncryption string
		want                 error
	}{
		{name: "no encryption", headers: SSECHeaders{}},
		{name: "SSE-S3", headers: SSECHeaders{}, serverSideEncryption: "AES256", want: s3err.GetAPIError(s3err.ErrNotImplemented)},
		{name: "KMS", headers: SSECHeaders{}, serverSideEncryption: "aws:kms", want: s3err.GetAPIError(s3err.ErrNotImplemented)},
		{name: "KMS DSSE", headers: SSECHeaders{}, serverSideEncryption: "aws:kms:dsse", want: s3err.GetAPIError(s3err.ErrNotImplemented)},
		{name: "SSE-C and SSE-S3", headers: ssec, serverSideEncryption: "AES256",
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECIncompatibleEncryption, "AES256")},
		{name: "SSE-C and other encryption", headers: ssec, serverSideEncryption: "other",
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECIncompatibleEncryption, "other")},
		{name: "SSE-C and KMS", headers: ssec, serverSideEncryption: "aws:kms",
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECIncompatibleEncryption, "aws:kms")},
		{name: "invalid encryption method", headers: SSECHeaders{}, serverSideEncryption: "invalid",
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSEInvalidEncryptionMethod, "")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSEHeaders(tt.headers, tt.serverSideEncryption)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.want) && (err == nil || err.Error() != tt.want.Error()) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}
