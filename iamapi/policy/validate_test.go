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

package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/versity/versitygw/iamapi/iamerr"
)

// Every case below was verified against a live AWS IAM account.
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr error // nil means Validate must succeed
	}{
		{"valid single statement", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, nil},
		{"valid statement as single object, not array", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`, nil},
		{"valid without version", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, nil},
		{"valid bare wildcard action and resource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, nil},
		{"valid NotAction alone", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}]}`, nil},
		{"valid NotResource alone", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotResource":"*"}]}`, nil},
		{"valid unrecognized vendor/action accepted", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"totallyfakeservice:DoSomething","Resource":"*"}]}`, nil},
		{"valid multiple unique sids", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"B","Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`, nil},
		{"valid action array", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"]}]}`, nil},

		{"invalid json syntax", `{invalid json`, errSyntax},
		{"empty object", `{}`, errSyntax},
		{"invalid version", `{"Version":"2020-01-01","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, errSyntax},
		{"missing statement", `{"Version":"2012-10-17"}`, errSyntax},
		{"null statement", `{"Version":"2012-10-17","Statement":null}`, errSyntax},
		{"empty statement array", `{"Version":"2012-10-17","Statement":[]}`, errSyntax},
		{"statement is a string", `{"Version":"2012-10-17","Statement":"hello"}`, errSyntax},
		{"missing effect", `{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Resource":"*"}]}`, errSyntax},
		{"invalid effect value", `{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"s3:GetObject","Resource":"*"}]}`, errSyntax},
		{"action and notaction both present", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"*"}]}`, errSyntax},
		{"resource and notresource both present", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","NotResource":"foo"}]}`, errSyntax},
		{"numeric action wrong type", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":123,"Resource":"*"}]}`, errSyntax},

		{"missing action and notaction", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"*"}]}`, errMissingActions},

		{"missing resource and notresource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`, errMissingResources},
		{"empty resource array", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":[]}]}`, errMissingResources},

		{"empty string action", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"","Resource":"*"}]}`, errMissingVendorPrefix},
		{"action missing vendor colon", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"GetObject","Resource":"*"}]}`, errMissingVendorPrefix},

		{"principal present", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`, errPrincipalNotAllowed},
		{"notprincipal present", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":"*","Action":"s3:GetObject","Resource":"*"}]}`, errPrincipalNotAllowed},

		{"duplicate sid across statements", `{"Version":"2012-10-17","Statement":[{"Sid":"Dup","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"Dup","Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`, errDuplicateSid},

		{"empty vendor prefix", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":":GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Vendor  is not valid")},
		{"vendor with invalid character", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam :Get","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Vendor iam  is not valid")},

		{"resource with no colon at all", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"invalid"}]}`, iamerr.MalformedPolicyDocument(`Resource invalid must be in ARN format or "*".`)},
		{"resource with colon but no arn prefix", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"s3::example-bucket/*"}]}`, iamerr.MalformedPolicyDocument(`Partition "" is not valid for resource "arn::example-bucket/*:*:*:*".`)},
		{"resource with arn prefix but too few fields", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:awss3::example-bucket/*"}]}`, errLegacyParsing},
		{"resource with invalid partition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws2:s3:::example-bucket/*"}]}`, iamerr.MalformedPolicyDocument(`Partition "aws2" is not valid for resource "arn:aws2:s3:::example-bucket/*".`)},
		{"notresource with invalid shape", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotResource":"invalid"}]}`, iamerr.MalformedPolicyDocument(`Resource invalid must be in ARN format or "*".`)},
		{"principal only, no action or resource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/bob"}}]}`, errPrincipalNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Parse(tt.doc)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSize(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{"valid small document", `{}`, nil},
		{"tab, newline, and carriage return allowed", "a\tb\nc\rd", nil},
		{"empty", "", iamerr.InvalidCharset("policyDocument")},
		{"exactly at max length", strings.Repeat("x", MaxDocumentLength), nil},
		{"one over max length", strings.Repeat("x", MaxDocumentLength+1), iamerr.ValueTooLong("policyDocument", MaxDocumentLength)},
		{"non-latin1 rune rejected", "emoji\U0001F600test", iamerr.InvalidCharset("policyDocument")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate("policyDocument", tt.raw)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateSize() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateSize() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
