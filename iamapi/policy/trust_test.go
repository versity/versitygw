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
	"testing"

	"github.com/versity/versitygw/iamapi/iamerr"
)

// Every case below was verified against a live AWS IAM account, except
// where noted as a deliberate simplification (see IAM_ROLES_IMPLEMENTATION_PLAN.md).
// The "ec2 service (unsupported)" case is one such deliberate deviation:
// real AWS accepts ec2.amazonaws.com, but this gateway only exposes S3,
// STS, and IAM APIs, so it restricts Service principals to those three.
func TestParseTrust(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr error // nil means ParseTrust must succeed
	}{
		{"valid AWS principal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`, nil},
		{"valid without version", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, nil},
		{"valid Service principal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, nil},
		{"valid multiple principal type keys together", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*","Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, nil},
		{"valid Federated non-cognito provider", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"bogus.example.com"},"Action":"sts:AssumeRole"}]}`, nil},
		{"valid non-AssumeRole sts action", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:TagSession"}]}`, nil},
		{"valid NotAction with sts prefix", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"NotAction":"sts:AssumeRole"}]}`, nil},
		{"valid action array all sts prefixed", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["sts:AssumeRole","sts:TagSession"]}]}`, nil},
		{"valid multiple unique sids", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},{"Sid":"B","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, nil},

		{"invalid json syntax", `{invalid json`, errTrustInvalidJSON},
		{"invalid version", `{"Version":"2020-01-01","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, errTrustInvalidVersion},
		{"empty statement array", `{"Version":"2012-10-17","Statement":[]}`, errTrustEmptyStatement},
		{"missing statement", `{"Version":"2012-10-17"}`, errTrustEmptyStatement},

		{"invalid effect value", `{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, iamerr.MalformedPolicyDocument("Invalid effect: Maybe")},
		{"missing effect field", `{"Version":"2012-10-17","Statement":[{"Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, errTrustMissingEffect},

		{"missing principal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`, errTrustMissingPrincipal},
		{"empty principal object", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{},"Action":"sts:AssumeRole"}]}`, errTrustEmptyPrincipal},
		{"principal as bare string", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`, errTrustPrincipalNotObject},
		{"principal as array", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":["a"],"Action":"sts:AssumeRole"}]}`, errTrustSyntax},
		{"principal has invalid key", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"CanonicalUser":"abc"},"Action":"sts:AssumeRole"}]}`, iamerr.MalformedPolicyDocument(`Invalid principal in policy: "CanonicalUser"`)},
		{"principal has unrecognized service", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"invalid.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, iamerr.MalformedPolicyDocument(`Invalid principal in policy: "SERVICE":"invalid.amazonaws.com"`)},
		{"principal has ec2 service (unsupported)", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, iamerr.MalformedPolicyDocument(`Invalid principal in policy: "SERVICE":"ec2.amazonaws.com"`)},

		{"allow with notprincipal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, errTrustAllowNotPrincipal},
		{"deny with notprincipal", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, errTrustNotPrincipalForbidden},

		{"missing action and notaction", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`, errTrustMissingAction},
		{"bare wildcard action rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"*"}]}`, errTrustNonSTSAction},
		{"non-sts vendor action rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`, errTrustNonSTSAction},
		{"non-sts notaction rejected even on deny", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"NotAction":"s3:GetObject"}]}`, errTrustNonSTSAction},

		{"resource forbidden", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Resource":"*"}]}`, errTrustResourceForbidden},
		{"notresource forbidden", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","NotResource":"*"}]}`, errTrustNotResourceForbidden},

		{"duplicate sid across statements", `{"Version":"2012-10-17","Statement":[{"Sid":"Dup","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},{"Sid":"Dup","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, errTrustDuplicateSid},

		{"cognito federated without condition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, errTrustCognitoConditionRequired},
		{"cognito federated with condition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:abc"}}}]}`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseTrust(tt.doc)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ParseTrust() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseTrust() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
