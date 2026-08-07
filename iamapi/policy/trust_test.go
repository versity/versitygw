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

// The "ec2 service (unsupported)" case is a deliberate deviation from real
// AWS: real AWS accepts ec2.amazonaws.com, but this gateway only exposes S3,
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
		{"both action and notaction rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","NotAction":"sts:AssumeRoleWithWebIdentity"}]}`, errTrustSyntax},
		{"bare wildcard action rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"*"}]}`, errTrustNonSTSAction},
		{"non-sts vendor action rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`, errTrustNonSTSAction},
		{"non-sts notaction rejected even on deny", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"NotAction":"s3:GetObject"}]}`, errTrustNonSTSAction},

		{"resource forbidden", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Resource":"*"}]}`, errTrustResourceForbidden},
		{"notresource forbidden", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","NotResource":"*"}]}`, errTrustNotResourceForbidden},

		{"duplicate sid across statements", `{"Version":"2012-10-17","Statement":[{"Sid":"Dup","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},{"Sid":"Dup","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`, errTrustDuplicateSid},

		{"cognito federated without condition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, errTrustCognitoConditionRequired},
		{"cognito federated with condition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:abc"}}}]}`, nil},
		// A condition block that doesn't actually scope the required aud
		// claim must still be rejected, even though a condition is present.
		{"cognito federated with unrelated condition (not aud) is still rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, errTrustCognitoConditionRequired},
		{"cognito federated with wildcard-only aud is still rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"*"}}}]}`, errTrustCognitoConditionRequired},

		// Known shared-audience OIDC CI/CD providers (GitHub Actions,
		// GitLab.com, Buildkite, Terraform Cloud) require a Condition scoping
		// their "sub" claim, the same way Cognito requires "aud" — their
		// audience is commonly left at a single non-secret shared default, so
		// it alone doesn't distinguish one tenant's workflow from another's.
		{"github actions federated without sub condition is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "token.actions.githubusercontent.com" without a Condition scoping "token.actions.githubusercontent.com:sub" to your own tenant.`)},
		{"github actions federated with wildcard-only sub is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"*"}}}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "token.actions.githubusercontent.com" without a Condition scoping "token.actions.githubusercontent.com:sub" to your own tenant.`)},
		{"github actions federated with scoped sub condition is accepted", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:my-org/my-repo:*"}}}]}`, nil},
		{"gitlab federated without sub condition is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "gitlab.com" without a Condition scoping "gitlab.com:sub" to your own tenant.`)},

		// Wildcard-only patterns must not satisfy a shared provider's
		// required scoping - AWS documents that the tenancy claim "must not
		// consist only of wildcard characters", not merely "must not be the
		// bare string '*'".
		{"github actions federated with double-wildcard sub is still rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"**"}}}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "token.actions.githubusercontent.com" without a Condition scoping "token.actions.githubusercontent.com:sub" to your own tenant.`)},
		{"github actions federated with single-char-wildcard sub is still rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"?"}}}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "token.actions.githubusercontent.com" without a Condition scoping "token.actions.githubusercontent.com:sub" to your own tenant.`)},
		{"github actions federated with mixed-wildcard-only sub is still rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"*?*"}}}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "token.actions.githubusercontent.com" without a Condition scoping "token.actions.githubusercontent.com:sub" to your own tenant.`)},
		// A StringEquals value of literally "**" isn't a wildcard operator
		// at all under that operator - it's compared as an exact literal
		// string that will never match a real sub claim - so only the
		// plain empty/"*" check applies to it, and "**" alone passes that.
		{"github actions federated with StringEquals literal double-asterisk is accepted (not a wildcard operator)", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"**"}}}]}`, nil},

		// Additional shared providers from AWS's published table, beyond
		// the original four.
		{"pulumi federated without aud condition is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/api.pulumi.com/oidc"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "api.pulumi.com/oidc" without a Condition scoping "api.pulumi.com/oidc:aud" to your own tenant.`)},
		{"pulumi federated with scoped aud condition is accepted", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/api.pulumi.com/oidc"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"api.pulumi.com/oidc:aud":"my-org"}}}]}`, nil},
		{"vercel federated without aud condition is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/oidc.vercel.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "oidc.vercel.com" without a Condition scoping "oidc.vercel.com:aud" to your own tenant.`)},
		{"upbound federated without sub condition is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/proidc.upbound.io"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "proidc.upbound.io" without a Condition scoping "proidc.upbound.io:sub" to your own tenant.`)},

		// Microsoft Sentinel is a shared provider whose required control is
		// the global sts:RoleSessionName key, not a claim on the token - a
		// non-claim control distinct from every other entry here.
		{"azure sentinel federated without RoleSessionName condition is rejected", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, iamerr.MalformedPolicyDocument(`The trust policy trusts shared OpenID Connect provider "sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d" without a Condition scoping "sts:RoleSessionName" to your own tenant.`)},
		{"azure sentinel federated with scoped RoleSessionName condition is accepted", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"sts:RoleSessionName":"my-workspace"}}}]}`, nil},

		// A private/self-hosted OIDC provider (not in the shared-provider
		// table) imposes no extra Condition requirement - its Url is already
		// tenant-specific, unlike the shared community providers above.
		{"private oidc provider federated without condition is accepted", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/idp.my-company.example.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, nil},

		{"valid condition, Null", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"Null":{"aws:username":"true"}}}]}`, nil},
		{"valid condition, Bool", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, nil},
		{"valid condition, NumericEquals", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"NumericEquals":{"example.com:level":"5"}}}]}`, nil},
		{"valid condition, ArnLike", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}}]}`, nil},
		{"valid condition, ForAllValues-qualified operator", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["a","b"]}}}]}`, nil},

		{"invalid condition, unrecognized operator", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"FooBarOperator":{"aws:username":"alice"}}}]}`, errTrustSyntax},
		{"invalid condition, malformed shape", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":"not an object"}]}`, errTrustSyntax},

		// A misspelled Statement field (as opposed to an unrecognized
		// Condition operator) is caught earlier, inside
		// Document.UnmarshalJSON's strict Statement decoding - reached
		// through ParseTrust's own top-level json.Unmarshal - so it
		// surfaces as errTrustInvalidJSON, not errTrustSyntax.
		{"misspelled Condition field is rejected, not silently ignored", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Conditon":{"StringEquals":{"aws:username":"alice"}}}]}`, errTrustInvalidJSON},
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
