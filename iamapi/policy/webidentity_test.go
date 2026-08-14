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

import "testing"

const testProviderArn = "arn:aws:iam::000000000000:oidc-provider/example.com"
const otherProviderArn = "arn:aws:iam::000000000000:oidc-provider/other.com"

// existingProviders resolves testProviderArn -> "example.com" and
// otherProviderArn -> "other.com"; any other ARN reports not-found,
// modeling a dangling trust-policy reference to a provider that was never
// created (or has since been deleted).
func existingProviders(arn string) (string, bool) {
	switch arn {
	case testProviderArn:
		return "example.com", true
	case otherProviderArn:
		return "other.com", true
	default:
		return "", false
	}
}

func TestEvaluateWebIdentityTrust(t *testing.T) {
	tests := []struct {
		name       string
		document   string
		wctx       WebIdentityContext
		wantResult WebIdentityMatch
		wantArn    string
	}{
		{
			name: "simple allow, no condition",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "aud1"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name: "wildcard action matches",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:*"}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name: "action does not match",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRole"}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: NoPrincipal,
		},
		{
			name: "dangling federated reference to a provider that doesn't exist",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/never-created.example.com"},
				"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: NoPrincipal,
		},
		{
			name: "existing provider referenced but issuer doesn't match",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			wctx:       WebIdentityContext{ProviderURL: "unregistered.example.com"},
			wantResult: NoIssuerMatch,
		},
		{
			name: "condition matches",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"StringEquals":{"example.com:aud":"client1"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "client1"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name: "condition does not match",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"StringEquals":{"example.com:aud":"client1"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "wrong-client"},
			wantResult: ConditionFailed,
		},
		{
			name: "explicit deny overrides matching allow",
			document: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"Federated":"` + testProviderArn + `"},"Action":"sts:AssumeRoleWithWebIdentity"},
				{"Effect":"Deny","Principal":{"Federated":"` + testProviderArn + `"},"Action":"sts:AssumeRoleWithWebIdentity"}
			]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: ExplicitlyDenied,
		},
		{
			name: "deny for a different provider does not affect allow for this one",
			document: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"Federated":"` + testProviderArn + `"},"Action":"sts:AssumeRoleWithWebIdentity"},
				{"Effect":"Deny","Principal":{"Federated":"` + otherProviderArn + `"},"Action":"sts:AssumeRoleWithWebIdentity"}
			]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name: "second statement matches when first references a different provider",
			document: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"Federated":"` + otherProviderArn + `"},"Action":"sts:AssumeRoleWithWebIdentity"},
				{"Effect":"Allow","Principal":{"Federated":"` + testProviderArn + `"},"Action":"sts:AssumeRoleWithWebIdentity"}
			]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name:       "malformed document",
			document:   `not json`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: NoPrincipal,
		},
		{
			// A Condition operator this package doesn't recognize (simulating
			// a legacy document stored before write-time validation existed)
			// must deny rather than being silently skipped or evaluated. The
			// ValidateTrust re-check catches this before per-statement
			// evaluation even runs, reported as NoPrincipal - the same
			// "assign no meaning to an invalid document" outcome as an
			// unresolvable Federated principal, and mapped to the identical
			// AccessDenied response as ExplicitlyDenied by the controller.
			name: "unrecognized operator on a matching statement denies",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"FooBarOperator":{"example.com:aud":"client1"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "client1"},
			wantResult: NoPrincipal,
		},
		{
			// Claims are genuinely multivalued in production (a token can
			// carry a "groups": ["admin","banned"] claim), unlike
			// RequestContext.Condition on the identity-policy side - this
			// is the most realistic place to exercise the multivalue
			// aggregation semantics documented on aggregate() in
			// internal/condition. "banned" is present among the claim's values,
			// so unqualified StringNotEquals (pre-existing, unchanged
			// semantics: fails to match if any actual value matches) fails
			// to match, and the Allow's condition doesn't hold.
			name: "StringNotEquals against a genuinely multivalued claim doesn't match when any value matches",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"StringNotEquals":{"example.com:groups":"banned"}}}]}`,
			wctx: WebIdentityContext{
				ProviderURL: "example.com",
				Claims:      map[string][]string{"groups": {"admin", "banned"}},
			},
			wantResult: ConditionFailed,
		},
		{
			name: "Null operator against a claim that's present",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"Null":{"example.com:amr":"false"}}}]}`,
			wctx: WebIdentityContext{
				ProviderURL: "example.com",
				Claims:      map[string][]string{"amr": {"mfa"}},
			},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name: "Null operator against a claim that's absent",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"Null":{"example.com:amr":"false"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com"},
			wantResult: ConditionFailed,
		},
		// A broad Allow plus an explicit Deny scoped to a global request key
		// (aws:SourceIp, aws:SecureTransport, sts:RoleSessionName) must see
		// the same request facts an Allow would, so a Deny relying on any
		// of them overrides the broad Allow.
		{
			name: "Deny on aws:SourceIp applies when the caller's address matches",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Deny",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "aud1", SourceIP: "203.0.113.5"},
			wantResult: ExplicitlyDenied,
		},
		{
			name: "Deny on aws:SourceIp does not apply for a different address",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Deny",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "aud1", SourceIP: "198.51.100.5"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
		{
			name: "Deny on aws:SecureTransport=false applies to a plaintext request",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Deny",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "aud1", Secure: false},
			wantResult: ExplicitlyDenied,
		},
		{
			name: "Deny on sts:RoleSessionName applies when it matches",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Deny",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"StringEquals":{"sts:RoleSessionName":"forbidden-session"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "aud1", RoleSessionName: "forbidden-session"},
			wantResult: ExplicitlyDenied,
		},
		{
			name: "Deny on sts:RoleSessionName does not apply for a different session name",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Deny",
				"Principal":{"Federated":"` + testProviderArn + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"StringEquals":{"sts:RoleSessionName":"forbidden-session"}}}]}`,
			wctx:       WebIdentityContext{ProviderURL: "example.com", Audience: "aud1", RoleSessionName: "allowed-session"},
			wantResult: Allowed,
			wantArn:    testProviderArn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, arn := EvaluateWebIdentityTrust(tt.document, existingProviders, tt.wctx)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v", result, tt.wantResult)
			}
			if arn != tt.wantArn {
				t.Errorf("providerArn = %q, want %q", arn, tt.wantArn)
			}
		})
	}
}

func TestMatchActionPattern(t *testing.T) {
	tests := []struct {
		pattern string
		action  string
		want    bool
	}{
		{pattern: "sts:AssumeRoleWithWebIdentity", action: "sts:AssumeRoleWithWebIdentity", want: true},
		{pattern: "sts:*", action: "sts:AssumeRoleWithWebIdentity", want: true},
		{pattern: "sts:AssumeRole*", action: "sts:AssumeRoleWithWebIdentity", want: true},
		{pattern: "STS:ASSUMEROLEWITHWEBIDENTITY", action: "sts:AssumeRoleWithWebIdentity", want: true},
		{pattern: "sts:AssumeRole", action: "sts:AssumeRoleWithWebIdentity", want: false},
		{pattern: "iam:*", action: "sts:AssumeRoleWithWebIdentity", want: false},
		{pattern: "sts:AssumeRoleWithWebIdentit?", action: "sts:AssumeRoleWithWebIdentity", want: true},
	}
	for _, tt := range tests {
		if got := matchActionPattern(tt.pattern, tt.action); got != tt.want {
			t.Errorf("matchActionPattern(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}
