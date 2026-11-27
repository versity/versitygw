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
	"slices"
	"testing"
)

const (
	testAccountID  = "000000000000"
	testRootArn    = "arn:aws:iam::000000000000:root"
	testUserArn    = "arn:aws:iam::000000000000:user/alice"
	testRoleArn    = "arn:aws:iam::000000000000:role/team/caller"
	testSessionArn = "arn:aws:sts::000000000000:assumed-role/caller/sess1"
)

var (
	testUserCaller    = AssumeRoleCaller{AccountID: testAccountID, UserArn: testUserArn}
	testSessionCaller = AssumeRoleCaller{AccountID: testAccountID, RoleArn: testRoleArn, SessionArn: testSessionArn}
	// A session whose role is gone is named by neither of its ARNs.
	testOrphanCaller = AssumeRoleCaller{AccountID: testAccountID}
)

func trustAllow(principal string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRole"}]}`
}

func TestEvaluateAssumeRoleTrustPrincipalForms(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		caller    AssumeRoleCaller
		want      TrustGrant
	}{
		{"account root delegates to a user", `{"AWS":"` + testRootArn + `"}`, testUserCaller, TrustAccount},
		{"bare account id delegates to a user", `{"AWS":"` + testAccountID + `"}`, testUserCaller, TrustAccount},
		{"account root delegates to a session", `{"AWS":"` + testRootArn + `"}`, testSessionCaller, TrustAccount},
		{"user arn grants the user directly", `{"AWS":"` + testUserArn + `"}`, testUserCaller, TrustDirect},
		{"another user's arn grants nothing", `{"AWS":"arn:aws:iam::000000000000:user/bob"}`, testUserCaller, TrustNone},
		{"user arn in another case grants nothing", `{"AWS":"arn:aws:iam::000000000000:user/ALICE"}`, testUserCaller, TrustNone},
		{"user arn grants nothing to a session", `{"AWS":"` + testUserArn + `"}`, testSessionCaller, TrustNone},
		{"wildcard grants a user directly", `{"AWS":"*"}`, testUserCaller, TrustDirect},
		{"wildcard grants a session directly", `{"AWS":"*"}`, testSessionCaller, TrustDirect},
		{"role arn grants its sessions", `{"AWS":"` + testRoleArn + `"}`, testSessionCaller, TrustRole},
		{"role arn without its path grants nothing", `{"AWS":"arn:aws:iam::000000000000:role/caller"}`, testSessionCaller, TrustNone},
		{"role arn grants nothing to a user", `{"AWS":"` + testRoleArn + `"}`, testUserCaller, TrustNone},
		{"session arn grants that session directly", `{"AWS":"` + testSessionArn + `"}`, testSessionCaller, TrustDirect},
		{"another session's arn grants nothing", `{"AWS":"arn:aws:sts::000000000000:assumed-role/caller/sess2"}`, testSessionCaller, TrustNone},
		{"strongest principal in an array wins", `{"AWS":["` + testRootArn + `","` + testRoleArn + `","` + testSessionArn + `"]}`, testSessionCaller, TrustDirect},
		{"role and account together grant as the role", `{"AWS":["` + testRootArn + `","` + testRoleArn + `"]}`, testSessionCaller, TrustRole},
		{"another account's root grants nothing", `{"AWS":"arn:aws:iam::111111111111:root"}`, testUserCaller, TrustNone},
		{"service principal grants nothing", `{"Service":"sts.amazonaws.com"}`, testUserCaller, TrustNone},
		{"federated principal grants nothing", `{"Federated":"arn:aws:iam::000000000000:oidc-provider/example.com"}`, testUserCaller, TrustNone},
		{"orphaned session is not named by its role arn", `{"AWS":"` + testRoleArn + `"}`, testOrphanCaller, TrustNone},
		{"orphaned session is not named by its session arn", `{"AWS":"` + testSessionArn + `"}`, testOrphanCaller, TrustNone},
		{"orphaned session is still covered by a wildcard", `{"AWS":"*"}`, testOrphanCaller, TrustDirect},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateAssumeRoleTrust(trustAllow(tt.principal), tt.caller, nil); got != tt.want {
				t.Fatalf("EvaluateAssumeRoleTrust = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEvaluateAssumeRoleTrustStatements(t *testing.T) {
	externalID := map[string][]string{"sts:ExternalId": {"secret-123"}}

	tests := []struct {
		name     string
		document string
		caller   AssumeRoleCaller
		ctxVars  map[string][]string
		want     TrustGrant
	}{
		{
			name:     "statement for another action does not apply",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			caller:   testUserCaller,
			want:     TrustNone,
		},
		{
			name:     "one action among several applies",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["sts:TagSession","sts:AssumeRole"]}]}`,
			caller:   testUserCaller,
			want:     TrustDirect,
		},
		{
			name:     "deny naming the caller overrides a direct allow",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"` + testUserArn + `"},"Action":"sts:AssumeRole"}]}`,
			caller:   testUserCaller,
			want:     TrustDenied,
		},
		{
			name:     "deny naming the account hits a directly allowed user",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testUserArn + `"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole"}]}`,
			caller:   testUserCaller,
			want:     TrustDenied,
		},
		{
			name:     "deny naming someone else leaves the allow standing",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/bob"},"Action":"sts:AssumeRole"}]}`,
			caller:   testUserCaller,
			want:     TrustAccount,
		},
		{
			name:     "condition met",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-123"}}}]}`,
			caller:   testUserCaller,
			ctxVars:  externalID,
			want:     TrustAccount,
		},
		{
			name:     "condition compares case-sensitively",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"SECRET-123"}}}]}`,
			caller:   testUserCaller,
			ctxVars:  externalID,
			want:     TrustNone,
		},
		{
			name:     "condition on an absent key is not met",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-123"}}}]}`,
			caller:   testUserCaller,
			want:     TrustNone,
		},
		{
			name:     "negated deny condition fires when the key is absent",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringNotEquals":{"sts:ExternalId":"secret-123"}}}]}`,
			caller:   testUserCaller,
			want:     TrustDenied,
		},
		{
			name:     "negated deny condition does not fire when the key matches",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringNotEquals":{"sts:ExternalId":"secret-123"}}}]}`,
			caller:   testUserCaller,
			ctxVars:  externalID,
			want:     TrustAccount,
		},
		{
			name:     "policy variable in a condition value",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole","Condition":{"StringLike":{"sts:RoleSessionName":"${aws:username}"}}}]}`,
			caller:   testUserCaller,
			ctxVars:  map[string][]string{"sts:RoleSessionName": {"alice"}, "aws:username": {"alice"}},
			want:     TrustAccount,
		},
		{
			name:     "a condition does not turn an account principal into a direct grant",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:PrincipalArn":"` + testUserArn + `"}}}]}`,
			caller:   testUserCaller,
			ctxVars:  map[string][]string{"aws:PrincipalArn": {testUserArn}},
			want:     TrustAccount,
		},
		{
			name:     "stored wildcard action still covers the action",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:*"}]}`,
			caller:   testUserCaller,
			want:     TrustDirect,
		},
		{
			name:     "document that does not parse grants nothing",
			document: `{not json`,
			caller:   testUserCaller,
			want:     TrustNone,
		},
		{
			name:     "document that fails trust grammar grants nothing",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Resource":"*"}]}`,
			caller:   testUserCaller,
			want:     TrustNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateAssumeRoleTrust(tt.document, tt.caller, tt.ctxVars); got != tt.want {
				t.Fatalf("EvaluateAssumeRoleTrust = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTrustAWSPrincipals(t *testing.T) {
	const document = `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"` + testRootArn + `","Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":{"AWS":["` + testUserArn + `","*"]},"Action":"sts:AssumeRole"},
		{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/example.com"},"Action":"sts:AssumeRoleWithWebIdentity"}
	]}`

	want := []string{testRootArn, testUserArn, "*"}
	if got := TrustAWSPrincipals(document); !slices.Equal(got, want) {
		t.Fatalf("TrustAWSPrincipals = %q, want %q", got, want)
	}
	if got := TrustAWSPrincipals(`{not json`); got != nil {
		t.Fatalf("TrustAWSPrincipals of an unparsable document = %q, want nil", got)
	}
}
