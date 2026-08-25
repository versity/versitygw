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
	"testing"

	"github.com/versity/versitygw/iamapi/types"
)

func policyEntries(documents ...string) []types.PolicyEntry {
	entries := make([]types.PolicyEntry, len(documents))
	for i, doc := range documents {
		entries[i] = types.PolicyEntry{PolicyDocument: doc}
	}
	return entries
}

func TestEvaluateIdentityPolicies(t *testing.T) {
	tests := []struct {
		name      string
		documents []types.PolicyEntry
		reqCtx    RequestContext
		want      Decision
	}{
		{
			name:      "no documents denies by default",
			documents: nil,
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionNoMatch,
		},
		{
			name:      "no matching statement denies by default",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionNoMatch,
		},
		{
			name:      "matching allow statement allows",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionAllow,
		},
		{
			name:      "wildcard action allows",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionAllow,
		},
		{
			name: "explicit deny overrides an allow in another document",
			documents: policyEntries(
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}]}`,
			),
			reqCtx: RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:   DecisionDeny,
		},
		{
			name:      "explicit deny overrides an allow in the same document",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionDeny,
		},
		{
			name:      "action match is case-insensitive",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"IAM:CREATEUSER","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionAllow,
		},
		{
			// A malformed document might have contained a Deny we can no
			// longer see, so the whole evaluation denies rather than
			// silently proceeding as if the document wasn't there.
			name:      "malformed document denies the whole evaluation, even with a valid Allow elsewhere",
			documents: policyEntries(`not json`, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionDeny,
		},
		{
			name:      "malformed document denies the whole evaluation regardless of document order",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}]}`, `not json`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionDeny,
		},
		{
			// A Deny guarded by a Condition operator this package doesn't
			// recognize (simulating a legacy document stored before
			// write-time validation existed - Parse() would reject this
			// today) must not be silently skipped in favor of the Allow
			// underneath it.
			name: "unrecognized operator on a Deny denies, does not let an Allow underneath it win",
			documents: policyEntries(
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*","Condition":{"FooBarOperator":{"aws:username":"alice"}}}]}`,
			),
			reqCtx: RequestContext{Action: "iam:CreateUser", Resource: "*", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:   DecisionDeny,
		},
		{
			// Fail-closed on a condition-evaluation error isn't scoped to
			// Deny statements specifically - it's a deny-all result for the
			// whole evaluation.
			name:      "unrecognized operator on an Allow-only statement still denies (fail-closed is not Deny-specific)",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*","Condition":{"FooBarOperator":{"aws:username":"alice"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionDeny,
		},
		{
			// A document containing any statement Validate() would
			// reject (here, an unrelated statement's unrecognized condition
			// operator) is invalid as a whole and denies every evaluation
			// against it, even a request the offending statement doesn't
			// itself cover - assigning no meaning to a document AWS itself
			// would reject at write time is safer than evaluating the parts
			// of it that happen to look fine.
			name:      "unrecognized operator in an unrelated statement invalidates the whole document",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"},{"Effect":"Deny","Action":"iam:DeleteUser","Resource":"*","Condition":{"FooBarOperator":{"aws:username":"alice"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionDeny,
		},
		{
			name:      "Null operator end-to-end: denies presence of aws:username",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*","Condition":{"Null":{"aws:username":"false"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionDeny,
		},
		{
			name:      "Null operator end-to-end: allows when aws:username is absent (session, not user)",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*","Condition":{"Null":{"aws:username":"false"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*", Condition: map[string][]string{"aws:userid": {"role-id:session"}}},
			want:      DecisionAllow,
		},
		{
			name:      "NotAction denies coverage for the excluded action",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:CreateUser","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:CreateUser", Resource: "*"},
			want:      DecisionNoMatch,
		},
		{
			name:      "NotAction allows actions outside the exclusion",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:CreateUser","Resource":"*"}]}`),
			reqCtx:    RequestContext{Action: "iam:DeleteUser", Resource: "*"},
			want:      DecisionAllow,
		},
		{
			name:      "resource-scoped allow matches the named resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::000000000000:role/role-a"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-a"},
			want:      DecisionAllow,
		},
		{
			name:      "resource-scoped allow does not cover a different resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::000000000000:role/role-a"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-b"},
			want:      DecisionNoMatch,
		},
		{
			name:      "resource match is case-sensitive",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::000000000000:role/Role-A"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-a"},
			want:      DecisionNoMatch,
		},
		{
			name:      "resource-scoped deny only affects the named resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"},{"Effect":"Deny","Action":"iam:GetRole","Resource":"arn:aws:iam::000000000000:role/role-a"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-b"},
			want:      DecisionAllow,
		},
		{
			name:      "resource-scoped deny denies the named resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"},{"Effect":"Deny","Action":"iam:GetRole","Resource":"arn:aws:iam::000000000000:role/role-a"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-a"},
			want:      DecisionDeny,
		},
		{
			name:      "NotResource excludes the named resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","NotResource":"arn:aws:iam::000000000000:role/role-a"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-a"},
			want:      DecisionNoMatch,
		},
		{
			name:      "NotResource allows resources outside the exclusion",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","NotResource":"arn:aws:iam::000000000000:role/role-a"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "arn:aws:iam::000000000000:role/role-b"},
			want:      DecisionAllow,
		},
		{
			// ${aws:username} in Resource must resolve to the requesting
			// principal's own name before matching, not be compared as a
			// literal string.
			name:      "policy variable in Resource matches the caller's own resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetUser", Resource: "arn:aws:iam::000000000000:user/alice", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionAllow,
		},
		{
			name:      "policy variable in Resource does not match a different principal's resource",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetUser", Resource: "arn:aws:iam::000000000000:user/bob", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionNoMatch,
		},
		{
			name:      "unresolvable policy variable in Resource is left literal and so does not match a real ARN",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetUser", Resource: "arn:aws:iam::000000000000:user/alice"},
			want:      DecisionNoMatch,
		},
		{
			// AWS requires Version 2012-10-17 to use policy variables at
			// all - the same statement under 2008-10-17 must treat
			// "${aws:username}" as literal text, not expand it.
			name:      "policy variable in Resource is not substituted under version 2008-10-17",
			documents: policyEntries(`{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetUser", Resource: "arn:aws:iam::000000000000:user/alice", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionNoMatch,
		},
		{
			name:      "policy variable in Resource is not substituted with no Version at all",
			documents: policyEntries(`{"Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`),
			reqCtx:    RequestContext{Action: "iam:GetUser", Resource: "arn:aws:iam::000000000000:user/alice", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionNoMatch,
		},
		{
			name:      "condition must match",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*","Condition":{"StringEquals":{"aws:username":"alice"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "*", Condition: map[string][]string{"aws:username": {"alice"}}},
			want:      DecisionAllow,
		},
		{
			name:      "condition mismatch denies by default",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*","Condition":{"StringEquals":{"aws:username":"alice"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "*", Condition: map[string][]string{"aws:username": {"bob"}}},
			want:      DecisionNoMatch,
		},
		{
			name:      "deny condition must also match to take effect",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"},{"Effect":"Deny","Action":"iam:GetRole","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "*", Condition: map[string][]string{"aws:SourceIp": {"203.0.113.5"}}},
			want:      DecisionAllow,
		},
		{
			name:      "deny condition matching denies",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"},{"Effect":"Deny","Action":"iam:GetRole","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`),
			reqCtx:    RequestContext{Action: "iam:GetRole", Resource: "*", Condition: map[string][]string{"aws:SourceIp": {"10.1.2.3"}}},
			want:      DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateIdentityPolicies(tt.documents, tt.reqCtx); got != tt.want {
				t.Fatalf("EvaluateIdentityPolicies() = %v, want %v", got, tt.want)
			}
		})
	}
}
