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
	"maps"
	"slices"
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

func TestConditionKeys(t *testing.T) {
	tests := []struct {
		name      string
		documents []types.PolicyEntry
		want      []string
		wantOK    bool
	}{
		{
			name:   "no documents",
			want:   nil,
			wantOK: true,
		},
		{
			name:      "no conditions or variables",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
			want:      nil,
			wantOK:    true,
		},
		{
			name: "condition keys from every statement, whatever it covers",
			documents: policyEntries(
				`{"Version":"2012-10-17","Statement":[`+
					`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},`+
					`{"Effect":"Deny","Action":"s3:PutObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
				`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringLike":{"s3:prefix":"home/*"}}}}`,
			),
			want:   []string{"aws:SecureTransport", "aws:SourceIp", "s3:prefix"},
			wantOK: true,
		},
		{
			name: "variables in Resource, NotResource and condition values",
			documents: policyEntries(
				`{"Version":"2012-10-17","Statement":[` +
					`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${aws:username}/*"},` +
					`{"Effect":"Deny","Action":"s3:GetObject","NotResource":"arn:aws:s3:::b/${aws:userid}/*"},` +
					`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringEquals":{"aws:Referer":"${aws:UserAgent}"}}}]}`,
			),
			want:   []string{"aws:Referer", "aws:UserAgent", "aws:userid", "aws:username"},
			wantOK: true,
		},
		{
			name: "duplicates removed, spelling kept",
			documents: policyEntries(
				`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}}`,
				`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8","AWS:SOURCEIP":"10.1.0.0/16"}}}}`,
			),
			want:   []string{"AWS:SOURCEIP", "aws:SourceIp"},
			wantOK: true,
		},
		{
			name:      "unparseable document",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":`),
			wantOK:    false,
		},
		{
			name:      "document failing validation",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","NotAction":"s3:Get*","Resource":"*"}}`),
			wantOK:    false,
		},
		{
			name:      "unrecognized condition operator",
			documents: policyEntries(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringSortOf":{"s3:prefix":"a"}}}}`),
			wantOK:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ConditionKeys(tt.documents)
			if ok != tt.wantOK {
				t.Fatalf("ConditionKeys ok = %v, want %v", ok, tt.wantOK)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ConditionKeys = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConditionKeysDecideEvaluation checks the property callers rely on:
// contexts that agree on every key ConditionKeys reports get the same
// decision, while a reported key can change it.
func TestConditionKeysDecideEvaluation(t *testing.T) {
	documents := policyEntries(
		`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":"${aws:username}/*"}}},` +
			`{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"NotIpAddress":{"aws:sourceip":"10.0.0.0/8"}}}]}`,
	)
	keys, ok := ConditionKeys(documents)
	if !ok {
		t.Fatal("ConditionKeys: not ok")
	}
	if want := []string{"aws:sourceip", "aws:username", "s3:prefix"}; !slices.Equal(keys, want) {
		t.Fatalf("ConditionKeys = %q, want %q", keys, want)
	}

	base := map[string][]string{
		"aws:username": {"alice"},
		"s3:prefix":    {"alice/docs"},
		"aws:SourceIp": {"10.1.2.3"},
	}
	evaluate := func(extra map[string][]string) Decision {
		condCtx := maps.Clone(base)
		maps.Copy(condCtx, extra)
		return EvaluateIdentityPolicies(documents, RequestContext{Action: "s3:ListBucket", Resource: "arn:aws:s3:::b", Condition: condCtx})
	}

	want := evaluate(nil)
	if want != DecisionAllow {
		t.Fatalf("baseline decision = %v, want allow", want)
	}
	// Keys the documents never read change nothing.
	if got := evaluate(map[string][]string{"aws:CurrentTime": {"2030-01-01T00:00:00Z"}, "aws:UserAgent": {"other"}}); got != want {
		t.Errorf("decision with unreferenced keys changed = %v, want %v", got, want)
	}
	// Each reported key can.
	if got := evaluate(map[string][]string{"s3:prefix": {"bob/docs"}}); got != DecisionNoMatch {
		t.Errorf("decision with another prefix = %v, want no match", got)
	}
	if got := evaluate(map[string][]string{"aws:SourceIp": {"192.0.2.1"}}); got != DecisionDeny {
		t.Errorf("decision from another network = %v, want deny", got)
	}
}
