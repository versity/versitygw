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

package auth

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

func TestBucketVisibleTo(t *testing.T) {
	const bucket = "shared"
	caller := Account{Access: "reader", Role: RoleUser}
	request := map[string][]string{
		"aws:SourceIp":        {"10.0.0.5"},
		"aws:SecureTransport": {"false"},
	}

	ownedBy := func(owner string, grantees ...Grantee) ACL {
		return ACL{Owner: owner, Grantees: grantees}
	}
	grant := func(access string, perm Permission) Grantee {
		return Grantee{Access: access, Permission: perm, Type: types.TypeCanonicalUser}
	}
	allUsers := func(perm Permission) Grantee {
		return Grantee{Access: "all-users", Permission: perm, Type: types.TypeGroup}
	}
	// policy builds a one-statement policy from its JSON fields.
	policy := func(statements ...string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`)
	}
	listAllow := func(principal string) string {
		return `{"Effect":"Allow","Principal":` + principal + `,"Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared"}`
	}
	listDeny := func(principal string) string {
		return `{"Effect":"Deny","Principal":` + principal + `,"Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared"}`
	}
	withCondition := func(effect, principal, cond string) string {
		return `{"Effect":"` + effect + `","Principal":` + principal + `,"Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared","Condition":` + cond + `}`
	}

	tests := []struct {
		name       string
		acl        ACL
		policy     []byte
		disableACL bool
		want       bool
	}{
		// Ownership
		{name: "owned bucket", acl: ownedBy("reader"), want: true},
		{name: "owned bucket despite deny", acl: ownedBy("reader"), policy: policy(listDeny(`"*"`)), want: true},
		{name: "owned bucket despite unparsable policy", acl: ownedBy("reader"), policy: []byte(`{`), want: true},
		{name: "other owner, no grants", acl: ownedBy("root"), want: false},

		// ACL
		{name: "ACL READ grant", acl: ownedBy("root", grant("reader", PermissionRead)), want: true},
		{name: "ACL FULL_CONTROL grant", acl: ownedBy("root", grant("reader", PermissionFullControl)), want: true},
		{name: "ACL WRITE grant does not list", acl: ownedBy("root", grant("reader", PermissionWrite)), want: false},
		{name: "ACL READ_ACP grant does not list", acl: ownedBy("root", grant("reader", PermissionReadAcp)), want: false},
		{name: "ACL grant to someone else", acl: ownedBy("root", grant("other", PermissionRead)), want: false},
		{name: "ACL AllUsers READ ignored", acl: ownedBy("root", allUsers(PermissionRead)), want: false},
		{name: "ACL AllUsers FULL_CONTROL ignored", acl: ownedBy("root", allUsers(PermissionFullControl)), want: false},
		{name: "ACL grant ignored with ACLs disabled", acl: ownedBy("root", grant("reader", PermissionRead)), disableACL: true, want: false},
		{name: "ACL grant with empty policy", acl: ownedBy("root", grant("reader", PermissionRead)), policy: []byte{}, want: true},

		// Policy Allow
		{name: "Allow naming the caller", acl: ownedBy("root"), policy: policy(listAllow(`{"AWS":"reader"}`)), want: true},
		{name: "Allow naming the caller in a list", acl: ownedBy("root"), policy: policy(listAllow(`{"AWS":["other","reader"]}`)), want: true},
		{name: "Allow naming someone else", acl: ownedBy("root"), policy: policy(listAllow(`{"AWS":"other"}`)), want: false},
		{name: "Allow to * alone ignored", acl: ownedBy("root"), policy: policy(listAllow(`"*"`)), want: false},
		{name: "Allow to * and the caller", acl: ownedBy("root"), policy: policy(listAllow(`["*","reader"]`)), want: true},
		{
			name: "Allow with s3:* on every resource", acl: ownedBy("root"),
			policy: policy(`{"Effect":"Allow","Principal":{"AWS":"reader"},"Action":"s3:*","Resource":"arn:aws:s3:::*"}`),
			want:   true,
		},
		{
			name: "Allow on the object resource only", acl: ownedBy("root"),
			policy: policy(`{"Effect":"Allow","Principal":{"AWS":"reader"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}`),
			want:   false,
		},
		{
			name: "Allow ListBucket on another bucket", acl: ownedBy("root"),
			policy: policy(`{"Effect":"Allow","Principal":{"AWS":"reader"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::other"}`),
			want:   false,
		},
		{
			name: "Allow of another bucket action", acl: ownedBy("root"),
			policy: policy(`{"Effect":"Allow","Principal":{"AWS":"reader"},"Action":"s3:GetBucketTagging","Resource":"arn:aws:s3:::shared"}`),
			want:   false,
		},

		// Policy Deny
		{
			name: "Deny for the caller hides an ACL grant", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(listDeny(`{"AWS":"reader"}`)), want: false,
		},
		{
			name: "Deny for * hides an ACL grant", acl: ownedBy("root", grant("reader", PermissionFullControl)),
			policy: policy(listDeny(`"*"`)), want: false,
		},
		{
			name: "Deny for the caller hides an Allow", acl: ownedBy("root"),
			policy: policy(listAllow(`{"AWS":"reader"}`), listDeny(`{"AWS":"reader"}`)), want: false,
		},
		{
			name: "Deny for * hides an Allow", acl: ownedBy("root"),
			policy: policy(listAllow(`{"AWS":"reader"}`), listDeny(`"*"`)), want: false,
		},
		{
			name: "Deny for someone else", acl: ownedBy("root"),
			policy: policy(listAllow(`{"AWS":"reader"}`), listDeny(`{"AWS":"other"}`)), want: true,
		},
		{
			name: "Deny of object reads only", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}`),
			want:   true,
		},
		{
			name: "Policy with no matching statement leaves the ACL grant", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(listAllow(`{"AWS":"other"}`)), want: true,
		},

		// Conditions
		{
			name: "Allow limited to a prefix", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"StringLike":{"s3:prefix":"team-a/*"}}`)),
			want:   true,
		},
		{
			name: "Allow requiring a delimiter and max-keys", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"StringEquals":{"s3:delimiter":"/"},"NumericLessThan":{"s3:max-keys":"100"}}`)),
			want:   true,
		},
		{
			name: "Deny limited to a prefix doesn't hide", acl: ownedBy("root"),
			policy: policy(
				listAllow(`{"AWS":"reader"}`),
				withCondition("Deny", `"*"`, `{"StringNotLike":{"s3:prefix":"team-a/*"}}`),
			),
			want: true,
		},
		{
			name: "Allow from the caller's address", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"IpAddress":{"aws:SourceIp":"10.0.0.0/24"}}`)),
			want:   true,
		},
		{
			name: "Allow from another address", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"IpAddress":{"aws:SourceIp":"192.168.0.0/24"}}`)),
			want:   false,
		},
		{
			name: "Allow limited to a prefix from another address", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"StringLike":{"s3:prefix":"team-a/*"},"IpAddress":{"aws:SourceIp":"192.168.0.0/24"}}`)),
			want:   false,
		},
		{
			name: "Allow requiring TLS over plain HTTP", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"Bool":{"aws:SecureTransport":"true"}}`)),
			want:   false,
		},
		{
			name: "Deny without TLS over plain HTTP", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(withCondition("Deny", `"*"`, `{"Bool":{"aws:SecureTransport":"false"}}`)),
			want:   false,
		},
		{
			name: "Deny from another address", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(withCondition("Deny", `"*"`, `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/24"}}`)),
			want:   true,
		},
		{
			name: "Deny settled by a known value beside a prefix variable", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(withCondition("Deny", `"*"`, `{"StringEquals":{"aws:SecureTransport":["false","${s3:prefix}"]}}`)),
			want:   false,
		},
		{
			name: "Deny left to a prefix variable", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(withCondition("Deny", `"*"`, `{"StringEquals":{"aws:SecureTransport":["true","${s3:prefix}"]}}`)),
			want:   true,
		},
		{
			name: "Allow that a known value beside a prefix variable rules out", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"StringNotEquals":{"aws:SecureTransport":["false","${s3:prefix}"]}}`)),
			want:   false,
		},
		{
			name: "Allow left to a prefix variable", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"StringNotEquals":{"aws:SecureTransport":["true","${s3:prefix}"]}}`)),
			want:   true,
		},
		{
			name: "Allow with a condition that can't be evaluated", acl: ownedBy("root"),
			policy: policy(withCondition("Allow", `{"AWS":"reader"}`, `{"StringFoo":{"aws:SourceIp":"x"}}`)),
			want:   false,
		},
		{
			name: "Public Allow with a condition that can't be evaluated hides an ACL grant", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(withCondition("Allow", `"*"`, `{"StringFoo":{"aws:SourceIp":"x"}}`)),
			want:   false,
		},
		{
			name: "Unevaluable condition on someone else's statement", acl: ownedBy("root", grant("reader", PermissionRead)),
			policy: policy(withCondition("Allow", `{"AWS":"other"}`, `{"StringFoo":{"aws:SourceIp":"x"}}`)),
			want:   true,
		},

		// Policy errors
		{name: "unparsable policy hides the bucket", acl: ownedBy("root", grant("reader", PermissionRead)), policy: []byte(`{`), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BucketVisibleTo(caller, bucket, tt.acl, tt.policy, request, tt.disableACL)
			if got != tt.want {
				t.Errorf("BucketVisibleTo() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBucketVisibleTo_DoesNotChangeTheACL checks that dropping the AllUsers
// grants for the check leaves the caller's ACL as it was.
func TestBucketVisibleTo_DoesNotChangeTheACL(t *testing.T) {
	acl := ACL{Owner: "root", Grantees: []Grantee{
		{Access: "all-users", Permission: PermissionRead, Type: types.TypeGroup},
		{Access: "reader", Permission: PermissionRead, Type: types.TypeCanonicalUser},
	}}
	if !BucketVisibleTo(Account{Access: "reader"}, "b", acl, nil, nil, false) {
		t.Fatal("BucketVisibleTo() = false, want true")
	}
	if len(acl.Grantees) != 2 || acl.Grantees[0].Access != "all-users" {
		t.Errorf("ACL grantees changed: %+v", acl.Grantees)
	}
}

func TestParseListBucketsScope(t *testing.T) {
	tests := []struct {
		in      string
		want    ListBucketsScope
		wantErr bool
	}{
		{in: "", want: ListBucketsScopeOwned},
		{in: "owned", want: ListBucketsScopeOwned},
		{in: "accessible", want: ListBucketsScopeAccessible},
		{in: "all", want: ListBucketsScopeAll},
		{in: " Accessible ", want: ListBucketsScopeAccessible},
		{in: "ALL", want: ListBucketsScopeAll},
		{in: "shared", wantErr: true},
		{in: "own", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseListBucketsScope(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseListBucketsScope(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseListBucketsScope(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// fixedOwnerIAM fixes bucket ownership without evaluating identity
// policies, to check that either interface alone rules the wider scopes out.
type fixedOwnerIAM struct {
	IAMService
}

func (fixedOwnerIAM) BucketOwner() Account { return Account{Access: "owner"} }

func TestValidateListBucketsScope(t *testing.T) {
	single := NewIAMServiceSingle(Account{Access: "root"})
	evaluator := &mockPolicyEvaluator{IAMService: single}
	fixed := fixedOwnerIAM{IAMService: single}

	tests := []struct {
		name    string
		iam     IAMService
		scope   ListBucketsScope
		wantErr bool
	}{
		{name: "owned without identity policies", iam: single, scope: ListBucketsScopeOwned},
		{name: "accessible without identity policies", iam: single, scope: ListBucketsScopeAccessible},
		{name: "all without identity policies", iam: single, scope: ListBucketsScopeAll},
		{name: "owned with a policy evaluator", iam: evaluator, scope: ListBucketsScopeOwned},
		{name: "accessible with a policy evaluator", iam: evaluator, scope: ListBucketsScopeAccessible, wantErr: true},
		{name: "all with a policy evaluator", iam: evaluator, scope: ListBucketsScopeAll, wantErr: true},
		{name: "owned with a fixed owner", iam: fixed, scope: ListBucketsScopeOwned},
		{name: "accessible with a fixed owner", iam: fixed, scope: ListBucketsScopeAccessible, wantErr: true},
		{name: "all with a fixed owner", iam: fixed, scope: ListBucketsScopeAll, wantErr: true},
		{name: "invalid scope", iam: single, scope: "shared", wantErr: true},
		{name: "unparsed scope", iam: single, scope: "ALL", wantErr: true},
		{name: "empty scope is owned", iam: evaluator, scope: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateListBucketsScope(tt.iam, tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateListBucketsScope() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestListBucketsConditionContext_OmitsListObjectsKeys(t *testing.T) {
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.Header.SetMethod(fiber.MethodGet)
	fctx.Request.SetRequestURI("/?prefix=team-a/&delimiter=/&max-keys=5&versionId=v1")
	fctx.Request.Header.Set("User-Agent", "cli")
	fctx.Request.Header.Set("X-Amz-Acl", "private")
	ctx := app.AcquireCtx(fctx)
	defer app.ReleaseCtx(ctx)

	condCtx := ListBucketsConditionContext(ctx)
	for _, key := range []string{"s3:prefix", "s3:delimiter", "s3:max-keys", "s3:x-amz-acl", "s3:VersionId"} {
		if _, ok := condCtx[key]; ok {
			t.Errorf("ListBucketsConditionContext() has %s = %v, want it absent", key, condCtx[key])
		}
	}
	for _, key := range []string{"aws:CurrentTime", "aws:EpochTime", "aws:SecureTransport", "aws:UserAgent"} {
		if _, ok := condCtx[key]; !ok {
			t.Errorf("ListBucketsConditionContext() lacks %s", key)
		}
	}

	// The same request authorized as a ListObjects call still carries them.
	full := requestConditionContext(ctx, []Action{ListBucketAction})
	if got := full["s3:prefix"]; len(got) != 1 || got[0] != "team-a/" {
		t.Errorf("requestConditionContext() s3:prefix = %v, want [team-a/]", got)
	}
}
