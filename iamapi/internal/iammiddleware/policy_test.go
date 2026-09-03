// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iammiddleware

import (
	"testing"

	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

func testIdentityUser() types.Identity {
	return types.Identity{User: &types.User{
		UserName: "alice",
		UserID:   "AIDAALICE",
		Arn:      iamutil.BuildUserArn(iamutil.DefaultAccountID, "/", "alice"),
	}}
}

func testIdentitySession() types.Identity {
	role := &types.Role{
		RoleName: "reader",
		RoleID:   "AROAREADER",
		Arn:      iamutil.BuildRoleArn(iamutil.DefaultAccountID, "/", "reader"),
	}
	return types.Identity{
		Role: role,
		Session: &types.Session{
			RoleArn:         role.Arn,
			RoleName:        role.RoleName,
			RoleID:          role.RoleID,
			RoleSessionName: "sess1",
		},
	}
}

// TestCallerArnAndPrincipalConditionArn pins the one place the two differ: a
// session is named by its assumed-role ARN in an error message, and by its
// role's own ARN as aws:PrincipalArn.
func TestCallerArnAndPrincipalConditionArn(t *testing.T) {
	tests := []struct {
		name          string
		identity      types.Identity
		wantCaller    string
		wantCondition string
	}{
		{
			name:          "user",
			identity:      testIdentityUser(),
			wantCaller:    "arn:aws:iam::000000000000:user/alice",
			wantCondition: "arn:aws:iam::000000000000:user/alice",
		},
		{
			name:          "session",
			identity:      testIdentitySession(),
			wantCaller:    "arn:aws:sts::000000000000:assumed-role/reader/sess1",
			wantCondition: "arn:aws:iam::000000000000:role/reader",
		},
		{
			name:          "root",
			identity:      types.Identity{IsRoot: true},
			wantCaller:    "",
			wantCondition: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CallerArn(tt.identity); got != tt.wantCaller {
				t.Errorf("CallerArn() = %q, want %q", got, tt.wantCaller)
			}
			if got := PrincipalConditionArn(tt.identity); got != tt.wantCondition {
				t.Errorf("PrincipalConditionArn() = %q, want %q", got, tt.wantCondition)
			}
		})
	}
}

// TestPrincipalConditionArnOutlivesRole pins that a session whose role has
// since been deleted is still named by the role it was minted against: the
// session carries the ARN, so nothing has to be looked up to name it.
func TestPrincipalConditionArnOutlivesRole(t *testing.T) {
	identity := testIdentitySession()
	identity.Role = nil

	want := "arn:aws:iam::000000000000:role/reader"
	if got := PrincipalConditionArn(identity); got != want {
		t.Errorf("PrincipalConditionArn() = %q, want %q", got, want)
	}
}

// TestIdentityConditionContext covers the identity-derived condition keys
// only this service can supply. aws:PrincipalArn for a session is the role
// ARN, so a Condition on it covers every session of the role and can never
// single one out — aws:userid, which carries <role id>:<session name>, is
// the key that can.
func TestIdentityConditionContext(t *testing.T) {
	tests := []struct {
		name     string
		identity types.Identity
		want     map[string]string
	}{
		{
			name:     "user",
			identity: testIdentityUser(),
			want: map[string]string{
				"aws:PrincipalArn":     "arn:aws:iam::000000000000:user/alice",
				"aws:PrincipalAccount": iamutil.DefaultAccountID,
				"aws:PrincipalType":    "User",
				"aws:username":         "alice",
				"aws:userid":           "AIDAALICE",
			},
		},
		{
			name:     "session",
			identity: testIdentitySession(),
			want: map[string]string{
				"aws:PrincipalArn":     "arn:aws:iam::000000000000:role/reader",
				"aws:PrincipalAccount": iamutil.DefaultAccountID,
				"aws:PrincipalType":    "AssumedRole",
				"aws:userid":           "AROAREADER:sess1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IdentityConditionContext(tt.identity)
			for key, want := range tt.want {
				vals, ok := got[key]
				if !ok {
					t.Errorf("%s missing, want %q", key, want)
					continue
				}
				if len(vals) != 1 || vals[0] != want {
					t.Errorf("%s = %v, want [%q]", key, vals, want)
				}
			}
			if _, ok := got["aws:username"]; ok && tt.identity.Session != nil {
				t.Error("aws:username set for a session, which has no user name")
			}
		})
	}
}
