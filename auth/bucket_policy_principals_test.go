// Copyright 2023 Versity Software
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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrincipals_Add(t *testing.T) {
	p := make(Principals)
	p.Add("user1")
	_, ok := p["user1"]
	assert.True(t, ok)
}

func TestPrincipals_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Principals
		wantErr bool
	}{
		{"valid slice", `["user1","user2"]`, Principals{"user1": {}, "user2": {}}, false},
		{"empty slice", `[]`, nil, true},
		{"valid string", `"user1"`, Principals{"user1": {}}, false},
		{"empty string", `""`, nil, true},
		{"valid AWS object", `{"AWS":"user1"}`, Principals{"user1": {}}, false},
		{"empty AWS object", `{"AWS":""}`, nil, true},
		{"valid AWS array", `{"AWS":["user1","user2"]}`, Principals{"user1": {}, "user2": {}}, false},
		{"empty AWS array", `{"AWS":[]}`, nil, true},
		{"invalid json", `{invalid}`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Principals
			err := json.Unmarshal([]byte(tt.input), &p)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, p)
			}
		})
	}
}

func TestPrincipals_ToSlice(t *testing.T) {
	p := Principals{"user1": {}, "user2": {}, "*": {}}
	got := p.ToSlice()
	assert.Contains(t, got, "user1")
	assert.Contains(t, got, "user2")
	assert.NotContains(t, got, "*")
}

func TestPrincipals_Validate(t *testing.T) {
	iamSingle := NewIAMServiceSingle(Account{
		Access: "user1",
	})
	tests := []struct {
		name       string
		principals Principals
		mockIAM    IAMService
		err        error
	}{
		{"only wildcard", Principals{"*": {}}, iamSingle, nil},
		{"wildcard and user", Principals{"*": {}, "user1": {}}, iamSingle, policyErrInvalidPrincipal},
		{"accounts exist returns err", Principals{"user2": {}, "user3": {}}, iamSingle, policyErrInvalidPrincipal},
		{"accounts exist non-empty", Principals{"user1": {}}, iamSingle, nil},
		{"accounts valid", Principals{"user1": {}}, iamSingle, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.principals.Validate(tt.mockIAM)
			assert.EqualValues(t, tt.err, err)
		})
	}
}

// mockPrincipalResolver is an IAMService that names its identities by ARN,
// standing in for the standalone IAM service client: it reports every
// principal not in valid as unresolvable, the way ResolvePrincipals does.
type mockPrincipalResolver struct {
	IAMService
	valid map[string]bool
	err   error
	calls [][]string
}

func (m *mockPrincipalResolver) ResolvePrincipals(principals []string) ([]string, error) {
	m.calls = append(m.calls, principals)
	if m.err != nil {
		return nil, m.err
	}
	invalid := []string{}
	for _, p := range principals {
		if !m.valid[p] {
			invalid = append(invalid, p)
		}
	}
	return invalid, nil
}

func newMockPrincipalResolver(valid ...string) *mockPrincipalResolver {
	set := make(map[string]bool, len(valid))
	for _, v := range valid {
		set[v] = true
	}
	return &mockPrincipalResolver{IAMService: NewIAMServiceSingle(Account{}), valid: set}
}

const (
	testUserArn    = "arn:aws:iam::000000000000:user/alice"
	testRoleArn    = "arn:aws:iam::000000000000:role/reader"
	testSessionArn = "arn:aws:sts::000000000000:assumed-role/reader/sess1"
	testRootArn    = "arn:aws:iam::000000000000:root"
)

// TestPrincipals_ValidateWithPrincipalResolver covers the write-time check
// for an ARN-naming backend: the resolver decides, ResolveAccounts is never
// consulted, and the wildcard rules are unchanged.
func TestPrincipals_ValidateWithPrincipalResolver(t *testing.T) {
	tests := []struct {
		name       string
		principals Principals
		valid      []string
		err        error
	}{
		{"resolvable user arn", Principals{testUserArn: {}}, []string{testUserArn}, nil},
		{"unresolvable arn", Principals{testUserArn: {}}, nil, policyErrInvalidPrincipal},
		{"access key id is not a principal", Principals{"AKIAEXAMPLE": {}}, []string{testUserArn}, policyErrInvalidPrincipal},
		{"one of several unresolvable", Principals{testUserArn: {}, testRoleArn: {}}, []string{testUserArn}, policyErrInvalidPrincipal},
		{"all resolvable", Principals{testUserArn: {}, testRoleArn: {}}, []string{testUserArn, testRoleArn}, nil},
		{"only wildcard", Principals{"*": {}}, nil, nil},
		{"wildcard mixed with an arn", Principals{"*": {}, testUserArn: {}}, []string{testUserArn}, policyErrInvalidPrincipal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newMockPrincipalResolver(tt.valid...)
			assert.EqualValues(t, tt.err, tt.principals.Validate(resolver))
		})
	}
}

// TestPrincipals_ValidateResolverErrorPropagates pins that a resolver
// failure surfaces as itself rather than as an invalid-principal verdict:
// an unreachable IAM service must not read as "this principal does not
// exist".
func TestPrincipals_ValidateResolverErrorPropagates(t *testing.T) {
	resolver := newMockPrincipalResolver()
	resolver.err = assert.AnError

	err := Principals{testUserArn: {}}.Validate(resolver)
	assert.ErrorIs(t, err, assert.AnError)
}

// TestPrincipals_ValidateWildcardSkipsResolver pins that a lone "*" costs no
// round trip - it names everyone, so there is nothing to resolve.
func TestPrincipals_ValidateWildcardSkipsResolver(t *testing.T) {
	resolver := newMockPrincipalResolver()

	assert.NoError(t, Principals{"*": {}}.Validate(resolver))
	assert.Empty(t, resolver.calls)
}

func TestPrincipals_matchForAccessKey(t *testing.T) {
	user := Account{Access: "user1"}

	assert.Equal(t, principalDirectMatch, Principals{"user1": {}}.matchFor(user))
	assert.Equal(t, principalNoMatch, Principals{"user2": {}}.matchFor(user))
	assert.Equal(t, principalDirectMatch, Principals{"*": {}}.matchFor(user))
	// An ARN means nothing to a backend whose identities are access keys.
	assert.Equal(t, principalNoMatch, Principals{testUserArn: {}}.matchFor(user))
}

func TestPrincipals_matchForArn(t *testing.T) {
	user := Account{Access: "AKIAEXAMPLE", Arn: testUserArn}
	session := Account{Access: "ASIAEXAMPLE", Arn: testSessionArn, RoleArn: testRoleArn, IsSession: true}
	root := Account{Access: "root", Arn: testRootArn}

	tests := []struct {
		name       string
		principals Principals
		acc        Account
		want       principalMatch
	}{
		{"user named by its own arn", Principals{testUserArn: {}}, user, principalDirectMatch},
		{"user not named", Principals{testRoleArn: {}}, user, principalNoMatch},
		{"wildcard", Principals{"*": {}}, user, principalDirectMatch},
		{"access key id no longer matches", Principals{"AKIAEXAMPLE": {}}, user, principalNoMatch},
		{"account id delegates", Principals{"000000000000": {}}, user, principalAccountMatch},
		{"account root arn delegates", Principals{testRootArn: {}}, user, principalAccountMatch},
		{"another account does not match", Principals{"arn:aws:iam::111111111111:root": {}}, user, principalNoMatch},
		{"session named by its role arn", Principals{testRoleArn: {}}, session, principalDirectMatch},
		{"session named by its own arn", Principals{testSessionArn: {}}, session, principalDirectMatch},
		{"another session of the same role", Principals{"arn:aws:sts::000000000000:assumed-role/reader/sess2": {}}, session, principalNoMatch},
		{"session under account delegation", Principals{testRootArn: {}}, session, principalAccountMatch},
		{"root matches the account root arn directly", Principals{testRootArn: {}}, root, principalDirectMatch},
		{"matching is case sensitive", Principals{"arn:aws:iam::000000000000:user/ALICE": {}}, user, principalNoMatch},
		{"no wildcard within an arn", Principals{"arn:aws:iam::000000000000:user/*": {}}, user, principalNoMatch},
		{"no whitespace trimming", Principals{" " + testUserArn: {}}, user, principalNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.principals.matchFor(tt.acc))
		})
	}
}

// TestMatchesPrincipal_AccountDelegation pins the asymmetry between Allow
// and Deny for an account-level principal: it delegates to the account's own
// IAM under Allow, granting nothing by itself, but denies the account's
// principals outright under Deny.
func TestMatchesPrincipal_AccountDelegation(t *testing.T) {
	user := Account{Access: "AKIAEXAMPLE", Arn: testUserArn}

	allow := &BucketPolicyItem{Effect: BucketPolicyAccessTypeAllow, Principals: Principals{testRootArn: {}}}
	deny := &BucketPolicyItem{Effect: BucketPolicyAccessTypeDeny, Principals: Principals{testRootArn: {}}}

	assert.False(t, allow.matchesPrincipal(user))
	assert.True(t, deny.matchesPrincipal(user))

	// A statement naming the user itself grants under either effect.
	allow.Principals = Principals{testUserArn: {}}
	deny.Principals = Principals{testUserArn: {}}
	assert.True(t, allow.matchesPrincipal(user))
	assert.True(t, deny.matchesPrincipal(user))
}

func TestAccountIDFromArn(t *testing.T) {
	tests := []struct {
		arn  string
		want string
	}{
		{testUserArn, "000000000000"},
		{testSessionArn, "000000000000"},
		{testRootArn, "000000000000"},
		{"arn:aws:iam::123456789012:role/some/path/name", "123456789012"},
		{"", ""},
		{"not-an-arn", ""},
		{"arn:aws:iam::000000000000", ""},
		{"xrn:aws:iam::000000000000:root", ""},
	}
	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			assert.Equal(t, tt.want, accountIDFromArn(tt.arn))
		})
	}
}

func TestPrincipals_isPublic(t *testing.T) {
	assert.True(t, Principals{"*": {}}.isPublic())
	assert.False(t, Principals{"user1": {}}.isPublic())
}

// TestValidatePolicyDocument_ResolverFailureIsNotMalformed pins that a
// policy whose principals could not be checked — because the IAM service
// failed, not because the document is wrong — is not reported as a
// malformed policy. Principal validation is a network call for an
// ARN-naming backend, so this is the difference between telling an operator
// their IAM service is down and telling a user their policy is invalid.
func TestValidatePolicyDocument_ResolverFailureIsNotMalformed(t *testing.T) {
	resolver := newMockPrincipalResolver()
	resolver.err = assert.AnError

	doc := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
		testUserArn + `"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`)

	err := ValidatePolicyDocument(doc, "bucket", resolver)
	assert.ErrorIs(t, err, assert.AnError)

	// A genuine document defect still reports as MalformedPolicy.
	resolver.err = nil
	err = ValidatePolicyDocument(doc, "bucket", resolver)
	assert.Equal(t, getMalformedPolicyError(policyErrInvalidPrincipal), err)
}
