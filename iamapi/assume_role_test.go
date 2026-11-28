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

package iamapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/iamapi/storage"
	iamtypes "github.com/versity/versitygw/iamapi/types"
)

const (
	testAccountRootArn = "arn:aws:iam::000000000000:root"

	// allowAssumeAnyRole is an identity policy letting its holder assume any
	// role whose trust policy delegates to the account.
	allowAssumeAnyRole = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`
)

// testCaller is a credential an AssumeRole request is signed with, together
// with the ARN the service reports it as.
type testCaller struct {
	arn    string
	access string
	secret string
	token  string
}

func TestIAMApiControllerAssumeRoleSuccess(t *testing.T) {
	server := newIAMControllerTestServer(t)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	role := createAssumeRoleTestRole(t, server, "reader", trustAllowing(`{"AWS":"`+bob.arn+`"}`), nil)

	before := time.Now().UTC().Truncate(time.Second)
	resp := assumeRoleAs(t, server, bob, role.Arn, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AssumeRole status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">`) {
		t.Fatalf("success response missing STS namespace: %s", body)
	}
	if strings.Contains(body, "PackedPolicySize") {
		t.Fatalf("PackedPolicySize present without a session policy: %s", body)
	}

	var out iamtypes.AssumeRoleResponse
	unmarshalXML(t, body, &out)
	if got, want := out.Result.AssumedRoleUser.Arn, "arn:aws:sts::000000000000:assumed-role/reader/session1"; got != want {
		t.Fatalf("AssumedRoleUser.Arn = %q, want %q", got, want)
	}
	if got, want := out.Result.AssumedRoleUser.AssumedRoleId, role.RoleID+":session1"; got != want {
		t.Fatalf("AssumedRoleUser.AssumedRoleId = %q, want %q", got, want)
	}
	creds := out.Result.Credentials
	if !strings.HasPrefix(creds.AccessKeyId, "ASIA") || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		t.Fatalf("Credentials = %#v", creds)
	}
	if want := before.Add(time.Hour); creds.Expiration.Before(want) || creds.Expiration.After(want.Add(5*time.Second)) {
		t.Fatalf("Expiration = %v, want about %v", creds.Expiration, want)
	}
	if out.ResponseMetadata.RequestID == "" {
		t.Fatal("missing RequestId")
	}

	// The credentials authenticate as the assumed-role session.
	resp = doSignedSTSAction(t, server, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken,
		url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var identity iamtypes.GetCallerIdentityResponse
	unmarshalXML(t, readBody(t, resp), &identity)
	if identity.Result.Arn != out.Result.AssumedRoleUser.Arn || identity.Result.UserId != out.Result.AssumedRoleUser.AssumedRoleId {
		t.Fatalf("GetCallerIdentity = %#v, want the assumed role user %#v", identity.Result, out.Result.AssumedRoleUser)
	}
}

func TestIAMApiControllerAssumeRoleRequiresAuthentication(t *testing.T) {
	server := newIAMControllerTestServer(t)

	t.Run("unsigned", func(t *testing.T) {
		resp := doSTSAction(t, server, url.Values{
			"Action": {"AssumeRole"}, "RoleArn": {"arn:aws:iam::000000000000:role/reader"}, "RoleSessionName": {"session1"},
		})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "MissingAuthenticationToken", "Request is missing Authentication Token")
	})
	t.Run("unknown access key", func(t *testing.T) {
		resp := doSignedSTSAction(t, server, "AKIAUNKNOWNUNKNOWN000", "secret", "", url.Values{
			"Action": {"AssumeRole"}, "RoleArn": {"arn:aws:iam::000000000000:role/reader"}, "RoleSessionName": {"session1"},
		})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
	})
	t.Run("unsigned request is refused before its parameters are looked at", func(t *testing.T) {
		resp := doSTSAction(t, server, url.Values{"Action": {"AssumeRole"}})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "MissingAuthenticationToken", "Request is missing Authentication Token")
	})
	t.Run("wrong version", func(t *testing.T) {
		resp := doSignedSTSAction(t, server, testRoot.Access, testRoot.Secret, "", url.Values{"Action": {"AssumeRole"}, "Version": {iamAPIVersion}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidAction", "Could not find operation AssumeRole for version "+iamAPIVersion)
	})
}

func TestIAMApiControllerAssumeRoleValidationErrors(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	const roleArn = "arn:aws:iam::000000000000:role/does-not-exist"

	base := func(extra url.Values) url.Values {
		params := url.Values{"Action": {"AssumeRole"}, "RoleArn": {roleArn}, "RoleSessionName": {"session1"}}
		for key, values := range extra {
			if values == nil {
				params.Del(key)
				continue
			}
			params[key] = values
		}
		return params
	}

	tests := []struct {
		name        string
		params      url.Values
		wantCode    string
		wantMessage string
	}{
		{
			name:        "missing RoleArn",
			params:      base(url.Values{"RoleArn": nil}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleArn' failed to satisfy constraint: Member must not be null",
		},
		{
			name:        "RoleArn too short",
			params:      base(url.Values{"RoleArn": {"arn:aws:iam::1:role"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleArn' failed to satisfy constraint: Member must have length greater than or equal to 20",
		},
		{
			name:        "RoleArn too long",
			params:      base(url.Values{"RoleArn": {roleArn + strings.Repeat("a", 2049)}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleArn' failed to satisfy constraint: Member must have length less than or equal to 2048",
		},
		{
			name:        "RoleArn that is not an ARN",
			params:      base(url.Values{"RoleArn": {"reader-role-by-its-name"}}),
			wantCode:    "ValidationError",
			wantMessage: "reader-role-by-its-name is invalid",
		},
		{
			name:        "RoleArn with too few ARN fields",
			params:      base(url.Values{"RoleArn": {"arn:aws:iam:000000000000:role/reader"}}),
			wantCode:    "ValidationError",
			wantMessage: "arn:aws:iam:000000000000:role/reader is invalid",
		},
		{
			name:        "missing RoleSessionName",
			params:      base(url.Values{"RoleSessionName": nil}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleSessionName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:        "RoleSessionName too short",
			params:      base(url.Values{"RoleSessionName": {"a"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleSessionName' failed to satisfy constraint: Member must have length greater than or equal to 2",
		},
		{
			name:        "RoleSessionName too long",
			params:      base(url.Values{"RoleSessionName": {strings.Repeat("a", 65)}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleSessionName' failed to satisfy constraint: Member must have length less than or equal to 64",
		},
		{
			name:        "RoleSessionName with a disallowed character",
			params:      base(url.Values{"RoleSessionName": {"a/b"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value 'a/b' at 'roleSessionName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*",
		},
		{
			name:        "DurationSeconds below the minimum",
			params:      base(url.Values{"DurationSeconds": {"899"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy constraint: Member must have value greater than or equal to 900",
		},
		{
			name:        "DurationSeconds above the maximum",
			params:      base(url.Values{"DurationSeconds": {"43201"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value '43201' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200",
		},
		{
			name:     "DurationSeconds that is not a number",
			params:   base(url.Values{"DurationSeconds": {"abc"}}),
			wantCode: "MalformedInput",
		},
		{
			name:        "empty ExternalId",
			params:      base(url.Values{"ExternalId": {""}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'externalId' failed to satisfy constraint: Member must have length greater than or equal to 2",
		},
		{
			name:        "ExternalId too short",
			params:      base(url.Values{"ExternalId": {"a"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'externalId' failed to satisfy constraint: Member must have length greater than or equal to 2",
		},
		{
			name:        "ExternalId too long",
			params:      base(url.Values{"ExternalId": {strings.Repeat("a", 1225)}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'externalId' failed to satisfy constraint: Member must have length less than or equal to 1224",
		},
		{
			name:        "ExternalId with a disallowed character",
			params:      base(url.Values{"ExternalId": {"a b"}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value 'a b' at 'externalId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@:\\/-]*",
		},
		{
			name:        "empty Policy",
			params:      base(url.Values{"Policy": {""}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'policy' failed to satisfy constraint: Member must have length greater than or equal to 1",
		},
		{
			name:        "Policy too long",
			params:      base(url.Values{"Policy": {strings.Repeat("a", 2049)}}),
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'policy' failed to satisfy constraint: Member must have length less than or equal to 2048",
		},
		{
			name:        "Policy with a character outside the allowed set",
			params:      base(url.Values{"Policy": {"{\"Sid\":\"Ā\"}"}}),
			wantCode:    "ValidationError",
			wantMessage: "The specified value for policy is invalid. It must contain only printable ASCII characters.",
		},
		{
			name:        "PolicyArns",
			params:      base(url.Values{"PolicyArns.member.1.arn": {"arn:aws:iam::aws:policy/ReadOnlyAccess"}}),
			wantCode:    "InvalidInput",
			wantMessage: "PolicyArns is not supported by this implementation.",
		},
		{
			name:        "Tags",
			params:      base(url.Values{"Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"blue"}}),
			wantCode:    "InvalidInput",
			wantMessage: "Tags is not supported by this implementation.",
		},
		{
			name:        "TransitiveTagKeys",
			params:      base(url.Values{"TransitiveTagKeys.member.1": {"team"}}),
			wantCode:    "InvalidInput",
			wantMessage: "TransitiveTagKeys is not supported by this implementation.",
		},
		{
			name:        "ProvidedContexts",
			params:      base(url.Values{"ProvidedContexts.member.1.ProviderArn": {"arn:aws:iam::aws:contextProvider/IdentityCenter"}}),
			wantCode:    "InvalidInput",
			wantMessage: "ProvidedContexts is not supported by this implementation.",
		},
		{
			name:        "SourceIdentity",
			params:      base(url.Values{"SourceIdentity": {"alice"}}),
			wantCode:    "InvalidInput",
			wantMessage: "SourceIdentity is not supported by this implementation.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := doSignedSTSAction(t, server, alice.access, alice.secret, "", tt.params)
			requireSTSError(t, resp, http.StatusBadRequest, "Sender", tt.wantCode, tt.wantMessage)
		})
	}
}

func TestIAMApiControllerAssumeRoleRootRefused(t *testing.T) {
	server := newIAMControllerTestServer(t)
	role := createAssumeRoleTestRole(t, server, "reader", trustAllowing(`{"AWS":"*"}`), nil)
	root := testCaller{arn: testAccountRootArn, access: testRoot.Access, secret: testRoot.Secret}
	const refused = "Roles may not be assumed by root accounts."

	t.Run("role that trusts every principal", func(t *testing.T) {
		requireSTSError(t, assumeRoleAs(t, server, root, role.Arn, nil), http.StatusForbidden, "Sender", "AccessDenied", refused)
	})
	t.Run("role that does not exist", func(t *testing.T) {
		requireSTSError(t, assumeRoleAs(t, server, root, "arn:aws:iam::000000000000:role/nope", nil), http.StatusForbidden, "Sender", "AccessDenied", refused)
	})
	t.Run("RoleArn that is not an ARN", func(t *testing.T) {
		requireSTSError(t, assumeRoleAs(t, server, root, "reader-role-by-its-name", nil), http.StatusForbidden, "Sender", "AccessDenied", refused)
	})
	t.Run("parameter shape is still checked first", func(t *testing.T) {
		resp := assumeRoleAs(t, server, root, role.Arn, url.Values{"DurationSeconds": {"1"}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
			"1 validation error detected: Value '1' at 'durationSeconds' failed to satisfy constraint: Member must have value greater than or equal to 900")
	})
}

// TestIAMApiControllerAssumeRoleAuthorization covers how a role's trust
// policy and the caller's identity policies combine for an IAM user.
func TestIAMApiControllerAssumeRoleAuthorization(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// alice may assume any role that delegates to the account, bob has no
	// policy at all, and carol is allowed everything except one role.
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	carol := newAssumeRoleTestUser(t, server, "carol", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"},
		{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/trust-carol"}]}`)
	scoped := newAssumeRoleTestUser(t, server, "scoped", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/team/*"}]}`)

	roles := map[string]iamtypes.Role{
		"trust-root":    createAssumeRoleTestRole(t, server, "trust-root", trustAllowing(`{"AWS":"`+testAccountRootArn+`"}`), nil),
		"trust-account": createAssumeRoleTestRole(t, server, "trust-account", trustAllowing(`{"AWS":"000000000000"}`), nil),
		"trust-bob":     createAssumeRoleTestRole(t, server, "trust-bob", trustAllowing(`{"AWS":"`+bob.arn+`"}`), nil),
		"trust-carol":   createAssumeRoleTestRole(t, server, "trust-carol", trustAllowing(`{"AWS":"`+carol.arn+`"}`), nil),
		"trust-star":    createAssumeRoleTestRole(t, server, "trust-star", trustAllowing(`{"AWS":"*"}`), nil),
		"deny-alice": createAssumeRoleTestRole(t, server, "deny-alice", `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Principal":{"AWS":"`+testAccountRootArn+`"},"Action":"sts:AssumeRole"},
			{"Effect":"Deny","Principal":{"AWS":"`+alice.arn+`"},"Action":"sts:AssumeRole"}]}`, nil),
		"deny-root": createAssumeRoleTestRole(t, server, "deny-root", `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Principal":{"AWS":"`+bob.arn+`"},"Action":"sts:AssumeRole"},
			{"Effect":"Deny","Principal":{"AWS":"`+testAccountRootArn+`"},"Action":"sts:AssumeRole"}]}`, nil),
		"web-identity-only": createAssumeRoleTestRole(t, server, "web-identity-only", `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, nil),
		"service-only": createAssumeRoleTestRole(t, server, "service-only", trustAllowing(`{"Service":"sts.amazonaws.com"}`), nil),
		"principal-arn-condition": createAssumeRoleTestRole(t, server, "principal-arn-condition", `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Principal":{"AWS":"`+testAccountRootArn+`"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:PrincipalArn":"`+bob.arn+`"}}}]}`, nil),
		"pathed": createAssumeRoleTestRole(t, server, "pathed", trustAllowing(`{"AWS":"`+testAccountRootArn+`"}`), url.Values{"Path": {"/team/sub/"}}),
	}

	tests := []struct {
		name    string
		caller  testCaller
		role    string
		allowed bool
	}{
		{"account trust with an identity allow", alice, "trust-root", true},
		{"account trust without an identity allow", bob, "trust-root", false},
		{"bare account id trust with an identity allow", alice, "trust-account", true},
		{"bare account id trust without an identity allow", bob, "trust-account", false},
		{"user trust needs no identity allow", bob, "trust-bob", true},
		{"identity allow without trust", alice, "trust-bob", false},
		{"user trust with an identity deny", carol, "trust-carol", false},
		{"identity deny on another role does not spill over", carol, "trust-root", true},
		{"wildcard trust needs no identity allow", bob, "trust-star", true},
		{"trust deny naming the caller", alice, "deny-alice", false},
		{"trust deny naming someone else", carol, "deny-alice", true},
		{"trust deny naming the account hits a directly trusted user", bob, "deny-root", false},
		{"trust statement for another action", alice, "web-identity-only", false},
		{"trust naming only a service", alice, "service-only", false},
		{"condition on an account principal still only delegates", bob, "principal-arn-condition", false},
		{"condition on an account principal not met", alice, "principal-arn-condition", false},
		{"identity allow scoped to the role's path", scoped, "pathed", true},
		{"identity allow scoped to another path", scoped, "trust-root", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireAssumeRoleOutcome(t, assumeRoleAs(t, server, tt.caller, roles[tt.role].Arn, nil), tt.caller, roles[tt.role].Arn, tt.allowed)
		})
	}
}

// A RoleArn that names no role is refused exactly as a role the caller is
// not trusted by, so the response never reveals whether a role exists.
func TestIAMApiControllerAssumeRoleUnresolvedRoleArn(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	createAssumeRoleTestRole(t, server, "reader", trustAllowing(`{"AWS":"*"}`), nil)
	createAssumeRoleTestRole(t, server, "pathed", trustAllowing(`{"AWS":"*"}`), url.Values{"Path": {"/team/"}})

	for name, roleArn := range map[string]string{
		"role that does not exist":   "arn:aws:iam::000000000000:role/does-not-exist",
		"role name in another case":  "arn:aws:iam::000000000000:role/READER",
		"role without its path":      "arn:aws:iam::000000000000:role/pathed",
		"role with another path":     "arn:aws:iam::000000000000:role/other/pathed",
		"role in another account":    "arn:aws:iam::111111111111:role/reader",
		"role with a trailing slash": "arn:aws:iam::000000000000:role/reader/",
		"user arn":                   alice.arn,
		"account root arn":           testAccountRootArn,
		"assumed-role arn":           "arn:aws:sts::000000000000:assumed-role/reader/session1",
		"role arn with a wildcard":   "arn:aws:iam::000000000000:role/read*",
		"another partition":          "arn:aws-cn:iam::000000000000:role/reader",
	} {
		t.Run(name, func(t *testing.T) {
			requireAssumeRoleOutcome(t, assumeRoleAs(t, server, alice, roleArn, nil), alice, roleArn, false)
		})
	}

	t.Run("the role's own arn", func(t *testing.T) {
		requireAssumeRoleOutcome(t, assumeRoleAs(t, server, alice, "arn:aws:iam::000000000000:role/team/pathed", nil), alice, "", true)
	})
}

// sts:ExternalId and sts:RoleSessionName are visible to the trust policy and
// to the caller's identity policies alike.
func TestIAMApiControllerAssumeRoleRequestConditionKeys(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	dave := newAssumeRoleTestUser(t, server, "dave", `{"Version":"2012-10-17","Statement":[
		{"Sid":"external","Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/open","Condition":{"StringEquals":{"sts:ExternalId":"identity-side"}}},
		{"Sid":"tagged","Effect":"Allow","Action":"sts:AssumeRole","Resource":"*","Condition":{"StringEquals":{"iam:ResourceTag/team":"blue"}}},
		{"Sid":"named","Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/untagged","Condition":{"StringEquals":{"sts:RoleSessionName":"named"}}}]}`)

	accountTrust := trustAllowing(`{"AWS":"` + testAccountRootArn + `"}`)
	externalID := createAssumeRoleTestRole(t, server, "external-id", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"`+testAccountRootArn+`"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-123"}}}]}`, nil)
	denyWithout := createAssumeRoleTestRole(t, server, "deny-without-external-id", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"`+testAccountRootArn+`"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringNotEquals":{"sts:ExternalId":"secret-123"}}}]}`, nil)
	sessionName := createAssumeRoleTestRole(t, server, "session-name", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"`+testAccountRootArn+`"},"Action":"sts:AssumeRole","Condition":{"StringLike":{"sts:RoleSessionName":"${aws:username}"}}}]}`, nil)
	open := createAssumeRoleTestRole(t, server, "open", accountTrust, nil)
	tagged := createAssumeRoleTestRole(t, server, "tagged", accountTrust, url.Values{"Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"blue"}})
	untagged := createAssumeRoleTestRole(t, server, "untagged", accountTrust, nil)

	tests := []struct {
		name    string
		caller  testCaller
		role    iamtypes.Role
		extra   url.Values
		allowed bool
	}{
		{"trust requires an external id that is missing", alice, externalID, nil, false},
		{"trust requires an external id that is wrong", alice, externalID, url.Values{"ExternalId": {"wrong-1"}}, false},
		{"trust requires an external id in another case", alice, externalID, url.Values{"ExternalId": {"SECRET-123"}}, false},
		{"trust requires an external id that matches", alice, externalID, url.Values{"ExternalId": {"secret-123"}}, true},
		{"an external id nobody asked for is ignored", alice, open, url.Values{"ExternalId": {"whatever"}}, true},
		{"trust denies a missing external id", alice, denyWithout, nil, false},
		{"trust does not deny the matching external id", alice, denyWithout, url.Values{"ExternalId": {"secret-123"}}, true},
		{"trust requires the session to be named after the user", alice, sessionName, nil, false},
		{"session named after the user", alice, sessionName, url.Values{"RoleSessionName": {"alice"}}, true},
		{"identity policy requires an external id that is missing", dave, open, nil, false},
		{"identity policy requires an external id that matches", dave, open, url.Values{"ExternalId": {"identity-side"}}, true},
		{"identity policy scoped to the role's tag", dave, tagged, nil, true},
		{"identity policy scoped to a tag the role lacks", dave, untagged, nil, false},
		{"identity policy scoped to a session name", dave, untagged, url.Values{"RoleSessionName": {"named"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireAssumeRoleOutcome(t, assumeRoleAs(t, server, tt.caller, tt.role.Arn, tt.extra), tt.caller, tt.role.Arn, tt.allowed)
		})
	}
}

func TestIAMApiControllerAssumeRoleDuration(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	accountTrust := trustAllowing(`{"AWS":"` + testAccountRootArn + `"}`)
	hour := createAssumeRoleTestRole(t, server, "one-hour", accountTrust, nil)
	twoHours := createAssumeRoleTestRole(t, server, "two-hours", accountTrust, url.Values{"MaxSessionDuration": {"7200"}})

	const exceedsRoleMax = "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."

	t.Run("default is one hour whatever the role allows", func(t *testing.T) {
		before := time.Now().UTC().Truncate(time.Second)
		creds := requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, twoHours.Arn, nil))
		if want := before.Add(time.Hour); creds.Expiration.Before(want) || creds.Expiration.After(want.Add(5*time.Second)) {
			t.Fatalf("Expiration = %v, want about %v", creds.Expiration, want)
		}
	})
	t.Run("up to the role's maximum", func(t *testing.T) {
		before := time.Now().UTC().Truncate(time.Second)
		creds := requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, twoHours.Arn, url.Values{"DurationSeconds": {"7200"}}))
		if want := before.Add(2 * time.Hour); creds.Expiration.Before(want) || creds.Expiration.After(want.Add(5*time.Second)) {
			t.Fatalf("Expiration = %v, want about %v", creds.Expiration, want)
		}
	})
	t.Run("minimum", func(t *testing.T) {
		requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, hour.Arn, url.Values{"DurationSeconds": {"900"}}))
	})
	t.Run("above the role's maximum", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, twoHours.Arn, url.Values{"DurationSeconds": {"7201"}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError", exceedsRoleMax)
	})
	t.Run("above the default maximum", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, hour.Arn, url.Values{"DurationSeconds": {"3601"}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError", exceedsRoleMax)
	})
	t.Run("a caller that is not authorized is told only that", func(t *testing.T) {
		resp := assumeRoleAs(t, server, bob, hour.Arn, url.Values{"DurationSeconds": {"3601"}})
		requireAssumeRoleOutcome(t, resp, bob, hour.Arn, false)
	})
	t.Run("the duration is reported before a malformed session policy", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, hour.Arn, url.Values{"DurationSeconds": {"3601"}, "Policy": {"not json"}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError", exceedsRoleMax)
	})
}

func TestIAMApiControllerAssumeRoleSessionPolicy(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	role := createAssumeRoleTestRole(t, server, "user-admin", trustAllowing(`{"AWS":"`+testAccountRootArn+`"}`), nil)
	putAssumeRoleTestRolePolicy(t, server, "user-admin", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GetUser","iam:ListUsers"],"Resource":"*"}]}`)

	const listUsersOnly = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}`

	t.Run("narrows what the role allows", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, role.Arn, url.Values{"Policy": {listUsersOnly}})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("AssumeRole status = %d, body=%s", resp.StatusCode, body)
		}
		var out iamtypes.AssumeRoleResponse
		unmarshalXML(t, body, &out)
		if out.Result.PackedPolicySize == nil || *out.Result.PackedPolicySize != int64(len(listUsersOnly)*100/2048) {
			t.Fatalf("PackedPolicySize = %v, want %d", out.Result.PackedPolicySize, len(listUsersOnly)*100/2048)
		}
		creds := out.Result.Credentials

		resp = doSignedIAMActionAs(t, server, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken, url.Values{"Action": {"ListUsers"}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ListUsers status = %d, want the session policy to allow it; body=%s", resp.StatusCode, readBody(t, resp))
		}
		resp = doSignedIAMActionAs(t, server, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken, url.Values{"Action": {"GetUser"}, "UserName": {"alice"}})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GetUser status = %d, want the session policy to deny what it does not list; body=%s", resp.StatusCode, readBody(t, resp))
		}
	})
	t.Run("without one the role's own policies apply", func(t *testing.T) {
		creds := requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, role.Arn, nil))
		resp := doSignedIAMActionAs(t, server, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken, url.Values{"Action": {"GetUser"}, "UserName": {"alice"}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GetUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
		}
	})
	t.Run("single statement object and actions of another service", func(t *testing.T) {
		const document = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["kms:Decrypt","s3:GetObject"],"Resource":"*"}}`
		requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, role.Arn, url.Values{"Policy": {document}}))
	})

	malformed := []struct {
		name     string
		document string
		message  string
	}{
		{"not json", `not json`, "Syntax errors in policy."},
		{"no statement", `{"Version":"2012-10-17"}`, "Syntax errors in policy."},
		{"principal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`, "Policy document should not specify a principal."},
		{"no resource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`, "Policy statement must contain resources."},
	}
	for _, tt := range malformed {
		t.Run("malformed: "+tt.name, func(t *testing.T) {
			resp := assumeRoleAs(t, server, alice, role.Arn, url.Values{"Policy": {tt.document}})
			requireSTSError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument", tt.message)
		})
	}
	t.Run("a caller that is not authorized never learns its policy is malformed", func(t *testing.T) {
		resp := assumeRoleAs(t, server, bob, role.Arn, url.Values{"Policy": {"not json"}})
		requireAssumeRoleOutcome(t, resp, bob, role.Arn, false)
	})
}

func TestIAMApiControllerAssumeRoleMFA(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	role := createAssumeRoleTestRole(t, server, "reader", trustAllowing(`{"AWS":"`+testAccountRootArn+`"}`), nil)

	const (
		unverifiable = "MultiFactorAuthentication failed, unable to validate MFA code.  Please verify your MFA serial number is valid and associated with this user."
		incomplete   = "MultiFactorAuthentication failed, must provide both MFA serial number and one time pass code."
		serial       = "arn:aws:iam::000000000000:mfa/alice"
	)

	t.Run("serial number and token code", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, role.Arn, url.Values{"SerialNumber": {serial}, "TokenCode": {"123456"}})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", unverifiable)
	})
	t.Run("serial number alone", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, role.Arn, url.Values{"SerialNumber": {serial}})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", incomplete)
	})
	t.Run("token code alone", func(t *testing.T) {
		resp := assumeRoleAs(t, server, alice, role.Arn, url.Values{"TokenCode": {"123456"}})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", incomplete)
	})
	t.Run("reported before the caller is found unauthorized", func(t *testing.T) {
		resp := assumeRoleAs(t, server, bob, role.Arn, url.Values{"SerialNumber": {serial}, "TokenCode": {"123456"}})
		requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", unverifiable)
	})
}

// TestIAMApiControllerAssumeRoleChaining covers a role session assuming
// another role.
func TestIAMApiControllerAssumeRoleChaining(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	accountTrust := trustAllowing(`{"AWS":"` + testAccountRootArn + `"}`)

	// plain has no policy of its own; chainer may assume any role.
	plain := createAssumeRoleTestRole(t, server, "plain", accountTrust, nil)
	chainer := createAssumeRoleTestRole(t, server, "chainer", accountTrust, nil)
	putAssumeRoleTestRolePolicy(t, server, "chainer", allowAssumeAnyRole)

	trustsRole := createAssumeRoleTestRole(t, server, "trusts-role", trustAllowing(`{"AWS":"`+plain.Arn+`"}`), nil)
	trustsSession := createAssumeRoleTestRole(t, server, "trusts-session", trustAllowing(`{"AWS":"arn:aws:sts::000000000000:assumed-role/plain/first"}`), nil)
	trustsStar := createAssumeRoleTestRole(t, server, "trusts-star", trustAllowing(`{"AWS":"*"}`), nil)
	trustsAccount := createAssumeRoleTestRole(t, server, "trusts-account", accountTrust, url.Values{"MaxSessionDuration": {"7200"}})
	trustsAlice := createAssumeRoleTestRole(t, server, "trusts-alice", trustAllowing(`{"AWS":"`+alice.arn+`"}`), nil)

	const (
		s3Only  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
		stsOnly = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`
		stsDeny = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}]}`
	)
	session := func(role iamtypes.Role, name, sessionPolicy string) testCaller {
		t.Helper()
		extra := url.Values{"RoleSessionName": {name}}
		if sessionPolicy != "" {
			extra.Set("Policy", sessionPolicy)
		}
		creds := requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, role.Arn, extra))
		return testCaller{
			arn:    "arn:aws:sts::000000000000:assumed-role/" + role.RoleName + "/" + name,
			access: creds.AccessKeyId, secret: creds.SecretAccessKey, token: creds.SessionToken,
		}
	}

	plainFirst := session(plain, "first", "")
	plainSecond := session(plain, "second", "")
	plainNarrowed := session(plain, "first", s3Only)
	plainDenied := session(plain, "first", stsDeny)
	chainerOpen := session(chainer, "first", "")
	chainerNarrowed := session(chainer, "first", s3Only)
	chainerSTS := session(chainer, "first", stsOnly)

	tests := []struct {
		name    string
		caller  testCaller
		role    iamtypes.Role
		allowed bool
	}{
		{"trust names the session's role", plainFirst, trustsRole, true},
		{"trust names the role, so any session of it", plainSecond, trustsRole, true},
		{"trust names the role but the session policy does not allow it", plainNarrowed, trustsRole, false},
		{"trust names the session itself", plainFirst, trustsSession, true},
		{"trust names another session of the role", plainSecond, trustsSession, false},
		{"trust naming the session is not limited by its session policy", plainNarrowed, trustsSession, true},
		{"trust naming the session still yields to a session policy deny", plainDenied, trustsSession, false},
		{"wildcard trust is not limited by the session policy", plainNarrowed, trustsStar, true},
		{"account trust and a role that allows nothing", plainFirst, trustsAccount, false},
		{"account trust and a role that allows it", chainerOpen, trustsAccount, true},
		{"account trust, allowing role, session policy that does not", chainerNarrowed, trustsAccount, false},
		{"account trust, allowing role, session policy that does", chainerSTS, trustsAccount, true},
		{"trust naming a user never covers a session", chainerOpen, trustsAlice, false},
		{"a role is not implicitly trusted by itself", plainFirst, plain, false},
		{"a role may assume itself through the ordinary rules", chainerOpen, chainer, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := assumeRoleAs(t, server, tt.caller, tt.role.Arn, url.Values{"RoleSessionName": {"chained"}})
			requireAssumeRoleOutcome(t, resp, tt.caller, tt.role.Arn, tt.allowed)
		})
	}

	const (
		exceedsChaining = "The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining."
		exceedsRoleMax  = "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."
	)
	t.Run("a chained session may last an hour", func(t *testing.T) {
		requireAssumeRoleCredentials(t, assumeRoleAs(t, server, chainerOpen, trustsAccount.Arn, url.Values{"DurationSeconds": {"3600"}}))
	})
	t.Run("a chained session may not outlast an hour even when the role allows it", func(t *testing.T) {
		resp := assumeRoleAs(t, server, chainerOpen, trustsAccount.Arn, url.Values{"DurationSeconds": {"3601"}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError", exceedsChaining)
	})
	t.Run("the role's own maximum is reported first", func(t *testing.T) {
		resp := assumeRoleAs(t, server, chainerOpen, trustsAccount.Arn, url.Values{"DurationSeconds": {"7201"}})
		requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError", exceedsRoleMax)
	})
	t.Run("a user is not limited to an hour", func(t *testing.T) {
		requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, trustsAccount.Arn, url.Values{"DurationSeconds": {"7200"}}))
	})
}

// A session that has outlived its role can assume no role at all, not even
// one whose trust policy names every principal, and recreating the role
// under the same name must not hand its old sessions the trust the new one
// was given.
func TestIAMApiControllerAssumeRoleSessionOfDeletedRole(t *testing.T) {
	server := newIAMControllerTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	accountTrust := trustAllowing(`{"AWS":"` + testAccountRootArn + `"}`)

	first := createAssumeRoleTestRole(t, server, "caller", accountTrust, nil)
	creds := requireAssumeRoleCredentials(t, assumeRoleAs(t, server, alice, first.Arn, nil))
	stale := testCaller{
		arn:    "arn:aws:sts::000000000000:assumed-role/caller/session1",
		access: creds.AccessKeyId, secret: creds.SecretAccessKey, token: creds.SessionToken,
	}
	targets := map[string]string{
		"a role trusting the caller's role": createAssumeRoleTestRole(t, server, "target", trustAllowing(`{"AWS":"`+first.Arn+`"}`), nil).Arn,
		"a role trusting every principal":   createAssumeRoleTestRole(t, server, "open", trustAllowing(`{"AWS":"*"}`), nil).Arn,
	}
	requireOutcomes := func(t *testing.T, allowed bool) {
		t.Helper()
		for name, target := range targets {
			t.Run(name, func(t *testing.T) {
				requireAssumeRoleOutcome(t, assumeRoleAs(t, server, stale, target, nil), stale, target, allowed)
			})
		}
	}

	t.Run("while the role exists", func(t *testing.T) { requireOutcomes(t, true) })

	if resp := doIAMAction(t, server, url.Values{"Action": {"DeleteRole"}, "RoleName": {"caller"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	t.Run("after the role was deleted", func(t *testing.T) { requireOutcomes(t, false) })

	createAssumeRoleTestRole(t, server, "caller", accountTrust, nil)
	t.Run("after the role was recreated", func(t *testing.T) { requireOutcomes(t, false) })
}

// A store that cannot answer is a retryable server fault, not AccessDenied.
func TestIAMApiControllerAssumeRoleStoreFailure(t *testing.T) {
	server, faulty := newFaultyStoreTestServer(t)
	alice := newAssumeRoleTestUser(t, server, "alice", allowAssumeAnyRole)
	role := createAssumeRoleTestRole(t, server, "reader", trustAllowing(`{"AWS":"`+testAccountRootArn+`"}`), nil)

	faulty.fail = func(method, _ string) error {
		if method == "GetRole" {
			return errStoreDown
		}
		return nil
	}
	resp := assumeRoleAs(t, server, alice, role.Arn, nil)
	requireSTSError(t, resp, http.StatusInternalServerError, "Receiver", "InternalFailure", internalFailureMessage)
}

// TestIAMApiControllerTrustPolicyPrincipalsMustResolve covers the write-time
// check CreateRole and UpdateAssumeRolePolicy make on a trust policy's AWS
// principals.
func TestIAMApiControllerTrustPolicyPrincipalsMustResolve(t *testing.T) {
	server := newIAMControllerTestServer(t)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	createAssumeRoleTestRole(t, server, "existing", trustAllowing(`{"AWS":"*"}`), url.Values{"Path": {"/team/"}})
	createAssumeRoleTestRole(t, server, "updated", trustAllowing(`{"AWS":"*"}`), nil)

	tests := []struct {
		name      string
		principal string
		// invalid is the principal value the error names, "" when the
		// document is accepted.
		invalid string
	}{
		{"every principal", `{"AWS":"*"}`, ""},
		{"account root", `{"AWS":"` + testAccountRootArn + `"}`, ""},
		{"bare account id", `{"AWS":"000000000000"}`, ""},
		{"existing user", `{"AWS":"` + bob.arn + `"}`, ""},
		{"existing role with its path", `{"AWS":"arn:aws:iam::000000000000:role/team/existing"}`, ""},
		{"session of an existing role", `{"AWS":"arn:aws:sts::000000000000:assumed-role/existing/anything"}`, ""},
		{"several that all resolve", `{"AWS":["` + testAccountRootArn + `","` + bob.arn + `"]}`, ""},
		{"service and federated principals are not looked up", `{"Service":"sts.amazonaws.com","Federated":"arn:aws:iam::000000000000:oidc-provider/unregistered.example.com"}`, ""},

		{"user that does not exist", `{"AWS":"arn:aws:iam::000000000000:user/nobody"}`, "arn:aws:iam::000000000000:user/nobody"},
		{"user in another case", `{"AWS":"arn:aws:iam::000000000000:user/BOB"}`, "arn:aws:iam::000000000000:user/BOB"},
		{"role that does not exist", `{"AWS":"arn:aws:iam::000000000000:role/nope"}`, "arn:aws:iam::000000000000:role/nope"},
		{"role without its path", `{"AWS":"arn:aws:iam::000000000000:role/existing"}`, "arn:aws:iam::000000000000:role/existing"},
		{"session of a role that does not exist", `{"AWS":"arn:aws:sts::000000000000:assumed-role/nope/anything"}`, "arn:aws:sts::000000000000:assumed-role/nope/anything"},
		{"session name with a wildcard", `{"AWS":"arn:aws:sts::000000000000:assumed-role/existing/*"}`, "arn:aws:sts::000000000000:assumed-role/existing/*"},
		{"wildcard inside an arn", `{"AWS":"arn:aws:iam::000000000000:user/*"}`, "arn:aws:iam::000000000000:user/*"},
		{"another account's root", `{"AWS":"arn:aws:iam::123456789012:root"}`, "arn:aws:iam::123456789012:root"},
		{"another account's id", `{"AWS":"123456789012"}`, "123456789012"},
		{"group arn", `{"AWS":"arn:aws:iam::000000000000:group/admins"}`, "arn:aws:iam::000000000000:group/admins"},
		{"not an arn", `{"AWS":"foo"}`, "foo"},
		{"empty", `{"AWS":""}`, ""},
		{"one of several that does not resolve", `{"AWS":["` + bob.arn + `","arn:aws:iam::000000000000:user/nobody"]}`, "arn:aws:iam::000000000000:user/nobody"},
	}
	for i, tt := range tests {
		// An empty principal is the one rejected case whose error names "".
		rejected := tt.invalid != "" || tt.name == "empty"
		wantMessage := `Invalid principal in policy: "AWS":"` + tt.invalid + `"`

		t.Run("CreateRole: "+tt.name, func(t *testing.T) {
			resp := doIAMAction(t, server, url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"created-" + string(rune('a'+i))},
				"AssumeRolePolicyDocument": {trustAllowing(tt.principal)},
			})
			if !rejected {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CreateRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
				}
				return
			}
			requireIAMError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument", wantMessage)
		})
		t.Run("UpdateAssumeRolePolicy: "+tt.name, func(t *testing.T) {
			resp := doIAMAction(t, server, url.Values{
				"Action":         {"UpdateAssumeRolePolicy"},
				"RoleName":       {"updated"},
				"PolicyDocument": {trustAllowing(tt.principal)},
			})
			if !rejected {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("UpdateAssumeRolePolicy status = %d, body=%s", resp.StatusCode, readBody(t, resp))
				}
				return
			}
			requireIAMError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument", wantMessage)
		})
	}

	t.Run("a deny statement's principals are checked too", func(t *testing.T) {
		resp := doIAMAction(t, server, url.Values{
			"Action":   {"CreateRole"},
			"RoleName": {"deny-unresolved"},
			"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/nobody"},"Action":"sts:AssumeRole"}]}`},
		})
		requireIAMError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument",
			`Invalid principal in policy: "AWS":"arn:aws:iam::000000000000:user/nobody"`)
	})
	t.Run("a role cannot name itself before it exists", func(t *testing.T) {
		resp := doIAMAction(t, server, url.Values{
			"Action":                   {"CreateRole"},
			"RoleName":                 {"self"},
			"AssumeRolePolicyDocument": {trustAllowing(`{"AWS":"arn:aws:iam::000000000000:role/self"}`)},
		})
		requireIAMError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument",
			`Invalid principal in policy: "AWS":"arn:aws:iam::000000000000:role/self"`)
	})
}

func TestIAMApiControllerTrustPolicyActionsAreAFixedList(t *testing.T) {
	server := newIAMControllerTestServer(t)
	createAssumeRoleTestRole(t, server, "updated", trustAllowing(`{"AWS":"*"}`), nil)
	const wildcard = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:*"}]}`
	const refused = "AssumeRole policy may only specify STS AssumeRole actions."

	resp := doIAMAction(t, server, url.Values{"Action": {"CreateRole"}, "RoleName": {"wildcard"}, "AssumeRolePolicyDocument": {wildcard}})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument", refused)

	resp = doIAMAction(t, server, url.Values{"Action": {"UpdateAssumeRolePolicy"}, "RoleName": {"updated"}, "PolicyDocument": {wildcard}})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "MalformedPolicyDocument", refused)
}

// A role stored before trust actions were restricted keeps the meaning its
// document always had, wildcard action included.
func TestIAMApiControllerAssumeRoleStoredWildcardTrustAction(t *testing.T) {
	server := newIAMControllerTestServer(t)
	bob := newAssumeRoleTestUser(t, server, "bob", "")
	role := createAssumeRoleTestRole(t, server, "legacy", trustAllowing(`{"AWS":"*"}`), nil)

	// Written straight to the store, as a release that still accepted a
	// wildcard action would have left it.
	const stored = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/bob"},"Action":"sts:*"}]}`
	if _, err := server.store.UpdateAssumeRolePolicy(context.Background(), storage.UpdateAssumeRolePolicyInput{
		RoleName:       role.RoleName,
		PolicyDocument: stored,
	}); err != nil {
		t.Fatalf("UpdateAssumeRolePolicy: %v", err)
	}

	requireAssumeRoleOutcome(t, assumeRoleAs(t, server, bob, role.Arn, nil), bob, role.Arn, true)
}

func newAssumeRoleTestUser(t *testing.T, server *IAMApiServer, userName, policyDocument string) testCaller {
	t.Helper()
	access, secret := createTestUserWithAccessKey(t, server, userName, policyDocument)
	return testCaller{arn: "arn:aws:iam::000000000000:user/" + userName, access: access, secret: secret}
}

func createAssumeRoleTestRole(t *testing.T, server *IAMApiServer, roleName, trustDocument string, extra url.Values) iamtypes.Role {
	t.Helper()
	params := url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {roleName},
		"AssumeRolePolicyDocument": {trustDocument},
	}
	for key, values := range extra {
		params[key] = values
	}
	resp := doIAMActionPost(t, server, params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole %q status = %d, body=%s", roleName, resp.StatusCode, readBody(t, resp))
	}
	var out iamtypes.CreateRoleResponse
	unmarshalXML(t, readBody(t, resp), &out)
	return *out.Result.Role
}

func putAssumeRoleTestRolePolicy(t *testing.T, server *IAMApiServer, roleName, policyDocument string) {
	t.Helper()
	resp := doIAMActionPost(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {roleName},
		"PolicyName":     {"test-policy"},
		"PolicyDocument": {policyDocument},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PutRolePolicy %q status = %d, body=%s", roleName, resp.StatusCode, readBody(t, resp))
	}
}

// trustAllowing is a trust policy with one statement allowing principal, a
// JSON Principal object, to call sts:AssumeRole.
func trustAllowing(principal string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRole"}]}`
}

// assumeRoleAs sends an AssumeRole request for roleArn signed by caller.
// extra overrides or adds parameters; the session is named "session1"
// unless it says otherwise.
func assumeRoleAs(t *testing.T, server *IAMApiServer, caller testCaller, roleArn string, extra url.Values) *http.Response {
	t.Helper()
	params := url.Values{"Action": {"AssumeRole"}, "RoleArn": {roleArn}, "RoleSessionName": {"session1"}}
	for key, values := range extra {
		params[key] = values
	}
	return doSignedSTSAction(t, server, caller.access, caller.secret, caller.token, params)
}

// requireAssumeRoleOutcome checks resp is a success when allowed, and
// otherwise the one error AssumeRole reports for every refusal.
func requireAssumeRoleOutcome(t *testing.T, resp *http.Response, caller testCaller, roleArn string, allowed bool) {
	t.Helper()
	if allowed {
		requireAssumeRoleCredentials(t, resp)
		return
	}
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: "+caller.arn+" is not authorized to perform: sts:AssumeRole on resource: "+roleArn)
}

func requireAssumeRoleCredentials(t *testing.T, resp *http.Response) iamtypes.Credentials {
	t.Helper()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AssumeRole status = %d, body=%s", resp.StatusCode, body)
	}
	var out iamtypes.AssumeRoleResponse
	unmarshalXML(t, body, &out)
	if out.Result.Credentials.AccessKeyId == "" {
		t.Fatalf("AssumeRole returned no credentials: %s", body)
	}
	return out.Result.Credentials
}
