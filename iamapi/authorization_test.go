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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	iamtypes "github.com/versity/versitygw/iamapi/types"
)

// signedIAMActionAs signs params (as an "iam"-service request, matching
// every non-STS action) with an arbitrary access key/secret/session token,
// unlike signedIAMRequest/querySignedIAMRequest which always sign as root.
func signedIAMActionAs(t *testing.T, access, secret, sessionToken string, params url.Values) *http.Request {
	t.Helper()
	if !params.Has("Version") {
		params.Set("Version", iamAPIVersion)
	}

	body := []byte(params.Encode())
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])

	creds := aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: sessionToken}
	signer := awsv4.NewSigner()
	if err := signer.SignHTTP(context.Background(), creds, req, payloadHash, "iam", iammiddleware.SigningRegion, time.Now().UTC()); err != nil {
		t.Fatalf("sign iam request: %v", err)
	}
	return req
}

func doSignedIAMActionAs(t *testing.T, server *IAMApiServer, access, secret, sessionToken string, params url.Values) *http.Response {
	t.Helper()
	req := signedIAMActionAs(t, access, secret, sessionToken, params)
	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// createTestUserWithAccessKey creates a user (and, if policyDocument != "",
// an inline policy for it) via root, and an access key for it, returning the
// key material tests sign requests with.
func createTestUserWithAccessKey(t *testing.T, server *IAMApiServer, userName, policyDocument string) (accessKeyID, secretAccessKey string) {
	t.Helper()

	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {userName}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	if policyDocument != "" {
		resp := doIAMActionPost(t, server, url.Values{
			"Action":         {"PutUserPolicy"},
			"UserName":       {userName},
			"PolicyName":     {"test-policy"},
			"PolicyDocument": {policyDocument},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PutUserPolicy status = %d, body=%s", resp.StatusCode, readBody(t, resp))
		}
	}

	resp := doIAMAction(t, server, url.Values{"Action": {"CreateAccessKey"}, "UserName": {userName}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out iamtypes.CreateAccessKeyResponse
	unmarshalXML(t, readBody(t, resp), &out)
	return out.Result.AccessKey.AccessKeyId, out.Result.AccessKey.SecretAccessKey
}

func TestVerifyIAMPolicyAllowsGrantedAction(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "alice",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func TestVerifyIAMPolicyDeniesUngrantedAction(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "bob",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"CreateUser"}, "UserName": {"carol"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/bob is not authorized to perform: iam:CreateUser because no identity-based policy allows the iam:CreateUser action")
}

func TestVerifyIAMPolicyDeniesUserWithNoPolicies(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "dave", "")

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"dave"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/dave is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")
}

func TestVerifyIAMAuthRejectsInactiveAccessKey(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "erin",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)

	resp := doIAMAction(t, server, url.Values{
		"Action":      {"UpdateAccessKey"},
		"UserName":    {"erin"},
		"AccessKeyId": {accessKeyID},
		"Status":      {"Inactive"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UpdateAccessKey status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"erin"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
}

func TestVerifyIAMAuthRejectsUnknownAccessKey(t *testing.T) {
	server := newIAMControllerTestServer(t)

	resp := doSignedIAMActionAs(t, server, "unknown-access-key-id", "does-not-matter", "", url.Values{"Action": {"ListUsers"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
}

func TestIAMApiControllerGetCallerIdentityWithUser(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "frank", "")

	resp := doSignedSTSAction(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out iamtypes.GetCallerIdentityResponse
	unmarshalXML(t, readBody(t, resp), &out)
	if out.Result.Arn != "arn:aws:iam::000000000000:user/frank" {
		t.Fatalf("GetCallerIdentity user Arn = %q", out.Result.Arn)
	}
	if out.Result.Account != "000000000000" {
		t.Fatalf("GetCallerIdentity user Account = %q", out.Result.Account)
	}
}

// createTestSession creates a role with rolePolicyDocument as its sole
// inline policy and directly stores a session assuming it (bypassing
// AssumeRoleWithWebIdentity's OIDC token verification, which needs a live
// provider) carrying sessionPolicyDocument as its session policy.
func createTestSession(t *testing.T, server *IAMApiServer, roleName, rolePolicyDocument, sessionPolicyDocument string) iamtypes.Session {
	t.Helper()

	resp := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {roleName},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}`},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var createRoleOut iamtypes.CreateRoleResponse
	unmarshalXML(t, readBody(t, resp), &createRoleOut)
	role := createRoleOut.Result.Role

	resp = doIAMActionPost(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {roleName},
		"PolicyName":     {"test-policy"},
		"PolicyDocument": {rolePolicyDocument},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PutRolePolicy status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIATEST" + roleName,
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         role.Arn,
		RoleName:        roleName,
		RoleID:          role.RoleID,
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
		Policy:          sessionPolicyDocument,
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return session
}

func TestVerifyIAMPolicySessionUsesRolePolicy(t *testing.T) {
	server := newIAMControllerTestServer(t)
	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"looked-up"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	session := createTestSession(t, server, "role-a",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`, "")

	// UserName names an existing user (rather than the caller's own
	// self-lookup form) so this specifically exercises the role's
	// identity-based policy granting iam:GetUser, independent of GetUser's
	// separate self-lookup-vs-named-lookup behavior.
	resp := doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetUser"}, "UserName": {"looked-up"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser (role-granted) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	resp = doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"CreateUser"}, "UserName": {"someone"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:sts::000000000000:assumed-role/role-a/my-session is not authorized to perform: iam:CreateUser because no identity-based policy allows the iam:CreateUser action")
}

func TestVerifyIAMPolicySessionPolicyCanOnlyNarrowRolePermissions(t *testing.T) {
	server := newIAMControllerTestServer(t)
	// The role broadly allows both actions; the session policy only allows
	// one of them. Effective permissions = role ∩ session policy, so the
	// narrower session policy is what actually governs.
	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"looked-up"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	session := createTestSession(t, server, "role-b",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GetUser","iam:CreateUser"],"Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`)

	resp := doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetUser"}, "UserName": {"looked-up"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser (allowed by both) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	resp = doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"CreateUser"}, "UserName": {"someone"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:sts::000000000000:assumed-role/role-b/my-session is not authorized to perform: iam:CreateUser because no identity-based policy allows the iam:CreateUser action")
}

func TestVerifyIAMPolicyResourceScopedAllowDeniesDifferentResource(t *testing.T) {
	server := newIAMControllerTestServer(t)

	for _, roleName := range []string{"role-x", "role-y"} {
		resp := doIAMAction(t, server, url.Values{
			"Action":                   {"CreateRole"},
			"RoleName":                 {roleName},
			"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}`},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CreateRole(%s) status = %d, body=%s", roleName, resp.StatusCode, readBody(t, resp))
		}
	}

	accessKeyID, secret := createTestUserWithAccessKey(t, server, "gina",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::000000000000:role/role-x"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetRole"}, "RoleName": {"role-x"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetRole(role-x) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	// The policy only names role-x's ARN as Resource; a request for role-y
	// must not be authorized by it, even though the Action matches.
	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetRole"}, "RoleName": {"role-y"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/gina is not authorized to perform: iam:GetRole because no identity-based policy allows the iam:GetRole action")
}

func TestVerifyIAMPolicySessionDeniedWhenStoredRoleIDNoLongerMatches(t *testing.T) {
	server := newIAMControllerTestServer(t)
	session := createTestSession(t, server, "role-mismatch",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`, "")

	// Simulate the role having been deleted and recreated (getting a new
	// RoleID) while this session, minted against the old role, is still
	// unexpired: mutate the stored session's RoleID so it no longer matches
	// the role currently on record.
	stale := session
	stale.RoleID = "AROASTALEROLEID"
	if _, err := server.store.CreateSession(context.Background(), stale); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	resp := doSignedIAMActionAs(t, server, stale.AccessKeyId, stale.SecretAccessKey, stale.SessionToken,
		url.Values{"Action": {"GetUser"}, "UserName": {""}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:sts::000000000000:assumed-role/role-mismatch/my-session is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")
}

func TestVerifyIAMPolicySessionPolicyCannotWidenRolePermissions(t *testing.T) {
	server := newIAMControllerTestServer(t)
	// The role only allows GetUser; a broad session policy cannot grant
	// CreateUser on top of that.
	session := createTestSession(t, server, "role-c",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)

	resp := doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"CreateUser"}, "UserName": {"someone"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:sts::000000000000:assumed-role/role-c/my-session is not authorized to perform: iam:CreateUser because no identity-based policy allows the iam:CreateUser action")
}

// TestVerifyIAMPolicyUpdateUserDeniedWithoutPermissionOnTargetResource
// exercises the two-resource nature of a rename/path-move: AWS's UpdateUser
// requires permission on both the source object and the object being moved
// to (see the UpdateUser API's documented "Note" on required permissions).
// A policy scoped only to the source path must not authorize moving the
// user out of it.
func TestVerifyIAMPolicyUpdateUserDeniedWithoutPermissionOnTargetResource(t *testing.T) {
	server := newIAMControllerTestServer(t)
	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}, "Path": {"/developers/"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	accessKeyID, secret := createTestUserWithAccessKey(t, server, "irene",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser","Resource":"arn:aws:iam::000000000000:user/developers/*"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "",
		url.Values{"Action": {"UpdateUser"}, "UserName": {"alice"}, "NewPath": {"/admins/"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/irene is not authorized to perform: iam:UpdateUser because no identity-based policy allows the iam:UpdateUser action")
}

// TestVerifyIAMPolicyUpdateUserAllowedWithPermissionOnBothResources is the
// positive counterpart: once the policy names both the source and the
// target ARN, the same rename/path-move succeeds.
func TestVerifyIAMPolicyUpdateUserAllowedWithPermissionOnBothResources(t *testing.T) {
	server := newIAMControllerTestServer(t)
	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}, "Path": {"/developers/"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	accessKeyID, secret := createTestUserWithAccessKey(t, server, "judy",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateUser","Resource":["arn:aws:iam::000000000000:user/developers/alice","arn:aws:iam::000000000000:user/admins/alice"]}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "",
		url.Values{"Action": {"UpdateUser"}, "UserName": {"alice"}, "NewPath": {"/admins/"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UpdateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

// TestVerifyIAMPolicyGetUserSelfLookupResourceScoped guards against
// GetUser's omitted-UserName ("look up my own identity") form resolving to
// "*" instead of the caller's own ARN: with only a wildcard fallback, a
// Resource-scoped policy naming the caller's own ARN could never authorize
// their own self-lookup, forcing callers to be granted Resource:"*" just to
// use the feature.
func TestVerifyIAMPolicyGetUserSelfLookupResourceScoped(t *testing.T) {
	server := newIAMControllerTestServer(t)

	hankAccessKeyID, hankSecret := createTestUserWithAccessKey(t, server, "hank",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/hank"}]}`)

	resp := doSignedIAMActionAs(t, server, hankAccessKeyID, hankSecret, "", url.Values{"Action": {"GetUser"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser(self) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	ivyAccessKeyID, ivySecret := createTestUserWithAccessKey(t, server, "ivy",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/hank"}]}`)

	// A policy scoped to hank's ARN must not authorize ivy's self-lookup,
	// which resolves against ivy's own ARN, not hank's.
	resp = doSignedIAMActionAs(t, server, ivyAccessKeyID, ivySecret, "", url.Values{"Action": {"GetUser"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/ivy is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")
}

// TestVerifyIAMPolicyAccessKeyImplicitUserNameResourceScoped covers the
// resource-level check for the access-key actions in their omitted-UserName
// form: with no UserName to resolve, the target must still be the caller's
// own user ARN, so a policy scoped to that ARN authorizes the call and one
// scoped to somebody else's does not.
func TestVerifyIAMPolicyAccessKeyImplicitUserNameResourceScoped(t *testing.T) {
	server := newIAMControllerTestServer(t)

	rosaAccessKeyID, rosaSecret := createTestUserWithAccessKey(t, server, "rosa",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys","Resource":"arn:aws:iam::000000000000:user/rosa"}]}`)

	resp := doSignedIAMActionAs(t, server, rosaAccessKeyID, rosaSecret, "", url.Values{"Action": {"ListAccessKeys"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListAccessKeys(self) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	samAccessKeyID, samSecret := createTestUserWithAccessKey(t, server, "sam",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListAccessKeys","Resource":"arn:aws:iam::000000000000:user/rosa"}]}`)

	resp = doSignedIAMActionAs(t, server, samAccessKeyID, samSecret, "", url.Values{"Action": {"ListAccessKeys"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/sam is not authorized to perform: iam:ListAccessKeys because no identity-based policy allows the iam:ListAccessKeys action")
}

// TestVerifyIAMPolicyGetAccessKeyLastUsedResourceScoped guards against
// GetAccessKeyLastUsed (which carries only AccessKeyId, never UserName)
// falling back to "*" instead of resolving the queried key's owning user:
// with only a wildcard fallback, a Resource-scoped policy could never
// authorize the action at all, and — once granted via Resource:"*" — could
// not stop a caller from looking up any other user's key.
func TestVerifyIAMPolicyGetAccessKeyLastUsedResourceScoped(t *testing.T) {
	server := newIAMControllerTestServer(t)

	ninaAccessKeyID, ninaSecret := createTestUserWithAccessKey(t, server, "nina",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetAccessKeyLastUsed","Resource":"arn:aws:iam::000000000000:user/nina"}]}`)

	resp := doSignedIAMActionAs(t, server, ninaAccessKeyID, ninaSecret, "",
		url.Values{"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {ninaAccessKeyID}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetAccessKeyLastUsed(own key) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	oscarAccessKeyID, _ := createTestUserWithAccessKey(t, server, "oscar", "")

	// nina's policy only names her own ARN as Resource; it must not
	// authorize looking up oscar's access key, even though the Action
	// matches — the resource-level check resolves AccessKeyId to its
	// owning user, not a wildcard.
	resp = doSignedIAMActionAs(t, server, ninaAccessKeyID, ninaSecret, "",
		url.Values{"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {oscarAccessKeyID}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/nina is not authorized to perform: iam:GetAccessKeyLastUsed because no identity-based policy allows the iam:GetAccessKeyLastUsed action")
}

func TestVerifyIAMPolicySecureTransportDenyAppliesToPlaintextRequest(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "paul",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"paul"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/paul is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")
}

// TestVerifyIAMPolicyConditionKeyMatchIsCaseInsensitive verifies that
// condition-key lookup treats key *names* (unlike their values) as
// case-insensitive, so a Deny written against this package's internal
// aws:SourceIp key using different casing is still evaluated, not silently
// treated as naming an absent key.
func TestVerifyIAMPolicyConditionKeyMatchIsCaseInsensitive(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "quinn",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"Null":{"AWS:SOURCEIP":"false"}}}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"quinn"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/quinn is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")
}

// TestVerifyIAMPolicyPermanentUserHasUserId verifies that aws:userid is
// populated for a long-term IAM user principal, not only for a session (AWS
// sets aws:username and aws:userid simultaneously). A Deny guarding on its
// absence must not fire for a permanent user.
func TestVerifyIAMPolicyPermanentUserHasUserId(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "ray",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"Null":{"aws:userid":"true"}}}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"ray"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

// TestVerifyIAMPolicyDenyResourceSubstitutesUsernameVariable verifies that
// ${aws:username} in a statement's Resource is substituted before matching,
// so a Deny scoped to the caller's own resource via this variable matches
// the actual resource ARN instead of letting the broader Allow win.
func TestVerifyIAMPolicyDenyResourceSubstitutesUsernameVariable(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "sam",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"arn:aws:iam::000000000000:user/${aws:username}"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"sam"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/sam is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")
}

// TestVerifyIAMPolicyCreateUserDeniedByRequestTagCondition verifies that
// aws:RequestTag/<key> and aws:TagKeys are populated from a Create action's
// own Tags parameter, so a Deny guarding against a specific tag value blocks
// the tagged create.
func TestVerifyIAMPolicyCreateUserDeniedByRequestTagCondition(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "tina",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/env":"prod"}}}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{
		"Action":              {"CreateUser"},
		"UserName":            {"newbie"},
		"Tags.member.1.Key":   {"env"},
		"Tags.member.1.Value": {"prod"},
	})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/tina is not authorized to perform: iam:CreateUser because no identity-based policy allows the iam:CreateUser action")

	// A different tag value doesn't match the Deny's condition, so creation
	// proceeds - confirming the Deny above was tag-value-specific, not a
	// blanket denial of tagged creates.
	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{
		"Action":              {"CreateUser"},
		"UserName":            {"newbie2"},
		"Tags.member.1.Key":   {"env"},
		"Tags.member.1.Value": {"dev"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser(env=dev) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

// TestVerifyIAMPolicyResourceTagConditionDeniesTaggedResource verifies that
// iam:ResourceTag/<key> (and, identically, the generic aws:ResourceTag/<key>)
// is hydrated from an existing target resource's own stored tags, so a Deny
// guarding on it overrides the broad Allow underneath it when the target
// carries that tag.
func TestVerifyIAMPolicyResourceTagConditionDeniesTaggedResource(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// victor is the tagged target; his tag is set at creation time, via root.
	if resp := doIAMAction(t, server, url.Values{
		"Action":              {"CreateUser"},
		"UserName":            {"victor"},
		"Tags.member.1.Key":   {"sensitive"},
		"Tags.member.1.Value": {"true"},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser(victor) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	accessKeyID, secret := createTestUserWithAccessKey(t, server, "wendy",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"StringEquals":{"iam:ResourceTag/sensitive":"true"}}}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"victor"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/wendy is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")

	// The generic aws:ResourceTag/<key> form is populated identically to the
	// iam:ResourceTag/<key> one.
	accessKeyID2, secret2 := createTestUserWithAccessKey(t, server, "xander",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/sensitive":"true"}}}]}`)
	resp = doSignedIAMActionAs(t, server, accessKeyID2, secret2, "", url.Values{"Action": {"GetUser"}, "UserName": {"victor"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/xander is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")

	// An untagged user isn't affected by either Deny.
	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"yolanda"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser(yolanda) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}, "UserName": {"yolanda"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser(yolanda, untagged) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

// TestVerifyIAMPolicyPrincipalTagConditionAppliesToCaller verifies that
// aws:PrincipalTag/<key> is hydrated from the *calling* user's own stored
// tags, so a Deny guarding on it overrides the broad Allow underneath it
// when the caller carries that tag.
func TestVerifyIAMPolicyPrincipalTagConditionAppliesToCaller(t *testing.T) {
	server := newIAMControllerTestServer(t)

	if resp := doIAMAction(t, server, url.Values{
		"Action":              {"CreateUser"},
		"UserName":            {"zack"},
		"Tags.member.1.Key":   {"team"},
		"Tags.member.1.Value": {"contractor"},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser(zack) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	if resp := doIAMActionPost(t, server, url.Values{
		"Action":     {"PutUserPolicy"},
		"UserName":   {"zack"},
		"PolicyName": {"test-policy"},
		"PolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},` +
			`{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"contractor"}}}]}`},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("PutUserPolicy(zack) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	resp := doIAMAction(t, server, url.Values{"Action": {"CreateAccessKey"}, "UserName": {"zack"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey(zack) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out iamtypes.CreateAccessKeyResponse
	unmarshalXML(t, readBody(t, resp), &out)

	resp = doSignedIAMActionAs(t, server, out.Result.AccessKey.AccessKeyId, out.Result.AccessKey.SecretAccessKey, "", url.Values{"Action": {"GetUser"}, "UserName": {"zack"}})
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "AccessDenied",
		"User: arn:aws:iam::000000000000:user/zack is not authorized to perform: iam:GetUser because no identity-based policy allows the iam:GetUser action")

	// A caller without that tag isn't affected by the same policy shape.
	untaggedAccessKeyID, untaggedSecret := createTestUserWithAccessKey(t, server, "abby",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"},{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"contractor"}}}]}`)
	resp = doSignedIAMActionAs(t, server, untaggedAccessKeyID, untaggedSecret, "", url.Values{"Action": {"GetUser"}, "UserName": {"abby"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser(abby, untagged principal) status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}
