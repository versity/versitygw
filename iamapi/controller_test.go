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

package iamapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
	iamtypes "github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/sigv4auth"
)

var userIDPattern = regexp.MustCompile(`^AIDA[A-Z2-7]{17}$`)
var roleIDPattern = regexp.MustCompile(`^AROA[A-Z2-7]{17}$`)

func TestIAMApiControllerUserLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{
		"Action":              {"CreateUser"},
		"UserName":            {"alice"},
		"Path":                {"/engineering/"},
		"Tags.member.1.Key":   {"env"},
		"Tags.member.1.Value": {"test"},
		"Tags.member.2.Key":   {"empty"},
		"Tags.member.2.Value": {""},
	})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", create.StatusCode, readBody(t, create))
	}
	createBody := readBody(t, create)
	var createOut iamtypes.CreateUserResponse
	unmarshalXML(t, createBody, &createOut)
	if createOut.XMLName.Space != "https://iam.amazonaws.com/doc/2010-05-08/" || createOut.XMLName.Local != "CreateUserResponse" {
		t.Fatalf("CreateUser XMLName = %#v", createOut.XMLName)
	}
	user := createOut.Result.User
	if user.Path != "/engineering/" || user.UserName != "alice" {
		t.Fatalf("created user = %#v, want path/name", user)
	}
	if !userIDPattern.MatchString(user.UserID) {
		t.Fatalf("UserId = %q, want AWS IAM user id form", user.UserID)
	}
	if user.Arn != "arn:aws:iam::000000000000:user/engineering/alice" {
		t.Fatalf("Arn = %q", user.Arn)
	}
	if user.CreateDate.IsZero() {
		t.Fatal("CreateDate is zero")
	}
	requireUserTags(t, user.Tags)
	if createOut.ResponseMetadata.RequestID == "" {
		t.Fatal("CreateUser missing RequestId")
	}

	duplicate := doIAMAction(t, server, url.Values{
		"Action":   {"CreateUser"},
		"UserName": {"alice"},
	})
	requireIAMError(t, duplicate, http.StatusConflict, "Sender", "EntityAlreadyExists", "User with name alice already exists.")

	update := doIAMAction(t, server, url.Values{
		"Action":      {"UpdateUser"},
		"UserName":    {"alice"},
		"NewUserName": {"zoe"},
		"NewPath":     {"/ops/"},
	})
	if update.StatusCode != http.StatusOK {
		t.Fatalf("UpdateUser status = %d, body=%s", update.StatusCode, readBody(t, update))
	}
	var updateOut iamtypes.UpdateUserResponse
	unmarshalXML(t, readBody(t, update), &updateOut)
	if updateOut.XMLName.Space != "https://iam.amazonaws.com/doc/2010-05-08/" || updateOut.XMLName.Local != "UpdateUserResponse" {
		t.Fatalf("UpdateUser XMLName = %#v", updateOut.XMLName)
	}
	if updateOut.ResponseMetadata.RequestID == "" {
		t.Fatal("UpdateUser missing RequestId")
	}
	updatedUser := updateOut.Result.User
	if updatedUser.UserID != user.UserID || !updatedUser.CreateDate.Equal(user.CreateDate) {
		t.Fatalf("UpdateUser result identity = %#v, want UserId/CreateDate preserved from %#v", updatedUser, user)
	}
	if updatedUser.UserName != "zoe" || updatedUser.Path != "/ops/" ||
		updatedUser.Arn != "arn:aws:iam::000000000000:user/ops/zoe" {
		t.Fatalf("UpdateUser result = %#v", updatedUser)
	}

	get := doIAMAction(t, server, url.Values{
		"Action":   {"GetUser"},
		"UserName": {"zoe"},
	})
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GetUser status = %d, body=%s", get.StatusCode, readBody(t, get))
	}
	var getOut iamtypes.GetUserResponse
	unmarshalXML(t, readBody(t, get), &getOut)
	gotUser := getOut.Result.User
	if gotUser.UserID != user.UserID || !gotUser.CreateDate.Equal(user.CreateDate) {
		t.Fatalf("updated user identity = %#v, want UserId/CreateDate preserved from %#v", gotUser, user)
	}
	if gotUser.Path != "/ops/" || gotUser.UserName != "zoe" ||
		gotUser.Arn != "arn:aws:iam::000000000000:user/ops/zoe" {
		t.Fatalf("GetUser after update = %#v", gotUser)
	}
	requireUserTags(t, gotUser.Tags)

	list := doIAMAction(t, server, url.Values{
		"Action":     {"ListUsers"},
		"PathPrefix": {"/ops/"},
	})
	if list.StatusCode != http.StatusOK {
		t.Fatalf("ListUsers status = %d, body=%s", list.StatusCode, readBody(t, list))
	}
	var listOut iamtypes.ListUsersResponse
	unmarshalXML(t, readBody(t, list), &listOut)
	if len(listOut.Result.Users.Members) != 1 || listOut.Result.Users.Members[0].UserName != "zoe" {
		t.Fatalf("ListUsers = %#v, want zoe", listOut.Result.Users.Members)
	}
	requireUserTags(t, listOut.Result.Users.Members[0].Tags)

	deleteResp := doIAMAction(t, server, url.Values{
		"Action":   {"DeleteUser"},
		"UserName": {"zoe"},
	})
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteUser status = %d, body=%s", deleteResp.StatusCode, readBody(t, deleteResp))
	}
	var deleteOut iamtypes.DeleteUserResponse
	unmarshalXML(t, readBody(t, deleteResp), &deleteOut)
	if deleteOut.XMLName.Local != "DeleteUserResponse" || deleteOut.ResponseMetadata.RequestID == "" {
		t.Fatalf("DeleteUser output = %#v", deleteOut)
	}

	missing := doIAMAction(t, server, url.Values{
		"Action":   {"GetUser"},
		"UserName": {"zoe"},
	})
	requireIAMError(t, missing, http.StatusNotFound, "Sender", "NoSuchEntity", "The user with name zoe cannot be found.")
}

// TestIAMApiControllerGetRootUser confirms GetUser's self-lookup form
// (UserName omitted, the only way any real AWS SDK/CLI ever invokes it,
// since Query-protocol clients simply don't serialize an absent optional
// field) and its non-standard explicit-empty-string equivalent both
// resolve to the actual authenticated caller — root, here, since
// doIAMAction always signs as root.
func TestIAMApiControllerGetRootUser(t *testing.T) {
	server := newIAMControllerTestServer(t)

	for _, params := range []url.Values{
		{"Action": {"GetUser"}},
		{"Action": {"GetUser"}, "UserName": {""}},
	} {
		resp := doIAMAction(t, server, params)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GetUser root (params=%v) status = %d, body=%s", params, resp.StatusCode, readBody(t, resp))
		}

		var out iamtypes.GetUserResponse
		unmarshalXML(t, readBody(t, resp), &out)
		if out.Result.User.UserID != iamutil.DefaultAccountID {
			t.Fatalf("GetUser root UserId = %q, want %q", out.Result.User.UserID, iamutil.DefaultAccountID)
		}
		if out.Result.User.Arn != "arn:aws:iam::000000000000:root" {
			t.Fatalf("GetUser root Arn = %q", out.Result.User.Arn)
		}
		if out.ResponseMetadata.RequestID == "" {
			t.Fatal("GetUser root missing RequestId")
		}
	}
}

// TestIAMApiControllerGetUserSelfLookupNonRoot confirms GetUser's
// self-lookup form resolves to the actual authenticated non-root caller —
// not always root, which was the bug this test guards against.
func TestIAMApiControllerGetUserSelfLookupNonRoot(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "ivan",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"GetUser"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser self-lookup status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out iamtypes.GetUserResponse
	unmarshalXML(t, readBody(t, resp), &out)
	if out.Result.User.UserName != "ivan" || out.Result.User.Arn != "arn:aws:iam::000000000000:user/ivan" {
		t.Fatalf("GetUser self-lookup = %#v, want caller's own identity (ivan)", out.Result.User)
	}
}

// TestIAMApiControllerGetUserSelfLookupSessionRejected confirms an assumed-
// role session — which has no IAM user identity to self-look-up — gets
// AWS's own ValidationError rather than being told it's root or some
// arbitrary user.
func TestIAMApiControllerGetUserSelfLookupSessionRejected(t *testing.T) {
	server := newIAMControllerTestServer(t)
	session := createTestSession(t, server, "role-selflookup",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`, "")

	resp := doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetUser"}})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
		"Must specify userName when calling with non-User credentials")
}

// TestIAMApiControllerAccessKeyImplicitUserName walks a user through the
// whole access-key lifecycle without ever naming itself: real IAM resolves
// the UserName from the access key signing the request.
func TestIAMApiControllerAccessKeyImplicitUserName(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "kate",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"CreateAccessKey"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var createOut iamtypes.CreateAccessKeyResponse
	unmarshalXML(t, readBody(t, resp), &createOut)
	created := createOut.Result.AccessKey
	if created.UserName != "kate" {
		t.Fatalf("CreateAccessKey UserName = %q, want the calling user %q", created.UserName, "kate")
	}

	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{
		"Action":      {"UpdateAccessKey"},
		"AccessKeyId": {created.AccessKeyId},
		"Status":      {"Inactive"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UpdateAccessKey status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{"Action": {"ListAccessKeys"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListAccessKeys status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var listOut iamtypes.ListAccessKeysResponse
	unmarshalXML(t, readBody(t, resp), &listOut)
	keys := listOut.Result.AccessKeyMetadata.Members
	if len(keys) != 2 {
		t.Fatalf("ListAccessKeys returned %d keys, want the caller's own 2", len(keys))
	}
	for _, key := range keys {
		if key.UserName != "kate" {
			t.Fatalf("ListAccessKeys returned a key owned by %q, want only %q's", key.UserName, "kate")
		}
		if key.AccessKeyId == created.AccessKeyId && key.Status != iamutil.AccessKeyStatusInactive {
			t.Fatalf("UpdateAccessKey left key %s Status = %q, want %q", key.AccessKeyId, key.Status, iamutil.AccessKeyStatusInactive)
		}
	}

	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{
		"Action":      {"DeleteAccessKey"},
		"AccessKeyId": {created.AccessKeyId},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteAccessKey status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	resp = doIAMAction(t, server, url.Values{"Action": {"ListAccessKeys"}, "UserName": {"kate"}})
	var remainingOut iamtypes.ListAccessKeysResponse
	unmarshalXML(t, readBody(t, resp), &remainingOut)
	remaining := remainingOut.Result.AccessKeyMetadata.Members
	if len(remaining) != 1 || remaining[0].AccessKeyId == created.AccessKeyId {
		t.Fatalf("after implicit DeleteAccessKey kate has %#v, want only her original key", remaining)
	}
}

// TestIAMApiControllerAccessKeyImplicitUserNameScopedToCaller confirms the
// inferred UserName is the caller's own and nothing else: another user's
// access key is simply not found, rather than being updated or deleted.
func TestIAMApiControllerAccessKeyImplicitUserNameScopedToCaller(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "liam",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)
	otherAccessKeyID, _ := createTestUserWithAccessKey(t, server, "mona", "")

	resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{
		"Action":      {"UpdateAccessKey"},
		"AccessKeyId": {otherAccessKeyID},
		"Status":      {"Inactive"},
	})
	requireIAMError(t, resp, http.StatusNotFound, "Sender", "NoSuchEntity",
		"The Access Key with id "+otherAccessKeyID+" cannot be found")

	resp = doSignedIAMActionAs(t, server, accessKeyID, secret, "", url.Values{
		"Action":      {"DeleteAccessKey"},
		"AccessKeyId": {otherAccessKeyID},
	})
	requireIAMError(t, resp, http.StatusNotFound, "Sender", "NoSuchEntity",
		"The Access Key with id "+otherAccessKeyID+" cannot be found")

	resp = doIAMAction(t, server, url.Values{"Action": {"ListAccessKeys"}, "UserName": {"mona"}})
	var listOut iamtypes.ListAccessKeysResponse
	unmarshalXML(t, readBody(t, resp), &listOut)
	if len(listOut.Result.AccessKeyMetadata.Members) != 1 ||
		listOut.Result.AccessKeyMetadata.Members[0].Status != iamutil.AccessKeyStatusActive {
		t.Fatalf("mona's keys = %#v, want her single key left Active", listOut.Result.AccessKeyMetadata.Members)
	}
}

// TestIAMApiControllerAccessKeyImplicitUserNameSessionRejected confirms an
// assumed-role session — which has no IAM user of its own to infer — gets
// IAM's own ValidationError rather than having the action attributed to
// some arbitrary user.
func TestIAMApiControllerAccessKeyImplicitUserNameSessionRejected(t *testing.T) {
	server := newIAMControllerTestServer(t)
	session := createTestSession(t, server, "role-accesskey",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`, "")

	for _, action := range accessKeyImplicitUserNameActions {
		t.Run(action, func(t *testing.T) {
			resp := doSignedIAMActionAs(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
				accessKeyActionParams(action))
			requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
				"Must specify userName when calling with non-User credentials")
		})
	}
}

// TestIAMApiControllerAccessKeyImplicitUserNameRootRejected covers the
// gateway's root credential, which is a configured key rather than a stored
// IAM user and so owns no access keys the IAM API could manage: there is
// nothing to infer, so UserName stays required.
func TestIAMApiControllerAccessKeyImplicitUserNameRootRejected(t *testing.T) {
	server := newIAMControllerTestServer(t)

	for _, action := range accessKeyImplicitUserNameActions {
		t.Run(action, func(t *testing.T) {
			resp := doIAMAction(t, server, accessKeyActionParams(action))
			requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
				"Must specify userName when calling with non-User credentials")
		})
	}
}

// TestIAMApiControllerAccessKeyEmptyUserNameRejected confirms only an
// entirely absent UserName is inferred: sending the parameter with an empty
// value is a validation failure, not a request to act on the caller.
func TestIAMApiControllerAccessKeyEmptyUserNameRejected(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "nate",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)

	for _, action := range accessKeyImplicitUserNameActions {
		t.Run(action, func(t *testing.T) {
			params := accessKeyActionParams(action)
			params.Set("UserName", "")
			resp := doSignedIAMActionAs(t, server, accessKeyID, secret, "", params)
			requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
				"The specified value for userName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-")
		})
	}
}

func TestIAMApiControllerCreateUserValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		status  int
		code    string
		message string
	}{
		{
			name: "missing username",
			params: url.Values{
				"Action": {"CreateUser"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "invalid path",
			params: url.Values{
				"Action":   {"CreateUser"},
				"UserName": {"alice"},
				"Path":     {"bad"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for path is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters.",
		},
		{
			name: "long path",
			params: url.Values{
				"Action":   {"CreateUser"},
				"UserName": {"alice"},
				"Path":     {"/" + strings.Repeat("a", 511) + "/"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'path' failed to satisfy constraint: Member must have length less than or equal to 512",
		},
		{
			name: "invalid username",
			params: url.Values{
				"Action":   {"CreateUser"},
				"UserName": {"bad/name"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for userName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name: "long username",
			params: url.Values{
				"Action":   {"CreateUser"},
				"UserName": {strings.Repeat("a", 65)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64",
		},
		{
			name: "invalid tag key",
			params: url.Values{
				"Action":              {"CreateUser"},
				"UserName":            {"alice"},
				"Tags.member.1.Key":   {"bad*key"},
				"Tags.member.1.Value": {"test"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+",
		},
		{
			name: "long tag key",
			params: url.Values{
				"Action":              {"CreateUser"},
				"UserName":            {"alice"},
				"Tags.member.1.Key":   {strings.Repeat("k", 129)},
				"Tags.member.1.Value": {"test"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name: "invalid tag value",
			params: url.Values{
				"Action":              {"CreateUser"},
				"UserName":            {"alice"},
				"Tags.member.1.Key":   {"badval"},
				"Tags.member.1.Value": {"bad*value"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*",
		},
		{
			name: "long tag value",
			params: url.Values{
				"Action":              {"CreateUser"},
				"UserName":            {"alice"},
				"Tags.member.1.Key":   {"key"},
				"Tags.member.1.Value": {strings.Repeat("v", 257)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256",
		},
		{
			name: "duplicate tag key",
			params: url.Values{
				"Action":              {"CreateUser"},
				"UserName":            {"alice"},
				"Tags.member.1.Key":   {"dup"},
				"Tags.member.1.Value": {"one"},
				"Tags.member.2.Key":   {"DUP"},
				"Tags.member.2.Value": {"two"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Duplicate tag keys found. Please note that Tag keys are case insensitive.",
		},
		{
			name: "missing tag key",
			params: url.Values{
				"Action":              {"CreateUser"},
				"UserName":            {"alice"},
				"Tags.member.1.Value": {"test"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "missing tag value",
			params: url.Values{
				"Action":            {"CreateUser"},
				"UserName":          {"alice"},
				"Tags.member.1.Key": {"env"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must not be null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func TestIAMApiControllerDeleteAndUpdateUserErrors(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		status  int
		code    string
		message string
	}{
		{
			name: "delete invalid username",
			params: url.Values{
				"Action":   {"DeleteUser"},
				"UserName": {"bad/name"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for userName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name: "delete long username",
			params: url.Values{
				"Action":   {"DeleteUser"},
				"UserName": {strings.Repeat("a", 129)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name: "delete missing user",
			params: url.Values{
				"Action":   {"DeleteUser"},
				"UserName": {"asdfadsf"},
			},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name asdfadsf cannot be found.",
		},
		{
			name: "update invalid username",
			params: url.Values{
				"Action":   {"UpdateUser"},
				"UserName": {"bad/name"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for userName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name: "update long username",
			params: url.Values{
				"Action":   {"UpdateUser"},
				"UserName": {strings.Repeat("a", 129)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name: "update invalid new username",
			params: url.Values{
				"Action":      {"UpdateUser"},
				"UserName":    {"asdfadsf"},
				"NewUserName": {"bad/name"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for newUserName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name: "update long new username",
			params: url.Values{
				"Action":      {"UpdateUser"},
				"UserName":    {"asdfadsf"},
				"NewUserName": {strings.Repeat("a", 65)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'newUserName' failed to satisfy constraint: Member must have length less than or equal to 64",
		},
		{
			name: "update invalid new path",
			params: url.Values{
				"Action":   {"UpdateUser"},
				"UserName": {"asdfadsf"},
				"NewPath":  {"invalid"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for newPath is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters.",
		},
		{
			name: "update long new path",
			params: url.Values{
				"Action":   {"UpdateUser"},
				"UserName": {"asdfadsf"},
				"NewPath":  {"/" + strings.Repeat("a", 511) + "/"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'newPath' failed to satisfy constraint: Member must have length less than or equal to 512",
		},
		{
			name: "update missing user",
			params: url.Values{
				"Action":   {"UpdateUser"},
				"UserName": {"asdfadsf"},
			},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name asdfadsf cannot be found.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func TestIAMApiControllerUpdateUserAlreadyExists(t *testing.T) {
	server := newIAMControllerTestServer(t)
	for _, userName := range []string{"alice", "zoe"} {
		resp := doIAMAction(t, server, url.Values{
			"Action":   {"CreateUser"},
			"UserName": {userName},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CreateUser(%q) status = %d, body=%s", userName, resp.StatusCode, readBody(t, resp))
		}
		resp.Body.Close()
	}

	resp := doIAMAction(t, server, url.Values{
		"Action":      {"UpdateUser"},
		"UserName":    {"alice"},
		"NewUserName": {"zoe"},
	})
	requireIAMError(t, resp, http.StatusConflict, "Sender", "EntityAlreadyExists", "User with name zoe already exists.")
}

func TestIAMApiControllerUserTagLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", create.StatusCode, readBody(t, create))
	}

	if got := listUserTags(t, server, "alice"); len(got.Tags.Members) != 0 || got.IsTruncated {
		t.Fatalf("ListUserTags on a fresh user = %#v, want no tags", got)
	}

	tagUser(t, server, "alice", map[string]string{"env": "prod", "team": "storage", "empty": ""})

	got := listUserTags(t, server, "alice")
	// Sorted by key, regardless of the order they were added in.
	want := []iamtypes.Tag{{Key: "empty", Value: ""}, {Key: "env", Value: "prod"}, {Key: "team", Value: "storage"}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags = %#v, want %#v", got.Tags.Members, want)
	}

	// A repeated key replaces its value in place; a differently-cased key
	// is the same tag, and the new casing wins.
	tagUser(t, server, "alice", map[string]string{"env": "staging"})
	tagUser(t, server, "alice", map[string]string{"TEAM": "compute"})

	got = listUserTags(t, server, "alice")
	want = []iamtypes.Tag{{Key: "TEAM", Value: "compute"}, {Key: "empty", Value: ""}, {Key: "env", Value: "staging"}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags after overwrite = %#v, want %#v", got.Tags.Members, want)
	}

	// GetUser reports the same tags the tag actions maintain.
	getUser := doIAMAction(t, server, url.Values{"Action": {"GetUser"}, "UserName": {"alice"}})
	var getResp struct {
		Result struct{ User iamtypes.User } `xml:"GetUserResult"`
	}
	unmarshalXML(t, readBody(t, getUser), &getResp)
	if len(getResp.Result.User.Tags) != 3 {
		t.Fatalf("GetUser Tags = %#v, want 3 tags", getResp.Result.User.Tags)
	}

	// Removal is case-insensitive, and a key naming no tag is not an error.
	untag := doIAMAction(t, server, url.Values{
		"Action":           {"UntagUser"},
		"UserName":         {"alice"},
		"TagKeys.member.1": {"EnV"},
		"TagKeys.member.2": {"never-existed"},
	})
	if untag.StatusCode != http.StatusOK {
		t.Fatalf("UntagUser status = %d, body=%s", untag.StatusCode, readBody(t, untag))
	}

	got = listUserTags(t, server, "alice")
	want = []iamtypes.Tag{{Key: "TEAM", Value: "compute"}, {Key: "empty", Value: ""}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags after untag = %#v, want %#v", got.Tags.Members, want)
	}
}

func TestIAMApiControllerListUserTagsPagination(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", create.StatusCode, readBody(t, create))
	}
	tagUser(t, server, "alice", map[string]string{"a": "1", "b": "2", "c": "3"})

	var seen []iamtypes.Tag
	marker := ""
	for page := 1; ; page++ {
		params := url.Values{"Action": {"ListUserTags"}, "UserName": {"alice"}, "MaxItems": {"1"}}
		if marker != "" {
			params.Set("Marker", marker)
		}
		resp := doIAMAction(t, server, params)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ListUserTags status = %d, body=%s", resp.StatusCode, readBody(t, resp))
		}
		var out struct {
			Result iamtypes.ListUserTagsResult `xml:"ListUserTagsResult"`
		}
		unmarshalXML(t, readBody(t, resp), &out)

		if len(out.Result.Tags.Members) != 1 {
			t.Fatalf("page %d holds %d tags, want 1", page, len(out.Result.Tags.Members))
		}
		seen = append(seen, out.Result.Tags.Members...)
		if !out.Result.IsTruncated {
			if out.Result.Marker != "" {
				t.Fatalf("final page Marker = %q, want empty", out.Result.Marker)
			}
			break
		}
		marker = out.Result.Marker
	}

	want := []iamtypes.Tag{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}, {Key: "c", Value: "3"}}
	if !slices.Equal(seen, want) {
		t.Fatalf("paged tags = %#v, want %#v", seen, want)
	}
}

func TestIAMApiControllerTagUserExceedsQuota(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", create.StatusCode, readBody(t, create))
	}

	atQuota := url.Values{"Action": {"TagUser"}, "UserName": {"alice"}}
	for i := 1; i <= storage.MaxTagsPerResource; i++ {
		atQuota.Set(fmt.Sprintf("Tags.member.%d.Key", i), fmt.Sprintf("k%d", i))
		atQuota.Set(fmt.Sprintf("Tags.member.%d.Value", i), fmt.Sprintf("v%d", i))
	}
	if resp := doIAMAction(t, server, atQuota); resp.StatusCode != http.StatusOK {
		t.Fatalf("TagUser with %d tags status = %d, body=%s", storage.MaxTagsPerResource, resp.StatusCode, readBody(t, resp))
	}

	// Replacing an existing key at the quota is fine: the total doesn't grow.
	replace := doIAMAction(t, server, url.Values{
		"Action": {"TagUser"}, "UserName": {"alice"},
		"Tags.member.1.Key": {"k1"}, "Tags.member.1.Value": {"replaced"},
	})
	if replace.StatusCode != http.StatusOK {
		t.Fatalf("TagUser replacing at quota status = %d, body=%s", replace.StatusCode, readBody(t, replace))
	}

	// One more distinct key does not fit.
	overflow := doIAMAction(t, server, url.Values{
		"Action": {"TagUser"}, "UserName": {"alice"},
		"Tags.member.1.Key": {"overflow"}, "Tags.member.1.Value": {"x"},
	})
	requireIAMError(t, overflow, http.StatusConflict, "Sender", "LimitExceeded",
		"The number of tags has reached the maximum limit.")
}

func TestIAMApiControllerUserTagValidationErrors(t *testing.T) {
	tooManyTags := url.Values{"Action": {"TagUser"}, "UserName": {"alice"}}
	for i := 1; i <= iamutil.MaxTagMembersPerRequest+1; i++ {
		tooManyTags.Set(fmt.Sprintf("Tags.member.%d.Key", i), fmt.Sprintf("k%d", i))
		tooManyTags.Set(fmt.Sprintf("Tags.member.%d.Value", i), fmt.Sprintf("v%d", i))
	}
	tooManyTagKeys := url.Values{"Action": {"UntagUser"}, "UserName": {"alice"}}
	for i := 1; i <= iamutil.MaxTagMembersPerRequest+1; i++ {
		tooManyTagKeys.Set(fmt.Sprintf("TagKeys.member.%d", i), fmt.Sprintf("k%d", i))
	}

	tests := []struct {
		name      string
		setupUser bool
		params    url.Values
		status    int
		code      string
		message   string
	}{
		{
			name:    "tag missing user name",
			params:  url.Values{"Action": {"TagUser"}, "Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag missing tags",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag missing key",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Value": {"prod"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag missing value",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Key": {"env"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag empty key",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Key": {""}, "Tags.member.1.Value": {"prod"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length greater than or equal to 1",
		},
		{
			name:      "tag key too long",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Key": {strings.Repeat("k", 129)}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name:      "tag invalid key characters",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Key": {"bad*key"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   `1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]+`,
		},
		{
			name:      "tag value too long",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {strings.Repeat("v", 257)}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256",
		},
		{
			name:      "tag invalid value characters",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"alice"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"bad*value"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   `1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]*`,
		},
		{
			name:      "tag duplicate keys",
			setupUser: true,
			params: url.Values{
				"Action": {"TagUser"}, "UserName": {"alice"},
				"Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"a"},
				"Tags.member.2.Key": {"ENV"}, "Tags.member.2.Value": {"b"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Duplicate tag keys found. Please note that Tag keys are case insensitive.",
		},
		{
			name:      "tag too many tags",
			setupUser: true,
			params:    tooManyTags,
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50",
		},
		{
			name:      "tag invalid user name characters",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"bad!name"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "The specified value for userName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name:      "tag user name too long",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {strings.Repeat("u", 129)}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			// A malformed tag is reported before the user is looked up.
			name:      "tag non existing user with invalid tag",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"nosuchuser"}, "Tags.member.1.Key": {"bad*key"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   `1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]+`,
		},
		{
			name:      "tag non existing user",
			setupUser: true,
			params:    url.Values{"Action": {"TagUser"}, "UserName": {"nosuchuser"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The user with name nosuchuser cannot be found.",
		},
		{
			name:    "untag missing user name",
			params:  url.Values{"Action": {"UntagUser"}, "TagKeys.member.1": {"env"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "untag missing tag keys",
			setupUser: true,
			params:    url.Values{"Action": {"UntagUser"}, "UserName": {"alice"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "untag empty key",
			setupUser: true,
			params:    url.Values{"Action": {"UntagUser"}, "UserName": {"alice"}, "TagKeys.member.1": {""}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   invalidTagKeysMessage,
		},
		{
			name:      "untag key too long",
			setupUser: true,
			params:    url.Values{"Action": {"UntagUser"}, "UserName": {"alice"}, "TagKeys.member.1": {strings.Repeat("k", 129)}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   invalidTagKeysMessage,
		},
		{
			name:      "untag invalid key characters",
			setupUser: true,
			params:    url.Values{"Action": {"UntagUser"}, "UserName": {"alice"}, "TagKeys.member.1": {"bad*key"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   invalidTagKeysMessage,
		},
		{
			name:      "untag too many tag keys",
			setupUser: true,
			params:    tooManyTagKeys,
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to 50",
		},
		{
			name:      "untag non existing user",
			setupUser: true,
			params:    url.Values{"Action": {"UntagUser"}, "UserName": {"nosuchuser"}, "TagKeys.member.1": {"env"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The user with name nosuchuser cannot be found.",
		},
		{
			name:    "list missing user name",
			params:  url.Values{"Action": {"ListUserTags"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "list max items too small",
			setupUser: true,
			params:    url.Values{"Action": {"ListUserTags"}, "UserName": {"alice"}, "MaxItems": {"0"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
		},
		{
			name:      "list max items too large",
			setupUser: true,
			params:    url.Values{"Action": {"ListUserTags"}, "UserName": {"alice"}, "MaxItems": {"1001"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
		},
		{
			name:      "list max items not a number",
			setupUser: true,
			params:    url.Values{"Action": {"ListUserTags"}, "UserName": {"alice"}, "MaxItems": {"abc"}},
			status:    http.StatusBadRequest,
			code:      "MalformedInput",
			message:   "",
		},
		{
			name:      "list non existing user",
			setupUser: true,
			params:    url.Values{"Action": {"ListUserTags"}, "UserName": {"nosuchuser"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The user with name nosuchuser cannot be found.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			if tt.setupUser {
				resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
				}
			}
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

// invalidTagKeysMessage is UntagUser's single response to every malformed
// TagKeys member, whatever the specific constraint that failed.
const invalidTagKeysMessage = `1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must satisfy constraint: [Member must have length less than or equal to 128, Member must have length greater than or equal to 1, Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]+, Member must not be null]`

func tagUser(t *testing.T, server *IAMApiServer, userName string, tags map[string]string) {
	t.Helper()

	params := url.Values{"Action": {"TagUser"}, "UserName": {userName}}
	i := 1
	for key, value := range tags {
		params.Set(fmt.Sprintf("Tags.member.%d.Key", i), key)
		params.Set(fmt.Sprintf("Tags.member.%d.Value", i), value)
		i++
	}

	resp := doIAMAction(t, server, params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TagUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func listUserTags(t *testing.T, server *IAMApiServer, userName string) iamtypes.ListUserTagsResult {
	t.Helper()

	resp := doIAMAction(t, server, url.Values{"Action": {"ListUserTags"}, "UserName": {userName}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListUserTags status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out struct {
		Result iamtypes.ListUserTagsResult `xml:"ListUserTagsResult"`
	}
	unmarshalXML(t, readBody(t, resp), &out)
	return out.Result
}

func TestIAMApiControllerUserPolicyLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)

	createUser := doIAMAction(t, server, url.Values{
		"Action":   {"CreateUser"},
		"UserName": {"alice"},
	})
	if createUser.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", createUser.StatusCode, readBody(t, createUser))
	}

	policyDoc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`

	put := doIAMAction(t, server, url.Values{
		"Action":         {"PutUserPolicy"},
		"UserName":       {"alice"},
		"PolicyName":     {"ReadOnly"},
		"PolicyDocument": {policyDoc},
	})
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PutUserPolicy status = %d, body=%s", put.StatusCode, readBody(t, put))
	}
	var putOut iamtypes.PutUserPolicyResponse
	unmarshalXML(t, readBody(t, put), &putOut)
	if putOut.XMLName.Space != "https://iam.amazonaws.com/doc/2010-05-08/" || putOut.XMLName.Local != "PutUserPolicyResponse" {
		t.Fatalf("PutUserPolicy XMLName = %#v", putOut.XMLName)
	}
	if putOut.ResponseMetadata.RequestID == "" {
		t.Fatal("PutUserPolicy missing RequestId")
	}

	get := doIAMAction(t, server, url.Values{
		"Action":     {"GetUserPolicy"},
		"UserName":   {"alice"},
		"PolicyName": {"ReadOnly"},
	})
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GetUserPolicy status = %d, body=%s", get.StatusCode, readBody(t, get))
	}
	var getOut iamtypes.GetUserPolicyResponse
	unmarshalXML(t, readBody(t, get), &getOut)
	if getOut.Result.UserName != "alice" || getOut.Result.PolicyName != "ReadOnly" {
		t.Fatalf("GetUserPolicy result = %#v", getOut.Result)
	}
	if !strings.Contains(getOut.Result.PolicyDocument, "%20") {
		t.Fatalf("GetUserPolicy PolicyDocument = %q, want RFC 3986 percent-encoding (%%20 for space)", getOut.Result.PolicyDocument)
	}
	decoded, err := url.QueryUnescape(getOut.Result.PolicyDocument)
	if err != nil {
		t.Fatalf("QueryUnescape: %v", err)
	}
	if decoded != policyDoc {
		t.Fatalf("GetUserPolicy PolicyDocument = %q, want verbatim %q", decoded, policyDoc)
	}

	list := doIAMAction(t, server, url.Values{
		"Action":   {"ListUserPolicies"},
		"UserName": {"alice"},
	})
	if list.StatusCode != http.StatusOK {
		t.Fatalf("ListUserPolicies status = %d, body=%s", list.StatusCode, readBody(t, list))
	}
	var listOut iamtypes.ListUserPoliciesResponse
	unmarshalXML(t, readBody(t, list), &listOut)
	if len(listOut.Result.PolicyNames.Members) != 1 || listOut.Result.PolicyNames.Members[0] != "ReadOnly" {
		t.Fatalf("ListUserPolicies = %#v, want [ReadOnly]", listOut.Result.PolicyNames.Members)
	}
	if listOut.Result.IsTruncated {
		t.Fatal("ListUserPolicies IsTruncated = true, want false")
	}

	// Re-Put-ing the same PolicyName replaces it rather than erroring or
	// stacking toward the aggregate size quota.
	overwritePut := doIAMAction(t, server, url.Values{
		"Action":         {"PutUserPolicy"},
		"UserName":       {"alice"},
		"PolicyName":     {"ReadOnly"},
		"PolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`},
	})
	if overwritePut.StatusCode != http.StatusOK {
		t.Fatalf("overwrite PutUserPolicy status = %d, body=%s", overwritePut.StatusCode, readBody(t, overwritePut))
	}
	overwriteGet := doIAMAction(t, server, url.Values{
		"Action":     {"GetUserPolicy"},
		"UserName":   {"alice"},
		"PolicyName": {"ReadOnly"},
	})
	var overwriteOut iamtypes.GetUserPolicyResponse
	unmarshalXML(t, readBody(t, overwriteGet), &overwriteOut)
	overwriteDecoded, err := url.QueryUnescape(overwriteOut.Result.PolicyDocument)
	if err != nil {
		t.Fatalf("QueryUnescape: %v", err)
	}
	if !strings.Contains(overwriteDecoded, "Deny") {
		t.Fatalf("GetUserPolicy after overwrite = %q, want the Deny statement", overwriteDecoded)
	}

	del := doIAMAction(t, server, url.Values{
		"Action":     {"DeleteUserPolicy"},
		"UserName":   {"alice"},
		"PolicyName": {"ReadOnly"},
	})
	if del.StatusCode != http.StatusOK {
		t.Fatalf("DeleteUserPolicy status = %d, body=%s", del.StatusCode, readBody(t, del))
	}
	var delOut iamtypes.DeleteUserPolicyResponse
	unmarshalXML(t, readBody(t, del), &delOut)
	if delOut.XMLName.Local != "DeleteUserPolicyResponse" || delOut.ResponseMetadata.RequestID == "" {
		t.Fatalf("DeleteUserPolicy output = %#v", delOut)
	}

	missing := doIAMAction(t, server, url.Values{
		"Action":     {"GetUserPolicy"},
		"UserName":   {"alice"},
		"PolicyName": {"ReadOnly"},
	})
	requireIAMError(t, missing, http.StatusNotFound, "Sender", "NoSuchEntity", "The user policy with name ReadOnly cannot be found.")

	// A second delete of the same (now-gone) policy is a hard error, not an
	// idempotent success.
	doubleDelete := doIAMAction(t, server, url.Values{
		"Action":     {"DeleteUserPolicy"},
		"UserName":   {"alice"},
		"PolicyName": {"ReadOnly"},
	})
	requireIAMError(t, doubleDelete, http.StatusNotFound, "Sender", "NoSuchEntity", "The user policy with name ReadOnly cannot be found.")
}

func TestIAMApiControllerUserPolicyValidationErrors(t *testing.T) {
	validDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	oversizedDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 2000) + `","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	tests := []struct {
		name      string
		setupUser bool
		params    url.Values
		status    int
		code      string
		message   string
	}{
		{
			name:      "put missing policy document",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"P"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "put missing policy name",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyDocument": {validDoc}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'policyName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:    "put missing user name",
			params:  url.Values{"Action": {"PutUserPolicy"}, "PolicyName": {"P"}, "PolicyDocument": {validDoc}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "put invalid policy name characters",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"bad/name"}, "PolicyDocument": {validDoc}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "The specified value for policyName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name:      "put long policy name",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {strings.Repeat("p", 129)}, "PolicyDocument": {validDoc}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'policyName' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name:      "put non-ascii policy document",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"P"}, "PolicyDocument": {"emoji\U0001F600test"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "The specified value for policyDocument is invalid. It must contain only printable ASCII characters.",
		},
		{
			name:    "put user does not exist",
			params:  url.Values{"Action": {"PutUserPolicy"}, "UserName": {"nonexistent"}, "PolicyName": {"P"}, "PolicyDocument": {validDoc}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name nonexistent cannot be found.",
		},
		{
			name:    "put nonexistent user wins over malformed document",
			params:  url.Values{"Action": {"PutUserPolicy"}, "UserName": {"nonexistent"}, "PolicyName": {"P"}, "PolicyDocument": {"{not valid json"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name nonexistent cannot be found.",
		},
		{
			name:      "put malformed policy document",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"P"}, "PolicyDocument": {"{not valid json"}},
			status:    http.StatusBadRequest,
			code:      "MalformedPolicyDocument",
			message:   "Syntax errors in policy.",
		},
		{
			name:      "put policy document with principal",
			setupUser: true,
			params: url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"P"}, "PolicyDocument": {
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
			}},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Policy document should not specify a principal.",
		},
		{
			name:      "put policy document exceeds aggregate size quota",
			setupUser: true,
			params:    url.Values{"Action": {"PutUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"P"}, "PolicyDocument": {oversizedDoc}},
			status:    http.StatusConflict,
			code:      "LimitExceeded",
			message:   "Maximum policy size of 2048 bytes exceeded for user alice",
		},
		{
			name:    "get user does not exist",
			params:  url.Values{"Action": {"GetUserPolicy"}, "UserName": {"nonexistent"}, "PolicyName": {"P"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name nonexistent cannot be found.",
		},
		{
			name:      "get policy does not exist",
			setupUser: true,
			params:    url.Values{"Action": {"GetUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"NoSuchPolicy"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The user policy with name NoSuchPolicy cannot be found.",
		},
		{
			name:    "delete user does not exist",
			params:  url.Values{"Action": {"DeleteUserPolicy"}, "UserName": {"nonexistent"}, "PolicyName": {"P"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name nonexistent cannot be found.",
		},
		{
			name:      "delete policy does not exist",
			setupUser: true,
			params:    url.Values{"Action": {"DeleteUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"NoSuchPolicy"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The user policy with name NoSuchPolicy cannot be found.",
		},
		{
			name:    "list user does not exist",
			params:  url.Values{"Action": {"ListUserPolicies"}, "UserName": {"nonexistent"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The user with name nonexistent cannot be found.",
		},
		{
			name:      "list max items too large",
			setupUser: true,
			params:    url.Values{"Action": {"ListUserPolicies"}, "UserName": {"alice"}, "MaxItems": {"1001"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			if tt.setupUser {
				resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
				}
			}
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func TestIAMApiControllerPutUserPolicyOversizedDocument(t *testing.T) {
	// A >131072 byte PolicyDocument does not fit in a GET query string
	// against this test server's header/URL read-buffer limit, matching
	// real IAM's own guidance to use POST rather than GET for large
	// policy documents - so this one case is exercised over POST directly
	// rather than through the doIAMAction GET helper used elsewhere.
	server := newIAMControllerTestServer(t)
	create := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", create.StatusCode, readBody(t, create))
	}

	resp := doIAMActionPost(t, server, url.Values{
		"Action":         {"PutUserPolicy"},
		"UserName":       {"alice"},
		"PolicyName":     {"P"},
		"PolicyDocument": {strings.Repeat("x", 131073)},
	})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
		"1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: Member must have length less than or equal to 131072")
}

func TestIAMApiControllerDeleteUserPolicyConflict(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"alice"}})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", create.StatusCode, readBody(t, create))
	}
	put := doIAMAction(t, server, url.Values{
		"Action":         {"PutUserPolicy"},
		"UserName":       {"alice"},
		"PolicyName":     {"P"},
		"PolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`},
	})
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PutUserPolicy status = %d, body=%s", put.StatusCode, readBody(t, put))
	}

	deletePolicyOnly := doIAMAction(t, server, url.Values{"Action": {"DeleteUser"}, "UserName": {"alice"}})
	requireIAMError(t, deletePolicyOnly, http.StatusConflict, "Sender", "DeleteConflict", "Cannot delete entity, must delete policies first.")

	// When both an access key and a policy are attached, the policy
	// conflict is reported first.
	createKey := doIAMAction(t, server, url.Values{"Action": {"CreateAccessKey"}, "UserName": {"alice"}})
	if createKey.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey status = %d, body=%s", createKey.StatusCode, readBody(t, createKey))
	}
	deleteBoth := doIAMAction(t, server, url.Values{"Action": {"DeleteUser"}, "UserName": {"alice"}})
	requireIAMError(t, deleteBoth, http.StatusConflict, "Sender", "DeleteConflict", "Cannot delete entity, must delete policies first.")

	delPolicy := doIAMAction(t, server, url.Values{"Action": {"DeleteUserPolicy"}, "UserName": {"alice"}, "PolicyName": {"P"}})
	if delPolicy.StatusCode != http.StatusOK {
		t.Fatalf("DeleteUserPolicy status = %d, body=%s", delPolicy.StatusCode, readBody(t, delPolicy))
	}

	deleteKeyOnly := doIAMAction(t, server, url.Values{"Action": {"DeleteUser"}, "UserName": {"alice"}})
	requireIAMError(t, deleteKeyOnly, http.StatusConflict, "Sender", "DeleteConflict", "Cannot delete entity, must delete access keys first.")
}

const validTrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`

func TestIAMApiControllerRoleLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"my-role"},
		"Path":                     {"/engineering/"},
		"AssumeRolePolicyDocument": {validTrustPolicy},
		"Description":              {"a test role"},
		"MaxSessionDuration":       {"7200"},
		"Tags.member.1.Key":        {"env"},
		"Tags.member.1.Value":      {"test"},
	})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", create.StatusCode, readBody(t, create))
	}
	createBody := readBody(t, create)
	var createOut iamtypes.CreateRoleResponse
	unmarshalXML(t, createBody, &createOut)
	if createOut.XMLName.Space != "https://iam.amazonaws.com/doc/2010-05-08/" || createOut.XMLName.Local != "CreateRoleResponse" {
		t.Fatalf("CreateRole XMLName = %#v", createOut.XMLName)
	}
	role := createOut.Result.Role
	if role.Path != "/engineering/" || role.RoleName != "my-role" {
		t.Fatalf("created role = %#v, want path/name", role)
	}
	if !roleIDPattern.MatchString(role.RoleID) {
		t.Fatalf("RoleId = %q, want AWS IAM role id form", role.RoleID)
	}
	if role.Arn != "arn:aws:iam::000000000000:role/engineering/my-role" {
		t.Fatalf("Arn = %q", role.Arn)
	}
	if role.CreateDate.IsZero() {
		t.Fatal("CreateDate is zero")
	}
	if role.Description != "a test role" {
		t.Fatalf("Description = %q", role.Description)
	}
	if role.MaxSessionDuration != 7200 {
		t.Fatalf("MaxSessionDuration = %d, want 7200", role.MaxSessionDuration)
	}
	wantEncodedPolicy := iamutil.EncodePolicyDocument(validTrustPolicy)
	if role.AssumeRolePolicyDocument != wantEncodedPolicy {
		t.Fatalf("AssumeRolePolicyDocument = %q, want %q", role.AssumeRolePolicyDocument, wantEncodedPolicy)
	}
	if role.RoleLastUsed == nil {
		t.Fatal("CreateRole RoleLastUsed = nil, want non-nil empty element")
	}
	if len(role.Tags) != 1 || role.Tags[0].Key != "env" || role.Tags[0].Value != "test" {
		t.Fatalf("Tags = %#v", role.Tags)
	}
	if createOut.ResponseMetadata.RequestID == "" {
		t.Fatal("CreateRole missing RequestId")
	}

	duplicate := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"MY-ROLE"},
		"AssumeRolePolicyDocument": {validTrustPolicy},
	})
	requireIAMError(t, duplicate, http.StatusConflict, "Sender", "EntityAlreadyExists", "Role with name MY-ROLE already exists.")

	get := doIAMAction(t, server, url.Values{
		"Action":   {"GetRole"},
		"RoleName": {"my-role"},
	})
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GetRole status = %d, body=%s", get.StatusCode, readBody(t, get))
	}
	var getOut iamtypes.GetRoleResponse
	unmarshalXML(t, readBody(t, get), &getOut)
	gotRole := getOut.Result.Role
	if gotRole.RoleID != role.RoleID || !gotRole.CreateDate.Equal(role.CreateDate) {
		t.Fatalf("GetRole identity = %#v, want RoleId/CreateDate preserved from %#v", gotRole, role)
	}
	if gotRole.RoleLastUsed == nil {
		t.Fatal("GetRole RoleLastUsed = nil, want non-nil empty element")
	}
	if gotRole.AssumeRolePolicyDocument != wantEncodedPolicy {
		t.Fatalf("GetRole AssumeRolePolicyDocument = %q, want %q", gotRole.AssumeRolePolicyDocument, wantEncodedPolicy)
	}

	list := doIAMAction(t, server, url.Values{
		"Action":     {"ListRoles"},
		"PathPrefix": {"/engineering/"},
	})
	if list.StatusCode != http.StatusOK {
		t.Fatalf("ListRoles status = %d, body=%s", list.StatusCode, readBody(t, list))
	}
	var listOut iamtypes.ListRolesResponse
	unmarshalXML(t, readBody(t, list), &listOut)
	if len(listOut.Result.Roles.Members) != 1 || listOut.Result.Roles.Members[0].RoleName != "my-role" {
		t.Fatalf("ListRoles = %#v, want my-role", listOut.Result.Roles.Members)
	}
	if listOut.Result.Roles.Members[0].RoleLastUsed != nil {
		t.Fatalf("ListRoles RoleLastUsed = %#v, want nil (list/get asymmetry)", listOut.Result.Roles.Members[0].RoleLastUsed)
	}
	if listOut.Result.Roles.Members[0].AssumeRolePolicyDocument != wantEncodedPolicy {
		t.Fatalf("ListRoles AssumeRolePolicyDocument = %q, want %q", listOut.Result.Roles.Members[0].AssumeRolePolicyDocument, wantEncodedPolicy)
	}

	const updatedTrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	update := doIAMAction(t, server, url.Values{
		"Action":         {"UpdateAssumeRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyDocument": {updatedTrustPolicy},
	})
	if update.StatusCode != http.StatusOK {
		t.Fatalf("UpdateAssumeRolePolicy status = %d, body=%s", update.StatusCode, readBody(t, update))
	}
	var updateOut iamtypes.UpdateAssumeRolePolicyResponse
	unmarshalXML(t, readBody(t, update), &updateOut)
	if updateOut.XMLName.Local != "UpdateAssumeRolePolicyResponse" || updateOut.ResponseMetadata.RequestID == "" {
		t.Fatalf("UpdateAssumeRolePolicy output = %#v", updateOut)
	}

	oversizedTrustPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 2000) + `","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
	updateOversized := doIAMAction(t, server, url.Values{
		"Action":         {"UpdateAssumeRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyDocument": {oversizedTrustPolicy},
	})
	requireIAMError(t, updateOversized, http.StatusConflict, "Sender", "LimitExceeded", "Cannot exceed quota for ACLSizePerRole: 2048")

	getAfterUpdate := doIAMAction(t, server, url.Values{
		"Action":   {"GetRole"},
		"RoleName": {"my-role"},
	})
	var getAfterUpdateOut iamtypes.GetRoleResponse
	unmarshalXML(t, readBody(t, getAfterUpdate), &getAfterUpdateOut)
	wantUpdatedEncoded := iamutil.EncodePolicyDocument(updatedTrustPolicy)
	if getAfterUpdateOut.Result.Role.AssumeRolePolicyDocument != wantUpdatedEncoded {
		t.Fatalf("GetRole after update AssumeRolePolicyDocument = %q, want %q", getAfterUpdateOut.Result.Role.AssumeRolePolicyDocument, wantUpdatedEncoded)
	}

	deleteResp := doIAMAction(t, server, url.Values{
		"Action":   {"DeleteRole"},
		"RoleName": {"my-role"},
	})
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteRole status = %d, body=%s", deleteResp.StatusCode, readBody(t, deleteResp))
	}
	var deleteOut iamtypes.DeleteRoleResponse
	unmarshalXML(t, readBody(t, deleteResp), &deleteOut)
	if deleteOut.XMLName.Local != "DeleteRoleResponse" || deleteOut.ResponseMetadata.RequestID == "" {
		t.Fatalf("DeleteRole output = %#v", deleteOut)
	}

	missing := doIAMAction(t, server, url.Values{
		"Action":   {"GetRole"},
		"RoleName": {"my-role"},
	})
	requireIAMError(t, missing, http.StatusNotFound, "Sender", "NoSuchEntity", "The role with name my-role cannot be found.")
}

// TestIAMApiControllerRoleLastUsed covers the RoleLastUsed lifecycle GetRole
// reports: a role nobody has assumed carries the empty element, and a
// request authenticated with one of the role's session credentials records
// that use — the role's counterpart to an access key's GetAccessKeyLastUsed
// tracking. GetCallerIdentity is the request here because it needs no
// policy of its own, so this exercises the auth middleware's recording
// independently of what the role is allowed to do.
func TestIAMApiControllerRoleLastUsed(t *testing.T) {
	server := newIAMControllerTestServer(t)
	session := createTestSession(t, server, "tracked-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}`, "")

	if lastUsed := getRoleLastUsed(t, server, "tracked-role"); lastUsed == nil || lastUsed.LastUsedDate != nil || lastUsed.Region != "" {
		t.Fatalf("RoleLastUsed before any use = %#v, want the empty element", lastUsed)
	}

	before := time.Now().UTC().Add(-time.Second)
	resp := doSignedSTSAction(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	lastUsed := getRoleLastUsed(t, server, "tracked-role")
	if lastUsed == nil || lastUsed.LastUsedDate == nil {
		t.Fatalf("RoleLastUsed after a session-authenticated request = %#v, want a recorded date", lastUsed)
	}
	if lastUsed.LastUsedDate.Before(before) {
		t.Fatalf("RoleLastUsed.LastUsedDate = %v, want at or after %v", lastUsed.LastUsedDate, before)
	}
	if lastUsed.Region != iammiddleware.SigningRegion {
		t.Fatalf("RoleLastUsed.Region = %q, want %q", lastUsed.Region, iammiddleware.SigningRegion)
	}

	// ListRoles omits RoleLastUsed entirely, used or not.
	list := doIAMAction(t, server, url.Values{"Action": {"ListRoles"}})
	var listOut iamtypes.ListRolesResponse
	unmarshalXML(t, readBody(t, list), &listOut)
	if len(listOut.Result.Roles.Members) != 1 || listOut.Result.Roles.Members[0].RoleLastUsed != nil {
		t.Fatalf("ListRoles members = %#v, want the used role with no RoleLastUsed", listOut.Result.Roles.Members)
	}
}

// TestIAMApiControllerRoleLastUsedNotRecordedForReplacedRole confirms a
// session that outlived its role does not attribute its own use to a
// same-named replacement role: the session still authenticates (STS
// credentials are self-contained), but the new role — which it was never
// minted against — must still report as never used.
func TestIAMApiControllerRoleLastUsedNotRecordedForReplacedRole(t *testing.T) {
	server := newIAMControllerTestServer(t)
	createTestRoleForTrust(t, server, "recreated-role", validTrustPolicy)

	get := doIAMAction(t, server, url.Values{"Action": {"GetRole"}, "RoleName": {"recreated-role"}})
	var getOut iamtypes.GetRoleResponse
	unmarshalXML(t, readBody(t, get), &getOut)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTREPLACEDROLE1",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         getOut.Result.Role.Arn,
		RoleName:        getOut.Result.Role.RoleName,
		RoleID:          getOut.Result.Role.RoleID,
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if resp := doIAMAction(t, server, url.Values{"Action": {"DeleteRole"}, "RoleName": {"recreated-role"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	createTestRoleForTrust(t, server, "recreated-role", validTrustPolicy)

	resp := doSignedSTSAction(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	if lastUsed := getRoleLastUsed(t, server, "recreated-role"); lastUsed == nil || lastUsed.LastUsedDate != nil {
		t.Fatalf("replacement role RoleLastUsed = %#v, want the empty element", lastUsed)
	}
}

func getRoleLastUsed(t *testing.T, server *IAMApiServer, roleName string) *iamtypes.RoleLastUsed {
	t.Helper()
	resp := doIAMAction(t, server, url.Values{"Action": {"GetRole"}, "RoleName": {roleName}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out iamtypes.GetRoleResponse
	unmarshalXML(t, readBody(t, resp), &out)
	if out.Result.Role == nil {
		t.Fatal("GetRole returned no role")
	}
	return out.Result.Role.RoleLastUsed
}

func TestIAMApiControllerRoleTagLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)
	createTestRoleForTrust(t, server, "my-role", validTrustPolicy)

	if got := listRoleTags(t, server, "my-role"); len(got.Tags.Members) != 0 || got.IsTruncated {
		t.Fatalf("ListRoleTags on a fresh role = %#v, want no tags", got)
	}

	tagRole(t, server, "my-role", map[string]string{"env": "prod", "team": "storage", "empty": ""})

	got := listRoleTags(t, server, "my-role")
	// Sorted by key, regardless of the order they were added in.
	want := []iamtypes.Tag{{Key: "empty", Value: ""}, {Key: "env", Value: "prod"}, {Key: "team", Value: "storage"}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags = %#v, want %#v", got.Tags.Members, want)
	}

	// A repeated key replaces its value in place; a differently-cased key
	// is the same tag, and the new casing wins.
	tagRole(t, server, "my-role", map[string]string{"env": "staging"})
	tagRole(t, server, "my-role", map[string]string{"TEAM": "compute"})

	got = listRoleTags(t, server, "my-role")
	want = []iamtypes.Tag{{Key: "TEAM", Value: "compute"}, {Key: "empty", Value: ""}, {Key: "env", Value: "staging"}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags after overwrite = %#v, want %#v", got.Tags.Members, want)
	}

	// GetRole reports the same tags the tag actions maintain.
	getRole := doIAMAction(t, server, url.Values{"Action": {"GetRole"}, "RoleName": {"my-role"}})
	var getResp struct {
		Result struct{ Role iamtypes.Role } `xml:"GetRoleResult"`
	}
	unmarshalXML(t, readBody(t, getRole), &getResp)
	if len(getResp.Result.Role.Tags) != 3 {
		t.Fatalf("GetRole Tags = %#v, want 3 tags", getResp.Result.Role.Tags)
	}

	// Removal is case-insensitive, and a key naming no tag is not an error.
	untag := doIAMAction(t, server, url.Values{
		"Action":           {"UntagRole"},
		"RoleName":         {"my-role"},
		"TagKeys.member.1": {"EnV"},
		"TagKeys.member.2": {"never-existed"},
	})
	if untag.StatusCode != http.StatusOK {
		t.Fatalf("UntagRole status = %d, body=%s", untag.StatusCode, readBody(t, untag))
	}

	got = listRoleTags(t, server, "my-role")
	want = []iamtypes.Tag{{Key: "TEAM", Value: "compute"}, {Key: "empty", Value: ""}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags after untag = %#v, want %#v", got.Tags.Members, want)
	}
}

// TestIAMApiControllerRoleTagsIndependentOfUserTags covers a role and a user
// sharing a name: they are separate entities, so neither one's tags leak
// into the other's.
func TestIAMApiControllerRoleTagsIndependentOfUserTags(t *testing.T) {
	server := newIAMControllerTestServer(t)
	createTestRoleForTrust(t, server, "shared", validTrustPolicy)
	if resp := doIAMAction(t, server, url.Values{"Action": {"CreateUser"}, "UserName": {"shared"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	tagRole(t, server, "shared", map[string]string{"owner": "role"})
	tagUser(t, server, "shared", map[string]string{"owner": "user"})

	if got := listRoleTags(t, server, "shared").Tags.Members; !slices.Equal(got, []iamtypes.Tag{{Key: "owner", Value: "role"}}) {
		t.Fatalf("role tags = %#v", got)
	}
	if got := listUserTags(t, server, "shared").Tags.Members; !slices.Equal(got, []iamtypes.Tag{{Key: "owner", Value: "user"}}) {
		t.Fatalf("user tags = %#v", got)
	}

	untag := doIAMAction(t, server, url.Values{
		"Action": {"UntagRole"}, "RoleName": {"shared"}, "TagKeys.member.1": {"owner"},
	})
	if untag.StatusCode != http.StatusOK {
		t.Fatalf("UntagRole status = %d, body=%s", untag.StatusCode, readBody(t, untag))
	}
	if got := listRoleTags(t, server, "shared").Tags.Members; len(got) != 0 {
		t.Fatalf("role tags after untag = %#v, want none", got)
	}
	if got := listUserTags(t, server, "shared").Tags.Members; !slices.Equal(got, []iamtypes.Tag{{Key: "owner", Value: "user"}}) {
		t.Fatalf("user tags after untagging the role = %#v", got)
	}
}

func TestIAMApiControllerListRoleTagsPagination(t *testing.T) {
	server := newIAMControllerTestServer(t)
	createTestRoleForTrust(t, server, "my-role", validTrustPolicy)
	tagRole(t, server, "my-role", map[string]string{"a": "1", "b": "2", "c": "3"})

	var seen []iamtypes.Tag
	marker := ""
	for page := 1; ; page++ {
		params := url.Values{"Action": {"ListRoleTags"}, "RoleName": {"my-role"}, "MaxItems": {"1"}}
		if marker != "" {
			params.Set("Marker", marker)
		}
		resp := doIAMAction(t, server, params)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ListRoleTags status = %d, body=%s", resp.StatusCode, readBody(t, resp))
		}
		var out struct {
			Result iamtypes.ListRoleTagsResult `xml:"ListRoleTagsResult"`
		}
		unmarshalXML(t, readBody(t, resp), &out)

		if len(out.Result.Tags.Members) != 1 {
			t.Fatalf("page %d holds %d tags, want 1", page, len(out.Result.Tags.Members))
		}
		seen = append(seen, out.Result.Tags.Members...)
		if !out.Result.IsTruncated {
			if out.Result.Marker != "" {
				t.Fatalf("final page Marker = %q, want empty", out.Result.Marker)
			}
			break
		}
		marker = out.Result.Marker
	}

	want := []iamtypes.Tag{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}, {Key: "c", Value: "3"}}
	if !slices.Equal(seen, want) {
		t.Fatalf("paged tags = %#v, want %#v", seen, want)
	}
}

func TestIAMApiControllerTagRoleExceedsQuota(t *testing.T) {
	server := newIAMControllerTestServer(t)
	createTestRoleForTrust(t, server, "my-role", validTrustPolicy)

	atQuota := url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}}
	for i := 1; i <= storage.MaxTagsPerResource; i++ {
		atQuota.Set(fmt.Sprintf("Tags.member.%d.Key", i), fmt.Sprintf("k%d", i))
		atQuota.Set(fmt.Sprintf("Tags.member.%d.Value", i), fmt.Sprintf("v%d", i))
	}
	if resp := doIAMAction(t, server, atQuota); resp.StatusCode != http.StatusOK {
		t.Fatalf("TagRole with %d tags status = %d, body=%s", storage.MaxTagsPerResource, resp.StatusCode, readBody(t, resp))
	}

	// Replacing an existing key at the quota is fine: the total doesn't grow.
	replace := doIAMAction(t, server, url.Values{
		"Action": {"TagRole"}, "RoleName": {"my-role"},
		"Tags.member.1.Key": {"k1"}, "Tags.member.1.Value": {"replaced"},
	})
	if replace.StatusCode != http.StatusOK {
		t.Fatalf("TagRole replacing at quota status = %d, body=%s", replace.StatusCode, readBody(t, replace))
	}

	// One more distinct key does not fit.
	overflow := doIAMAction(t, server, url.Values{
		"Action": {"TagRole"}, "RoleName": {"my-role"},
		"Tags.member.1.Key": {"overflow"}, "Tags.member.1.Value": {"x"},
	})
	requireIAMError(t, overflow, http.StatusConflict, "Sender", "LimitExceeded",
		"The number of tags has reached the maximum limit.")
}

func TestIAMApiControllerRoleTagValidationErrors(t *testing.T) {
	tooManyTags := url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}}
	for i := 1; i <= iamutil.MaxTagMembersPerRequest+1; i++ {
		tooManyTags.Set(fmt.Sprintf("Tags.member.%d.Key", i), fmt.Sprintf("k%d", i))
		tooManyTags.Set(fmt.Sprintf("Tags.member.%d.Value", i), fmt.Sprintf("v%d", i))
	}
	tooManyTagKeys := url.Values{"Action": {"UntagRole"}, "RoleName": {"my-role"}}
	for i := 1; i <= iamutil.MaxTagMembersPerRequest+1; i++ {
		tooManyTagKeys.Set(fmt.Sprintf("TagKeys.member.%d", i), fmt.Sprintf("k%d", i))
	}

	tests := []struct {
		name      string
		setupRole bool
		params    url.Values
		status    int
		code      string
		message   string
	}{
		{
			name:    "tag missing role name",
			params:  url.Values{"Action": {"TagRole"}, "Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag missing tags",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag missing key",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Value": {"prod"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag missing value",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Key": {"env"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "tag empty key",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Key": {""}, "Tags.member.1.Value": {"prod"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length greater than or equal to 1",
		},
		{
			name:      "tag key too long",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Key": {strings.Repeat("k", 129)}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name:      "tag invalid key characters",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Key": {"bad*key"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   `1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]+`,
		},
		{
			name:      "tag value too long",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {strings.Repeat("v", 257)}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256",
		},
		{
			name:      "tag invalid value characters",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"my-role"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"bad*value"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   `1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]*`,
		},
		{
			name:      "tag duplicate keys",
			setupRole: true,
			params: url.Values{
				"Action": {"TagRole"}, "RoleName": {"my-role"},
				"Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"a"},
				"Tags.member.2.Key": {"ENV"}, "Tags.member.2.Value": {"b"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Duplicate tag keys found. Please note that Tag keys are case insensitive.",
		},
		{
			name:      "tag too many tags",
			setupRole: true,
			params:    tooManyTags,
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50",
		},
		{
			name:      "tag invalid role name characters",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"bad!name"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "The specified value for roleName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name:      "tag role name too long",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {strings.Repeat("r", 65)}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must have length less than or equal to 64",
		},
		{
			// A malformed tag is reported before the role is looked up.
			name:      "tag non existing role with invalid tag",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"nosuchrole"}, "Tags.member.1.Key": {"bad*key"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   `1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]+`,
		},
		{
			name:      "tag non existing role",
			setupRole: true,
			params:    url.Values{"Action": {"TagRole"}, "RoleName": {"nosuchrole"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The role with name nosuchrole cannot be found.",
		},
		{
			name:    "untag missing role name",
			params:  url.Values{"Action": {"UntagRole"}, "TagKeys.member.1": {"env"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "untag missing tag keys",
			setupRole: true,
			params:    url.Values{"Action": {"UntagRole"}, "RoleName": {"my-role"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "untag empty key",
			setupRole: true,
			params:    url.Values{"Action": {"UntagRole"}, "RoleName": {"my-role"}, "TagKeys.member.1": {""}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   invalidTagKeysMessage,
		},
		{
			name:      "untag key too long",
			setupRole: true,
			params:    url.Values{"Action": {"UntagRole"}, "RoleName": {"my-role"}, "TagKeys.member.1": {strings.Repeat("k", 129)}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   invalidTagKeysMessage,
		},
		{
			name:      "untag invalid key characters",
			setupRole: true,
			params:    url.Values{"Action": {"UntagRole"}, "RoleName": {"my-role"}, "TagKeys.member.1": {"bad*key"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   invalidTagKeysMessage,
		},
		{
			name:      "untag too many tag keys",
			setupRole: true,
			params:    tooManyTagKeys,
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to 50",
		},
		{
			name:      "untag non existing role",
			setupRole: true,
			params:    url.Values{"Action": {"UntagRole"}, "RoleName": {"nosuchrole"}, "TagKeys.member.1": {"env"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The role with name nosuchrole cannot be found.",
		},
		{
			name:    "list missing role name",
			params:  url.Values{"Action": {"ListRoleTags"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "list max items too small",
			setupRole: true,
			params:    url.Values{"Action": {"ListRoleTags"}, "RoleName": {"my-role"}, "MaxItems": {"0"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
		},
		{
			name:      "list max items too large",
			setupRole: true,
			params:    url.Values{"Action": {"ListRoleTags"}, "RoleName": {"my-role"}, "MaxItems": {"1001"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
		},
		{
			name:      "list max items not a number",
			setupRole: true,
			params:    url.Values{"Action": {"ListRoleTags"}, "RoleName": {"my-role"}, "MaxItems": {"abc"}},
			status:    http.StatusBadRequest,
			code:      "MalformedInput",
			message:   "",
		},
		{
			name:      "list non existing role",
			setupRole: true,
			params:    url.Values{"Action": {"ListRoleTags"}, "RoleName": {"nosuchrole"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The role with name nosuchrole cannot be found.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			if tt.setupRole {
				createTestRoleForTrust(t, server, "my-role", validTrustPolicy)
			}
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func tagRole(t *testing.T, server *IAMApiServer, roleName string, tags map[string]string) {
	t.Helper()

	params := url.Values{"Action": {"TagRole"}, "RoleName": {roleName}}
	i := 1
	for key, value := range tags {
		params.Set(fmt.Sprintf("Tags.member.%d.Key", i), key)
		params.Set(fmt.Sprintf("Tags.member.%d.Value", i), value)
		i++
	}

	resp := doIAMAction(t, server, params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TagRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func listRoleTags(t *testing.T, server *IAMApiServer, roleName string) iamtypes.ListRoleTagsResult {
	t.Helper()

	resp := doIAMAction(t, server, url.Values{"Action": {"ListRoleTags"}, "RoleName": {roleName}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListRoleTags status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out struct {
		Result iamtypes.ListRoleTagsResult `xml:"ListRoleTagsResult"`
	}
	unmarshalXML(t, readBody(t, resp), &out)
	return out.Result
}

func TestIAMApiControllerCreateRoleValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		status  int
		code    string
		message string
	}{
		{
			name: "missing role name",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "invalid role name",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"bad/name"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for roleName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name: "long role name",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {strings.Repeat("a", 65)},
				"AssumeRolePolicyDocument": {validTrustPolicy},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must have length less than or equal to 64",
		},
		{
			name: "invalid path",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"Path":                     {"bad"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "The specified value for path is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters.",
		},
		{
			name: "missing assume role policy document",
			params: url.Values{
				"Action":   {"CreateRole"},
				"RoleName": {"my-role"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'assumeRolePolicyDocument' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "invalid json policy",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {"{invalid"},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "This policy contains invalid Json",
		},
		{
			name: "policy statement empty",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Could not parse the policy: Statement is empty!",
		},
		{
			name: "policy missing principal",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Missing required field Principal",
		},
		{
			name: "policy principal empty object",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{},"Action":"sts:AssumeRole"}]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Missing required field Principal cannot be empty!",
		},
		{
			name: "policy action not sts prefixed",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"*"}]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "AssumeRole policy may only specify STS AssumeRole actions.",
		},
		{
			name: "policy has resource",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Resource":"*"}]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Has prohibited field Resource",
		},
		{
			name: "policy has notresource",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","NotResource":"*"}]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "AssumeRole policy must not contain resources.",
		},
		{
			name: "policy allow with notprincipal",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Allow with NotPrincipal is not allowed.",
		},
		{
			name: "policy too large",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {strings.Repeat("x", 131073)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'assumeRolePolicyDocument' failed to satisfy constraint: Member must have length less than or equal to 131072",
		},
		{
			name: "description invalid charset",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
				"Description":              {"emoji\U0001F600test"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'description' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u007E\\u00A1-\\u00FF]*",
		},
		{
			name: "trust policy exceeds ACLSizePerRole quota",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 2000) + `","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`},
			},
			status:  http.StatusConflict,
			code:    "LimitExceeded",
			message: "Cannot exceed quota for ACLSizePerRole: 2048",
		},
		{
			name: "max session duration not a number",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
				"MaxSessionDuration":       {"not-a-number"},
			},
			status:  http.StatusBadRequest,
			code:    "MalformedInput",
			message: "",
		},
		{
			name: "max session duration too low",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
				"MaxSessionDuration":       {"3599"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'maxSessionDuration' failed to satisfy constraint: Member must have value greater than or equal to 3600",
		},
		{
			name: "max session duration too high",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
				"MaxSessionDuration":       {"43201"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'maxSessionDuration' failed to satisfy constraint: Member must have value less than or equal to 43200",
		},
		{
			name: "duplicate tag key",
			params: url.Values{
				"Action":                   {"CreateRole"},
				"RoleName":                 {"my-role"},
				"AssumeRolePolicyDocument": {validTrustPolicy},
				"Tags.member.1.Key":        {"dup"},
				"Tags.member.1.Value":      {"one"},
				"Tags.member.2.Key":        {"DUP"},
				"Tags.member.2.Value":      {"two"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Duplicate tag keys found. Please note that Tag keys are case insensitive.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			resp := doIAMActionPost(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func TestIAMApiControllerDeleteAndUpdateAssumeRolePolicyErrors(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		status  int
		code    string
		message string
	}{
		{
			name: "get missing role name",
			params: url.Values{
				"Action": {"GetRole"},
			},
			status:  http.StatusBadRequest,
			code:    "MissingParameter",
			message: "The request must contain the parameter RoleName.",
		},
		{
			name: "get missing role",
			params: url.Values{
				"Action":   {"GetRole"},
				"RoleName": {"asdfadsf"},
			},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name asdfadsf cannot be found.",
		},
		{
			name: "delete missing role",
			params: url.Values{
				"Action":   {"DeleteRole"},
				"RoleName": {"asdfadsf"},
			},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name asdfadsf cannot be found.",
		},
		{
			name: "update assume role policy missing role",
			params: url.Values{
				"Action":         {"UpdateAssumeRolePolicy"},
				"RoleName":       {"asdfadsf"},
				"PolicyDocument": {validTrustPolicy},
			},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name asdfadsf cannot be found.",
		},
		{
			name: "update assume role policy missing document",
			params: url.Values{
				"Action":   {"UpdateAssumeRolePolicy"},
				"RoleName": {"asdfadsf"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: Member must not be null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func TestIAMApiControllerRolePolicyLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)

	createRole := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"my-role"},
		"AssumeRolePolicyDocument": {validTrustPolicy},
	})
	if createRole.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", createRole.StatusCode, readBody(t, createRole))
	}

	policyDoc := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}`

	put := doIAMAction(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyName":     {"ReadOnly"},
		"PolicyDocument": {policyDoc},
	})
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PutRolePolicy status = %d, body=%s", put.StatusCode, readBody(t, put))
	}
	var putOut iamtypes.PutRolePolicyResponse
	unmarshalXML(t, readBody(t, put), &putOut)
	if putOut.XMLName.Space != "https://iam.amazonaws.com/doc/2010-05-08/" || putOut.XMLName.Local != "PutRolePolicyResponse" {
		t.Fatalf("PutRolePolicy XMLName = %#v", putOut.XMLName)
	}
	if putOut.ResponseMetadata.RequestID == "" {
		t.Fatal("PutRolePolicy missing RequestId")
	}

	get := doIAMAction(t, server, url.Values{
		"Action":     {"GetRolePolicy"},
		"RoleName":   {"my-role"},
		"PolicyName": {"ReadOnly"},
	})
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GetRolePolicy status = %d, body=%s", get.StatusCode, readBody(t, get))
	}
	var getOut iamtypes.GetRolePolicyResponse
	unmarshalXML(t, readBody(t, get), &getOut)
	if getOut.Result.RoleName != "my-role" || getOut.Result.PolicyName != "ReadOnly" {
		t.Fatalf("GetRolePolicy result = %#v", getOut.Result)
	}
	if !strings.Contains(getOut.Result.PolicyDocument, "%20") {
		t.Fatalf("GetRolePolicy PolicyDocument = %q, want RFC 3986 percent-encoding (%%20 for space)", getOut.Result.PolicyDocument)
	}
	decoded, err := url.QueryUnescape(getOut.Result.PolicyDocument)
	if err != nil {
		t.Fatalf("QueryUnescape: %v", err)
	}
	if decoded != policyDoc {
		t.Fatalf("GetRolePolicy PolicyDocument = %q, want verbatim %q", decoded, policyDoc)
	}

	list := doIAMAction(t, server, url.Values{
		"Action":   {"ListRolePolicies"},
		"RoleName": {"my-role"},
	})
	if list.StatusCode != http.StatusOK {
		t.Fatalf("ListRolePolicies status = %d, body=%s", list.StatusCode, readBody(t, list))
	}
	var listOut iamtypes.ListRolePoliciesResponse
	unmarshalXML(t, readBody(t, list), &listOut)
	if len(listOut.Result.PolicyNames.Members) != 1 || listOut.Result.PolicyNames.Members[0] != "ReadOnly" {
		t.Fatalf("ListRolePolicies = %#v, want [ReadOnly]", listOut.Result.PolicyNames.Members)
	}
	if listOut.Result.IsTruncated {
		t.Fatal("ListRolePolicies IsTruncated = true, want false")
	}

	// Re-Put-ing the same PolicyName replaces it rather than erroring or
	// stacking toward the aggregate size quota.
	overwritePut := doIAMAction(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyName":     {"ReadOnly"},
		"PolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`},
	})
	if overwritePut.StatusCode != http.StatusOK {
		t.Fatalf("overwrite PutRolePolicy status = %d, body=%s", overwritePut.StatusCode, readBody(t, overwritePut))
	}
	overwriteGet := doIAMAction(t, server, url.Values{
		"Action":     {"GetRolePolicy"},
		"RoleName":   {"my-role"},
		"PolicyName": {"ReadOnly"},
	})
	var overwriteOut iamtypes.GetRolePolicyResponse
	unmarshalXML(t, readBody(t, overwriteGet), &overwriteOut)
	overwriteDecoded, err := url.QueryUnescape(overwriteOut.Result.PolicyDocument)
	if err != nil {
		t.Fatalf("QueryUnescape: %v", err)
	}
	if !strings.Contains(overwriteDecoded, "Deny") {
		t.Fatalf("GetRolePolicy after overwrite = %q, want the Deny statement", overwriteDecoded)
	}

	del := doIAMAction(t, server, url.Values{
		"Action":     {"DeleteRolePolicy"},
		"RoleName":   {"my-role"},
		"PolicyName": {"ReadOnly"},
	})
	if del.StatusCode != http.StatusOK {
		t.Fatalf("DeleteRolePolicy status = %d, body=%s", del.StatusCode, readBody(t, del))
	}
	var delOut iamtypes.DeleteRolePolicyResponse
	unmarshalXML(t, readBody(t, del), &delOut)
	if delOut.XMLName.Local != "DeleteRolePolicyResponse" || delOut.ResponseMetadata.RequestID == "" {
		t.Fatalf("DeleteRolePolicy output = %#v", delOut)
	}

	missing := doIAMAction(t, server, url.Values{
		"Action":     {"GetRolePolicy"},
		"RoleName":   {"my-role"},
		"PolicyName": {"ReadOnly"},
	})
	requireIAMError(t, missing, http.StatusNotFound, "Sender", "NoSuchEntity", "The role policy with name ReadOnly cannot be found.")

	// A second delete of the same (now-gone) policy is a hard error, not an
	// idempotent success.
	doubleDelete := doIAMAction(t, server, url.Values{
		"Action":     {"DeleteRolePolicy"},
		"RoleName":   {"my-role"},
		"PolicyName": {"ReadOnly"},
	})
	requireIAMError(t, doubleDelete, http.StatusNotFound, "Sender", "NoSuchEntity", "The role policy with name ReadOnly cannot be found.")
}

func TestIAMApiControllerRolePolicyValidationErrors(t *testing.T) {
	validDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	tests := []struct {
		name      string
		setupRole bool
		params    url.Values
		status    int
		code      string
		message   string
	}{
		{
			name:      "put missing policy document",
			setupRole: true,
			params:    url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"P"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "put missing policy name",
			setupRole: true,
			params:    url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyDocument": {validDoc}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'policyName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:    "put missing role name",
			params:  url.Values{"Action": {"PutRolePolicy"}, "PolicyName": {"P"}, "PolicyDocument": {validDoc}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'roleName' failed to satisfy constraint: Member must not be null",
		},
		{
			name:      "put invalid policy name characters",
			setupRole: true,
			params:    url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"bad/name"}, "PolicyDocument": {validDoc}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "The specified value for policyName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
		},
		{
			name:      "put long policy name",
			setupRole: true,
			params:    url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {strings.Repeat("p", 129)}, "PolicyDocument": {validDoc}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'policyName' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name:      "put non-ascii policy document",
			setupRole: true,
			params:    url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"P"}, "PolicyDocument": {"emoji\U0001F600test"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "The specified value for policyDocument is invalid. It must contain only printable ASCII characters.",
		},
		{
			name:    "put role does not exist",
			params:  url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"nonexistent"}, "PolicyName": {"P"}, "PolicyDocument": {validDoc}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name nonexistent cannot be found.",
		},
		{
			name:    "put nonexistent role wins over malformed document",
			params:  url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"nonexistent"}, "PolicyName": {"P"}, "PolicyDocument": {"{not valid json"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name nonexistent cannot be found.",
		},
		{
			name:      "put malformed policy document",
			setupRole: true,
			params:    url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"P"}, "PolicyDocument": {"{not valid json"}},
			status:    http.StatusBadRequest,
			code:      "MalformedPolicyDocument",
			message:   "Syntax errors in policy.",
		},
		{
			name:      "put policy document with principal",
			setupRole: true,
			params: url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"P"}, "PolicyDocument": {
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
			}},
			status:  http.StatusBadRequest,
			code:    "MalformedPolicyDocument",
			message: "Policy document should not specify a principal.",
		},
		{
			name:    "get role does not exist",
			params:  url.Values{"Action": {"GetRolePolicy"}, "RoleName": {"nonexistent"}, "PolicyName": {"P"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name nonexistent cannot be found.",
		},
		{
			name:      "get policy does not exist",
			setupRole: true,
			params:    url.Values{"Action": {"GetRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"NoSuchPolicy"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The role policy with name NoSuchPolicy cannot be found.",
		},
		{
			name:    "delete role does not exist",
			params:  url.Values{"Action": {"DeleteRolePolicy"}, "RoleName": {"nonexistent"}, "PolicyName": {"P"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name nonexistent cannot be found.",
		},
		{
			name:      "delete policy does not exist",
			setupRole: true,
			params:    url.Values{"Action": {"DeleteRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"NoSuchPolicy"}},
			status:    http.StatusNotFound,
			code:      "NoSuchEntity",
			message:   "The role policy with name NoSuchPolicy cannot be found.",
		},
		{
			name:    "list role does not exist",
			params:  url.Values{"Action": {"ListRolePolicies"}, "RoleName": {"nonexistent"}},
			status:  http.StatusNotFound,
			code:    "NoSuchEntity",
			message: "The role with name nonexistent cannot be found.",
		},
		{
			name:      "list max items too large",
			setupRole: true,
			params:    url.Values{"Action": {"ListRolePolicies"}, "RoleName": {"my-role"}, "MaxItems": {"1001"}},
			status:    http.StatusBadRequest,
			code:      "ValidationError",
			message:   "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			if tt.setupRole {
				resp := doIAMAction(t, server, url.Values{
					"Action":                   {"CreateRole"},
					"RoleName":                 {"my-role"},
					"AssumeRolePolicyDocument": {validTrustPolicy},
				})
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CreateRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
				}
			}
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func TestIAMApiControllerDeleteRolePolicyConflict(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"my-role"},
		"AssumeRolePolicyDocument": {validTrustPolicy},
	})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", create.StatusCode, readBody(t, create))
	}
	put := doIAMAction(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyName":     {"P"},
		"PolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`},
	})
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PutRolePolicy status = %d, body=%s", put.StatusCode, readBody(t, put))
	}

	deleteRole := doIAMAction(t, server, url.Values{"Action": {"DeleteRole"}, "RoleName": {"my-role"}})
	requireIAMError(t, deleteRole, http.StatusConflict, "Sender", "DeleteConflict", "Cannot delete entity, must delete policies first.")

	delPolicy := doIAMAction(t, server, url.Values{"Action": {"DeleteRolePolicy"}, "RoleName": {"my-role"}, "PolicyName": {"P"}})
	if delPolicy.StatusCode != http.StatusOK {
		t.Fatalf("DeleteRolePolicy status = %d, body=%s", delPolicy.StatusCode, readBody(t, delPolicy))
	}

	deleteRoleAfter := doIAMAction(t, server, url.Values{"Action": {"DeleteRole"}, "RoleName": {"my-role"}})
	if deleteRoleAfter.StatusCode != http.StatusOK {
		t.Fatalf("DeleteRole status = %d, body=%s", deleteRoleAfter.StatusCode, readBody(t, deleteRoleAfter))
	}
}

func TestIAMApiControllerPutRolePolicyOversizedDocument(t *testing.T) {
	// A >131072 byte PolicyDocument does not fit in a GET query string
	// against this test server's header/URL read-buffer limit, matching
	// real IAM's own guidance to use POST rather than GET for large
	// policy documents - so this one case is exercised over POST directly
	// rather than through the doIAMAction GET helper used elsewhere.
	server := newIAMControllerTestServer(t)
	create := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"my-role"},
		"AssumeRolePolicyDocument": {validTrustPolicy},
	})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", create.StatusCode, readBody(t, create))
	}

	resp := doIAMActionPost(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyName":     {"P"},
		"PolicyDocument": {strings.Repeat("x", 131073)},
	})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
		"1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: Member must have length less than or equal to 131072")
}

func TestIAMApiControllerPutRolePolicyExceedsQuota(t *testing.T) {
	// The role's aggregate inline-policy quota (10240 bytes) is well over
	// this test server's GET header/URL read-buffer limit, so this case
	// is exercised over POST, same as TestIAMApiControllerPutRolePolicyOversizedDocument.
	server := newIAMControllerTestServer(t)
	create := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"my-role"},
		"AssumeRolePolicyDocument": {validTrustPolicy},
	})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", create.StatusCode, readBody(t, create))
	}

	oversizedDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 10300) + `","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	resp := doIAMActionPost(t, server, url.Values{
		"Action":         {"PutRolePolicy"},
		"RoleName":       {"my-role"},
		"PolicyName":     {"P"},
		"PolicyDocument": {oversizedDoc},
	})
	requireIAMError(t, resp, http.StatusConflict, "Sender", "LimitExceeded", "Maximum policy size of 10240 bytes exceeded for role my-role")
}

func TestIAMApiControllerOIDCProviderLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)

	create := doIAMAction(t, server, url.Values{
		"Action":                  {"CreateOpenIDConnectProvider"},
		"Url":                     {"https://token.actions.githubusercontent.com"},
		"ClientIDList.member.1":   {"sts.amazonaws.com"},
		"ThumbprintList.member.1": {"6938FD4D98BAB03FAADB97B34396831E3780AEA1"},
		"Tags.member.1.Key":       {"env"},
		"Tags.member.1.Value":     {"test"},
	})
	if create.StatusCode != http.StatusOK {
		t.Fatalf("CreateOpenIDConnectProvider status = %d, body=%s", create.StatusCode, readBody(t, create))
	}
	createBody := readBody(t, create)
	var createOut iamtypes.CreateOpenIDConnectProviderResponse
	unmarshalXML(t, createBody, &createOut)
	if createOut.XMLName.Space != "https://iam.amazonaws.com/doc/2010-05-08/" || createOut.XMLName.Local != "CreateOpenIDConnectProviderResponse" {
		t.Fatalf("CreateOpenIDConnectProvider XMLName = %#v", createOut.XMLName)
	}
	wantArn := "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
	if createOut.Result.OpenIDConnectProviderArn != wantArn {
		t.Fatalf("OpenIDConnectProviderArn = %q, want %q", createOut.Result.OpenIDConnectProviderArn, wantArn)
	}
	if len(createOut.Result.Tags) != 1 || createOut.Result.Tags[0].Key != "env" || createOut.Result.Tags[0].Value != "test" {
		t.Fatalf("Tags = %#v", createOut.Result.Tags)
	}
	if createOut.ResponseMetadata.RequestID == "" {
		t.Fatal("CreateOpenIDConnectProvider missing RequestId")
	}

	duplicate := doIAMAction(t, server, url.Values{
		"Action":                  {"CreateOpenIDConnectProvider"},
		"Url":                     {"https://token.actions.githubusercontent.com"},
		"ThumbprintList.member.1": {"6938fd4d98bab03faadb97b34396831e3780aea1"},
	})
	requireIAMError(t, duplicate, http.StatusConflict, "Sender", "EntityAlreadyExists",
		"Provider with url https://token.actions.githubusercontent.com already exists.")

	get := doIAMAction(t, server, url.Values{
		"Action":                   {"GetOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
	})
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GetOpenIDConnectProvider status = %d, body=%s", get.StatusCode, readBody(t, get))
	}
	var getOut iamtypes.GetOpenIDConnectProviderResponse
	unmarshalXML(t, readBody(t, get), &getOut)
	if getOut.Result.Url != "token.actions.githubusercontent.com" {
		t.Fatalf("Url = %q, want scheme stripped", getOut.Result.Url)
	}
	if len(getOut.Result.ClientIDList) != 1 || getOut.Result.ClientIDList[0] != "sts.amazonaws.com" {
		t.Fatalf("ClientIDList = %#v", getOut.Result.ClientIDList)
	}
	// Submitted uppercase; AWS lowercases whatever is stored.
	if len(getOut.Result.ThumbprintList) != 1 || getOut.Result.ThumbprintList[0] != "6938fd4d98bab03faadb97b34396831e3780aea1" {
		t.Fatalf("ThumbprintList = %#v, want lowercased", getOut.Result.ThumbprintList)
	}
	if getOut.Result.CreateDate.IsZero() {
		t.Fatal("CreateDate is zero")
	}

	list := doIAMAction(t, server, url.Values{"Action": {"ListOpenIDConnectProviders"}})
	if list.StatusCode != http.StatusOK {
		t.Fatalf("ListOpenIDConnectProviders status = %d, body=%s", list.StatusCode, readBody(t, list))
	}
	var listOut iamtypes.ListOpenIDConnectProvidersResponse
	unmarshalXML(t, readBody(t, list), &listOut)
	if len(listOut.Result.OpenIDConnectProviderList.Members) != 1 || listOut.Result.OpenIDConnectProviderList.Members[0].Arn != wantArn {
		t.Fatalf("ListOpenIDConnectProviders = %#v, want [%s]", listOut.Result.OpenIDConnectProviderList.Members, wantArn)
	}

	addClientID := doIAMAction(t, server, url.Values{
		"Action":                   {"AddClientIDToOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
		"ClientID":                 {"another-client"},
	})
	if addClientID.StatusCode != http.StatusOK {
		t.Fatalf("AddClientIDToOpenIDConnectProvider status = %d, body=%s", addClientID.StatusCode, readBody(t, addClientID))
	}

	// Idempotent: adding an already-present client ID succeeds silently.
	addDuplicate := doIAMAction(t, server, url.Values{
		"Action":                   {"AddClientIDToOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
		"ClientID":                 {"another-client"},
	})
	if addDuplicate.StatusCode != http.StatusOK {
		t.Fatalf("AddClientIDToOpenIDConnectProvider (duplicate) status = %d, body=%s", addDuplicate.StatusCode, readBody(t, addDuplicate))
	}

	removeClientID := doIAMAction(t, server, url.Values{
		"Action":                   {"RemoveClientIDFromOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
		"ClientID":                 {"another-client"},
	})
	if removeClientID.StatusCode != http.StatusOK {
		t.Fatalf("RemoveClientIDFromOpenIDConnectProvider status = %d, body=%s", removeClientID.StatusCode, readBody(t, removeClientID))
	}

	// Idempotent: removing an absent client ID succeeds silently.
	removeAbsent := doIAMAction(t, server, url.Values{
		"Action":                   {"RemoveClientIDFromOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
		"ClientID":                 {"never-existed"},
	})
	if removeAbsent.StatusCode != http.StatusOK {
		t.Fatalf("RemoveClientIDFromOpenIDConnectProvider (absent) status = %d, body=%s", removeAbsent.StatusCode, readBody(t, removeAbsent))
	}

	getAfterClientIDChanges := doIAMAction(t, server, url.Values{
		"Action":                   {"GetOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
	})
	var getAfterClientIDOut iamtypes.GetOpenIDConnectProviderResponse
	unmarshalXML(t, readBody(t, getAfterClientIDChanges), &getAfterClientIDOut)
	if len(getAfterClientIDOut.Result.ClientIDList) != 1 || getAfterClientIDOut.Result.ClientIDList[0] != "sts.amazonaws.com" {
		t.Fatalf("ClientIDList after add+remove = %#v, want [sts.amazonaws.com]", getAfterClientIDOut.Result.ClientIDList)
	}

	updateThumbprint := doIAMAction(t, server, url.Values{
		"Action":                   {"UpdateOpenIDConnectProviderThumbprint"},
		"OpenIDConnectProviderArn": {wantArn},
		"ThumbprintList.member.1":  {strings.Repeat("a", 40)},
		"ThumbprintList.member.2":  {strings.Repeat("B", 40)},
	})
	if updateThumbprint.StatusCode != http.StatusOK {
		t.Fatalf("UpdateOpenIDConnectProviderThumbprint status = %d, body=%s", updateThumbprint.StatusCode, readBody(t, updateThumbprint))
	}

	getAfterThumbprintUpdate := doIAMAction(t, server, url.Values{
		"Action":                   {"GetOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
	})
	var getAfterThumbprintOut iamtypes.GetOpenIDConnectProviderResponse
	unmarshalXML(t, readBody(t, getAfterThumbprintUpdate), &getAfterThumbprintOut)
	wantThumbprints := []string{strings.Repeat("a", 40), strings.Repeat("b", 40)}
	if !slices.Equal(getAfterThumbprintOut.Result.ThumbprintList, wantThumbprints) {
		t.Fatalf("ThumbprintList after update = %#v, want %#v (full replace, lowercased)", getAfterThumbprintOut.Result.ThumbprintList, wantThumbprints)
	}

	deleteResp := doIAMAction(t, server, url.Values{
		"Action":                   {"DeleteOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
	})
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteOpenIDConnectProvider status = %d, body=%s", deleteResp.StatusCode, readBody(t, deleteResp))
	}

	// DeleteOpenIDConnectProvider is NOT idempotent, contradicting AWS's own
	// published docs - a second delete of the same ARN must fail.
	deleteAgain := doIAMAction(t, server, url.Values{
		"Action":                   {"DeleteOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
	})
	requireIAMError(t, deleteAgain, http.StatusNotFound, "Sender", "NoSuchEntity",
		"OpenId connect Provider "+wantArn+" cannot be found.")

	missing := doIAMAction(t, server, url.Values{
		"Action":                   {"GetOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {wantArn},
	})
	requireIAMError(t, missing, http.StatusNotFound, "Sender", "NoSuchEntity",
		"OpenIDConnect Provider not found for arn "+wantArn)
}

func TestIAMApiControllerCreateOIDCProviderValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		params  url.Values
		status  int
		code    string
		message string
	}{
		{
			name:    "missing url",
			params:  url.Values{"Action": {"CreateOpenIDConnectProvider"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'url' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "no scheme at all",
			params: url.Values{
				"Action": {"CreateOpenIDConnectProvider"},
				"Url":    {"example.com"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "Invalid Open ID Connect Provider URL",
		},
		{
			name: "wrong scheme",
			params: url.Values{
				"Action": {"CreateOpenIDConnectProvider"},
				"Url":    {"http://example.com"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Invalid Open ID Connect Provider URL. The URL must begin with https://.",
		},
		{
			name: "query params",
			params: url.Values{
				"Action": {"CreateOpenIDConnectProvider"},
				"Url":    {"https://example.com?foo=1"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Invalid Open ID Connect Provider URL.",
		},
		{
			name: "explicit port",
			params: url.Values{
				"Action": {"CreateOpenIDConnectProvider"},
				"Url":    {"https://example.com:8443"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Invalid Open ID Connect Provider URL.",
		},
		{
			name: "url too long",
			params: url.Values{
				"Action": {"CreateOpenIDConnectProvider"},
				"Url":    {"https://" + strings.Repeat("a", 250) + ".com"},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'url' failed to satisfy constraint: Member must have length less than or equal to 255",
		},
		{
			name: "client id too long",
			params: url.Values{
				"Action":                {"CreateOpenIDConnectProvider"},
				"Url":                   {"https://example.com"},
				"ClientIDList.member.1": {strings.Repeat("c", 256)},
			},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'clientID' failed to satisfy constraint: Member must have length less than or equal to 255",
		},
		{
			name: "thumbprint wrong length",
			params: url.Values{
				"Action":                  {"CreateOpenIDConnectProvider"},
				"Url":                     {"https://example.com"},
				"ThumbprintList.member.1": {strings.Repeat("a", 39)},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Thumbprint must be exactly 40 characters.",
		},
		{
			name: "thumbprint too many",
			params: url.Values{
				"Action":                  {"CreateOpenIDConnectProvider"},
				"Url":                     {"https://example.com"},
				"ThumbprintList.member.1": {strings.Repeat("1", 40)},
				"ThumbprintList.member.2": {strings.Repeat("2", 40)},
				"ThumbprintList.member.3": {strings.Repeat("3", 40)},
				"ThumbprintList.member.4": {strings.Repeat("4", 40)},
				"ThumbprintList.member.5": {strings.Repeat("5", 40)},
				"ThumbprintList.member.6": {strings.Repeat("6", 40)},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Thumbprint list must contain fewer than 5 entries.",
		},
		{
			// Provider tag keys are compared exactly, so only a
			// byte-identical repeat is a duplicate.
			name: "duplicate tag keys",
			params: url.Values{
				"Action":                  {"CreateOpenIDConnectProvider"},
				"Url":                     {"https://example.com"},
				"ThumbprintList.member.1": {strings.Repeat("a", 40)},
				"Tags.member.1.Key":       {"key"},
				"Tags.member.1.Value":     {"one"},
				"Tags.member.2.Key":       {"key"},
				"Tags.member.2.Value":     {"two"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Duplicate tag keys found.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

// TestIAMApiControllerOIDCProviderTagLifecycle covers the provider tagging
// actions' distinguishing trait: tag keys are compared exactly, so "env"
// and "ENV" are two independent tags rather than one.
func TestIAMApiControllerOIDCProviderTagLifecycle(t *testing.T) {
	server := newIAMControllerTestServer(t)
	arn := createTestOIDCProviderForTrust(t, server, "https://tags.example.com", "")

	if got := listOIDCProviderTags(t, server, arn); len(got.Tags.Members) != 0 || got.IsTruncated {
		t.Fatalf("ListOpenIDConnectProviderTags on a fresh provider = %#v, want no tags", got)
	}

	tagOIDCProvider(t, server, arn, map[string]string{"env": "prod", "team": "storage", "empty": ""})

	got := listOIDCProviderTags(t, server, arn)
	// Sorted by key, regardless of the order they were added in.
	want := []iamtypes.Tag{{Key: "empty", Value: ""}, {Key: "env", Value: "prod"}, {Key: "team", Value: "storage"}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags = %#v, want %#v", got.Tags.Members, want)
	}

	// A repeated key replaces its value in place; a differently-cased key
	// is a different tag and is added alongside.
	tagOIDCProvider(t, server, arn, map[string]string{"env": "staging"})
	tagOIDCProvider(t, server, arn, map[string]string{"TEAM": "compute"})

	got = listOIDCProviderTags(t, server, arn)
	want = []iamtypes.Tag{
		{Key: "TEAM", Value: "compute"},
		{Key: "empty", Value: ""},
		{Key: "env", Value: "staging"},
		{Key: "team", Value: "storage"},
	}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags after overwrite = %#v, want %#v", got.Tags.Members, want)
	}

	// GetOpenIDConnectProvider reports the same tags the tag actions maintain.
	get := doIAMAction(t, server, url.Values{"Action": {"GetOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}})
	var getOut iamtypes.GetOpenIDConnectProviderResponse
	unmarshalXML(t, readBody(t, get), &getOut)
	if len(getOut.Result.Tags) != 4 {
		t.Fatalf("GetOpenIDConnectProvider Tags = %#v, want 4 tags", getOut.Result.Tags)
	}

	// Removal matches keys exactly, and a key naming no tag is not an error.
	untag := doIAMAction(t, server, url.Values{
		"Action":                   {"UntagOpenIDConnectProvider"},
		"OpenIDConnectProviderArn": {arn},
		"TagKeys.member.1":         {"team"},
		"TagKeys.member.2":         {"EnV"},
		"TagKeys.member.3":         {"never-existed"},
	})
	if untag.StatusCode != http.StatusOK {
		t.Fatalf("UntagOpenIDConnectProvider status = %d, body=%s", untag.StatusCode, readBody(t, untag))
	}

	got = listOIDCProviderTags(t, server, arn)
	want = []iamtypes.Tag{{Key: "TEAM", Value: "compute"}, {Key: "empty", Value: ""}, {Key: "env", Value: "staging"}}
	if !slices.Equal(got.Tags.Members, want) {
		t.Fatalf("Tags after untag = %#v, want %#v", got.Tags.Members, want)
	}
}

// TestIAMApiControllerOIDCProviderTagsIndependentPerProvider covers two
// providers carrying the same tag keys: each set is its own.
func TestIAMApiControllerOIDCProviderTagsIndependentPerProvider(t *testing.T) {
	server := newIAMControllerTestServer(t)
	first := createTestOIDCProviderForTrust(t, server, "https://first.example.com", "")
	second := createTestOIDCProviderForTrust(t, server, "https://second.example.com", "")

	tagOIDCProvider(t, server, first, map[string]string{"owner": "first"})
	tagOIDCProvider(t, server, second, map[string]string{"owner": "second"})

	untag := doIAMAction(t, server, url.Values{
		"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {first}, "TagKeys.member.1": {"owner"},
	})
	if untag.StatusCode != http.StatusOK {
		t.Fatalf("UntagOpenIDConnectProvider status = %d, body=%s", untag.StatusCode, readBody(t, untag))
	}

	if got := listOIDCProviderTags(t, server, first).Tags.Members; len(got) != 0 {
		t.Fatalf("first provider tags after untag = %#v, want none", got)
	}
	if got := listOIDCProviderTags(t, server, second).Tags.Members; !slices.Equal(got, []iamtypes.Tag{{Key: "owner", Value: "second"}}) {
		t.Fatalf("second provider tags = %#v", got)
	}
}

func TestIAMApiControllerListOIDCProviderTagsPagination(t *testing.T) {
	server := newIAMControllerTestServer(t)
	arn := createTestOIDCProviderForTrust(t, server, "https://paged.example.com", "")
	tagOIDCProvider(t, server, arn, map[string]string{"a": "1", "b": "2", "c": "3"})

	var seen []iamtypes.Tag
	marker := ""
	for page := 1; ; page++ {
		params := url.Values{
			"Action":                   {"ListOpenIDConnectProviderTags"},
			"OpenIDConnectProviderArn": {arn},
			"MaxItems":                 {"1"},
		}
		if marker != "" {
			params.Set("Marker", marker)
		}
		resp := doIAMAction(t, server, params)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ListOpenIDConnectProviderTags status = %d, body=%s", resp.StatusCode, readBody(t, resp))
		}
		var out struct {
			Result iamtypes.ListOpenIDConnectProviderTagsResult `xml:"ListOpenIDConnectProviderTagsResult"`
		}
		unmarshalXML(t, readBody(t, resp), &out)

		if len(out.Result.Tags.Members) != 1 {
			t.Fatalf("page %d holds %d tags, want 1", page, len(out.Result.Tags.Members))
		}
		seen = append(seen, out.Result.Tags.Members...)
		if !out.Result.IsTruncated {
			if out.Result.Marker != "" {
				t.Fatalf("final page Marker = %q, want empty", out.Result.Marker)
			}
			break
		}
		marker = out.Result.Marker
	}

	want := []iamtypes.Tag{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}, {Key: "c", Value: "3"}}
	if !slices.Equal(seen, want) {
		t.Fatalf("paged tags = %#v, want %#v", seen, want)
	}
}

func TestIAMApiControllerTagOIDCProviderExceedsQuota(t *testing.T) {
	server := newIAMControllerTestServer(t)
	arn := createTestOIDCProviderForTrust(t, server, "https://quota.example.com", "")

	atQuota := url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}}
	for i := 1; i <= storage.MaxTagsPerResource; i++ {
		atQuota.Set(fmt.Sprintf("Tags.member.%d.Key", i), fmt.Sprintf("k%d", i))
		atQuota.Set(fmt.Sprintf("Tags.member.%d.Value", i), fmt.Sprintf("v%d", i))
	}
	if resp := doIAMAction(t, server, atQuota); resp.StatusCode != http.StatusOK {
		t.Fatalf("TagOpenIDConnectProvider with %d tags status = %d, body=%s", storage.MaxTagsPerResource, resp.StatusCode, readBody(t, resp))
	}

	// Replacing an existing key at the quota is fine: the total doesn't grow.
	replace := doIAMAction(t, server, url.Values{
		"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn},
		"Tags.member.1.Key": {"k1"}, "Tags.member.1.Value": {"replaced"},
	})
	if replace.StatusCode != http.StatusOK {
		t.Fatalf("TagOpenIDConnectProvider replacing at quota status = %d, body=%s", replace.StatusCode, readBody(t, replace))
	}

	// A differently-cased key is a new tag, so it overflows the quota.
	overflow := doIAMAction(t, server, url.Values{
		"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn},
		"Tags.member.1.Key": {"K1"}, "Tags.member.1.Value": {"x"},
	})
	requireIAMError(t, overflow, http.StatusConflict, "Sender", "LimitExceeded", "The number of tags has reached the maximum limit.")
}

func TestIAMApiControllerOIDCProviderTagValidationErrors(t *testing.T) {
	const arn = "arn:aws:iam::000000000000:oidc-provider/tags.example.com"

	tooManyTags := url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}}
	for i := 1; i <= iamutil.MaxTagMembersPerRequest+1; i++ {
		tooManyTags.Set(fmt.Sprintf("Tags.member.%d.Key", i), fmt.Sprintf("k%d", i))
		tooManyTags.Set(fmt.Sprintf("Tags.member.%d.Value", i), fmt.Sprintf("v%d", i))
	}
	tooManyTagKeys := url.Values{"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}}
	for i := 1; i <= iamutil.MaxTagMembersPerRequest+1; i++ {
		tooManyTagKeys.Set(fmt.Sprintf("TagKeys.member.%d", i), fmt.Sprintf("k%d", i))
	}

	const missingArn = "arn:aws:iam::000000000000:oidc-provider/nosuch.example.com"
	const notFoundMessage = "OpenId connect Provider " + missingArn + " cannot be found."

	tests := []struct {
		name          string
		setupProvider bool
		params        url.Values
		status        int
		code          string
		message       string
	}{
		{
			name:    "tag missing arn",
			params:  url.Values{"Action": {"TagOpenIDConnectProvider"}, "Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'openIDConnectProviderArn' failed to satisfy constraint: Member must not be null",
		},
		{
			name:    "tag arn too short",
			params:  url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {"arn:aws:iam::1"}, "Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'openIDConnectProviderArn' failed to satisfy constraint: Member must have length greater than or equal to 20",
		},
		{
			name:    "tag wrong resource type in arn",
			params:  url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {"arn:aws:iam::000000000000:user/alice"}, "Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "Invalid resource type in ARN",
		},
		{
			name:          "tag missing tags",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must not be null",
		},
		{
			name:          "tag missing key",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Value": {"prod"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must not be null",
		},
		{
			name:          "tag missing value",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Key": {"env"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must not be null",
		},
		{
			name:          "tag empty key",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Key": {""}, "Tags.member.1.Value": {"prod"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length greater than or equal to 1",
		},
		{
			name:          "tag key too long",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Key": {strings.Repeat("k", 129)}, "Tags.member.1.Value": {"v"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128",
		},
		{
			name:          "tag invalid key characters",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Key": {"bad*key"}, "Tags.member.1.Value": {"v"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+",
		},
		{
			name:          "tag value too long",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {strings.Repeat("v", 257)}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256",
		},
		{
			name:          "tag invalid value characters",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"bad*value"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*",
		},
		{
			name:          "tag duplicate keys",
			setupProvider: true,
			params: url.Values{
				"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn},
				"Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"},
				"Tags.member.2.Key": {"env"}, "Tags.member.2.Value": {"staging"},
			},
			status:  http.StatusBadRequest,
			code:    "InvalidInput",
			message: "Duplicate tag keys found.",
		},
		{
			name:          "tag too many tags",
			setupProvider: true,
			params:        tooManyTags,
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50",
		},
		{
			name:          "tag invalid tag on non existing provider",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {missingArn}, "Tags.member.1.Key": {"bad*key"}, "Tags.member.1.Value": {"v"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+",
		},
		{
			name:          "tag non existing provider",
			setupProvider: true,
			params:        url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {missingArn}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}},
			status:        http.StatusNotFound,
			code:          "NoSuchEntity",
			message:       notFoundMessage,
		},
		{
			name:    "untag missing arn",
			params:  url.Values{"Action": {"UntagOpenIDConnectProvider"}, "TagKeys.member.1": {"env"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'openIDConnectProviderArn' failed to satisfy constraint: Member must not be null",
		},
		{
			name:          "untag missing tag keys",
			setupProvider: true,
			params:        url.Values{"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must not be null",
		},
		{
			name:          "untag empty tag key",
			setupProvider: true,
			params:        url.Values{"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "TagKeys.member.1": {""}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       invalidTagKeysMessage,
		},
		{
			name:          "untag tag key too long",
			setupProvider: true,
			params:        url.Values{"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "TagKeys.member.1": {strings.Repeat("k", 129)}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       invalidTagKeysMessage,
		},
		{
			name:          "untag invalid tag key",
			setupProvider: true,
			params:        url.Values{"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}, "TagKeys.member.1": {"bad*key"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       invalidTagKeysMessage,
		},
		{
			name:          "untag too many tag keys",
			setupProvider: true,
			params:        tooManyTagKeys,
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to 50",
		},
		{
			name:          "untag non existing provider",
			setupProvider: true,
			params:        url.Values{"Action": {"UntagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {missingArn}, "TagKeys.member.1": {"env"}},
			status:        http.StatusNotFound,
			code:          "NoSuchEntity",
			message:       notFoundMessage,
		},
		{
			name:    "list missing arn",
			params:  url.Values{"Action": {"ListOpenIDConnectProviderTags"}},
			status:  http.StatusBadRequest,
			code:    "ValidationError",
			message: "1 validation error detected: Value at 'openIDConnectProviderArn' failed to satisfy constraint: Member must not be null",
		},
		{
			name:          "list max items too low",
			setupProvider: true,
			params:        url.Values{"Action": {"ListOpenIDConnectProviderTags"}, "OpenIDConnectProviderArn": {arn}, "MaxItems": {"0"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
		},
		{
			name:          "list max items too high",
			setupProvider: true,
			params:        url.Values{"Action": {"ListOpenIDConnectProviderTags"}, "OpenIDConnectProviderArn": {arn}, "MaxItems": {"1001"}},
			status:        http.StatusBadRequest,
			code:          "ValidationError",
			message:       "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
		},
		{
			name:          "list max items not a number",
			setupProvider: true,
			params:        url.Values{"Action": {"ListOpenIDConnectProviderTags"}, "OpenIDConnectProviderArn": {arn}, "MaxItems": {"abc"}},
			status:        http.StatusBadRequest,
			code:          "MalformedInput",
			message:       "",
		},
		{
			name:          "list non existing provider",
			setupProvider: true,
			params:        url.Values{"Action": {"ListOpenIDConnectProviderTags"}, "OpenIDConnectProviderArn": {missingArn}},
			status:        http.StatusNotFound,
			code:          "NoSuchEntity",
			message:       notFoundMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			if tt.setupProvider {
				createTestOIDCProviderForTrust(t, server, "https://tags.example.com", "")
			}
			resp := doIAMAction(t, server, tt.params)
			requireIAMError(t, resp, tt.status, "Sender", tt.code, tt.message)
		})
	}
}

func tagOIDCProvider(t *testing.T, server *IAMApiServer, arn string, tags map[string]string) {
	t.Helper()

	params := url.Values{"Action": {"TagOpenIDConnectProvider"}, "OpenIDConnectProviderArn": {arn}}
	i := 1
	for key, value := range tags {
		params.Set(fmt.Sprintf("Tags.member.%d.Key", i), key)
		params.Set(fmt.Sprintf("Tags.member.%d.Value", i), value)
		i++
	}

	resp := doIAMAction(t, server, params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TagOpenIDConnectProvider status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func listOIDCProviderTags(t *testing.T, server *IAMApiServer, arn string) iamtypes.ListOpenIDConnectProviderTagsResult {
	t.Helper()

	resp := doIAMAction(t, server, url.Values{
		"Action":                   {"ListOpenIDConnectProviderTags"},
		"OpenIDConnectProviderArn": {arn},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListOpenIDConnectProviderTags status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out struct {
		Result iamtypes.ListOpenIDConnectProviderTagsResult `xml:"ListOpenIDConnectProviderTagsResult"`
	}
	unmarshalXML(t, readBody(t, resp), &out)
	return out.Result
}

func TestIAMApiControllerOIDCThumbprintAutoFetchDisabled(t *testing.T) {
	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	server, err := New(store, testRoot, WithQuiet(), WithOIDCThumbprintAutoFetchDisabled())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp := doIAMAction(t, server, url.Values{
		"Action": {"CreateOpenIDConnectProvider"},
		"Url":    {"https://example.com"},
	})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
		"1 validation error detected: Value at 'thumbprintList' failed to satisfy constraint: Member must not be null")
}

// TestIAMApiControllerCreateOIDCProviderAutoFetchSSRFGuard confirms the
// auto-fetch fallback's SSRF guard is wired all the way through the HTTP
// action handler: an omitted ThumbprintList against a loopback URL must be
// rejected before any real network attempt, deterministically and without
// requiring outbound network access from the test environment.
func TestIAMApiControllerCreateOIDCProviderAutoFetchSSRFGuard(t *testing.T) {
	server := newIAMControllerTestServer(t)

	resp := doIAMAction(t, server, url.Values{
		"Action": {"CreateOpenIDConnectProvider"},
		"Url":    {"https://127.0.0.1"},
	})
	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "OpenIdIdpCommunicationError",
		"Could not connect to https://127.0.0.1")
}

// accessKeyImplicitUserNameActions are the four access-key actions that
// accept an omitted UserName and infer it from the calling access key.
var accessKeyImplicitUserNameActions = []string{"CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey", "ListAccessKeys"}

// accessKeyActionParams builds a request for action carrying every
// parameter but UserName, so a test can exercise the omitted-UserName path
// without each case repeating the action's other required parameters.
func accessKeyActionParams(action string) url.Values {
	params := url.Values{"Action": {action}}
	switch action {
	case "UpdateAccessKey":
		params.Set("AccessKeyId", "AKIAIOSFODNN7EXAMPLE")
		params.Set("Status", "Inactive")
	case "DeleteAccessKey":
		params.Set("AccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	}
	return params
}

func newIAMControllerTestServer(t *testing.T) *IAMApiServer {
	t.Helper()

	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	server, err := New(store, testRoot, WithQuiet())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server
}

func doIAMAction(t *testing.T, server *IAMApiServer, params url.Values) *http.Response {
	t.Helper()
	if !params.Has("Version") {
		params.Set("Version", iamAPIVersion)
	}

	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?"+params.Encode(), nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// doIAMActionPost signs and sends params as a POST form body rather than a
// GET query string, for requests too large to fit a GET request's
// header/URL buffer (e.g. an oversized PolicyDocument).
func doIAMActionPost(t *testing.T, server *IAMApiServer, params url.Values) *http.Response {
	t.Helper()
	if !params.Has("Version") {
		params.Set("Version", iamAPIVersion)
	}

	req := signedIAMRequest(t, http.MethodPost, "http://example.com/", []byte(params.Encode()), testRoot.Secret)
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

func unmarshalXML(t *testing.T, body string, out any) {
	t.Helper()

	if err := xml.Unmarshal([]byte(body), out); err != nil {
		t.Fatalf("unmarshal XML: %v\n%s", err, body)
	}
}

func requireUserTags(t *testing.T, tags []iamtypes.Tag) {
	t.Helper()

	if len(tags) != 2 || tags[0].Key != "env" || tags[0].Value != "test" ||
		tags[1].Key != "empty" || tags[1].Value != "" {
		t.Fatalf("Tags = %#v, want env=test and empty=", tags)
	}
}

// requireSTSError is requireIAMError's counterpart for the two STS actions:
// their errors render under STS's namespace instead of IAM's, except
// InvalidAction (a request whose Version doesn't resolve to any known
// action, so there's no specific service to attribute the fault to yet),
// which always uses the generic AWS fault namespace.
func requireSTSError(t *testing.T, resp *http.Response, status int, errType, code, message string) {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, status, body)
	}

	var errResp struct {
		XMLName xml.Name `xml:"ErrorResponse"`
		Error   struct {
			Type    string
			Code    string
			Message string
		}
		RequestID string `xml:"RequestId"`
	}
	if err := xml.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("unmarshal STS error: %v\n%s", err, body)
	}

	wantNamespace := iamerr.STSNamespace
	if code == "InvalidAction" {
		wantNamespace = iamerr.AWSFaultNamespace
	}
	if errResp.XMLName.Space != wantNamespace {
		t.Fatalf("namespace = %q, want %q", errResp.XMLName.Space, wantNamespace)
	}
	if errResp.Error.Type != errType || errResp.Error.Code != code || errResp.Error.Message != message {
		t.Fatalf("error = %#v, want type=%q code=%q message=%q", errResp.Error, errType, code, message)
	}
	if errResp.RequestID == "" {
		t.Fatal("missing RequestId")
	}
}

// doSTSAction sends params as an unsigned POST request — every one of
// these tests either exercises AssumeRoleWithWebIdentity (which requires no
// credentials at all) or deliberately omits auth to check the resulting
// error, so signing is opt-in via signedSTSRequest instead of the default.
func doSTSAction(t *testing.T, server *IAMApiServer, params url.Values) *http.Response {
	t.Helper()
	if !params.Has("Version") {
		params.Set("Version", stsAPIVersion)
	}

	body := []byte(params.Encode())
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", bytes.NewReader(body))
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// signedSTSRequest builds an STS-style request (Credential scoped to
// "sts", matching a real STS SDK client) signed with the given
// credentials, optionally carrying an X-Amz-Security-Token header for
// temporary credentials.
func signedSTSRequest(t *testing.T, access, secret, sessionToken string, params url.Values) *http.Request {
	t.Helper()
	if !params.Has("Version") {
		params.Set("Version", stsAPIVersion)
	}

	body := []byte(params.Encode())
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", bytes.NewReader(body))
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)

	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])

	creds := aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: sessionToken}
	signer := awsv4.NewSigner()
	if err := signer.SignHTTP(context.Background(), creds, req, payloadHash, "sts", iammiddleware.SigningRegion, time.Now().UTC()); err != nil {
		t.Fatalf("sign sts request: %v", err)
	}
	return req
}

func doSignedSTSAction(t *testing.T, server *IAMApiServer, access, secret, sessionToken string, params url.Values) *http.Response {
	t.Helper()
	req := signedSTSRequest(t, access, secret, sessionToken, params)
	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// validWebIdentityToken is a structurally valid (but unverifiable — no
// registered provider will ever match its issuer) JWT carrying every claim
// AWS requires (including iat — its absence would itself be a rejection
// reason, see VerifyWebIdentityRequiredClaims), sufficient for exercising
// every AssumeRoleWithWebIdentity validation step that runs before the
// network call to fetch a provider's signing keys.
const validWebIdentityToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJpc3MiOiJodHRwczovL3VucmVnaXN0ZXJlZC5leGFtcGxlLmNvbSIsImF1ZCI6ImNsaWVudDEiLCJzdWIiOiJ1c2VyMSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ." +
	"c2lnbmF0dXJl"

func TestIAMApiControllerAssumeRoleWithWebIdentityRequiresNoAuth(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// A completely unsigned request (no Authorization header, no query
	// auth params at all) must still reach business logic rather than
	// being rejected for missing credentials — the entire point of this
	// action is that no AWS credentials are required.
	resp := doSTSAction(t, server, url.Values{"Action": {"AssumeRoleWithWebIdentity"}})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
		"1 validation error detected: Value at 'roleArn' failed to satisfy constraint: Member must not be null")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityValidationErrors(t *testing.T) {
	server := newIAMControllerTestServer(t)
	const roleArn = "arn:aws:iam::000000000000:role/does-not-exist"

	tests := []struct {
		name        string
		params      url.Values
		wantStatus  int
		wantErrType string
		wantCode    string
		wantMessage string
	}{
		{
			name:        "missing RoleSessionName",
			params:      url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn}, "WebIdentityToken": {validWebIdentityToken}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleSessionName' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "invalid RoleSessionName characters",
			params: url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn},
				"RoleSessionName": {"bad session!!"}, "WebIdentityToken": {validWebIdentityToken}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value 'bad session!!' at 'roleSessionName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*",
		},
		{
			name:        "missing WebIdentityToken",
			params:      url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn}, "RoleSessionName": {"session1"}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'webIdentityToken' failed to satisfy constraint: Member must not be null",
		},
		{
			name: "malformed (non-JWT) token",
			params: url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn},
				"RoleSessionName": {"session1"}, "WebIdentityToken": {"not-a-real-jwt-token"}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "InvalidIdentityToken",
			wantMessage: "The ID Token provided is not a valid JWT. (You may see this error if you sent an Access Token)",
		},
		{
			name: "duration too low",
			params: url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn},
				"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}, "DurationSeconds": {"100"}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value '100' at 'durationSeconds' failed to satisfy constraint: Member must have value greater than or equal to 900",
		},
		{
			name: "duration too high",
			params: url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn},
				"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}, "DurationSeconds": {"50000"}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value '50000' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200",
		},
		{
			name:        "RoleArn too short",
			params:      url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"short"}, "RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleArn' failed to satisfy constraint: Member must have length greater than or equal to 20",
		},
		{
			name:        "RoleArn too long",
			params:      url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn + strings.Repeat("a", 2048)}, "RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'roleArn' failed to satisfy constraint: Member must have length less than or equal to 2048",
		},
		{
			name:        "WebIdentityToken too short",
			params:      url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn}, "RoleSessionName": {"session1"}, "WebIdentityToken": {"ab"}},
			wantStatus:  http.StatusBadRequest,
			wantErrType: "Sender",
			wantCode:    "ValidationError",
			wantMessage: "1 validation error detected: Value at 'webIdentityToken' failed to satisfy constraint: Member must have length greater than or equal to 4",
		},
		{
			name:        "nonexistent role",
			params:      url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {roleArn}, "RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}},
			wantStatus:  http.StatusForbidden,
			wantErrType: "Sender",
			wantCode:    "AccessDenied",
			wantMessage: "Not authorized to perform sts:AssumeRoleWithWebIdentity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := doSTSAction(t, server, tt.params)
			requireSTSError(t, resp, tt.wantStatus, tt.wantErrType, tt.wantCode, tt.wantMessage)
		})
	}
}

func TestIAMApiControllerAssumeRoleWithWebIdentityErrorsUseSTSNamespace(t *testing.T) {
	server := newIAMControllerTestServer(t)
	resp := doSTSAction(t, server, url.Values{"Action": {"AssumeRoleWithWebIdentity"}})
	body := readBody(t, resp)
	if !strings.Contains(body, `xmlns="https://sts.amazonaws.com/doc/2011-06-15/"`) {
		t.Fatalf("error response missing STS namespace: %s", body)
	}
}

func TestIAMApiControllerAssumeRoleWithWebIdentityDurationExceedsRoleMax(t *testing.T) {
	server := newIAMControllerTestServer(t)

	createResp := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"my-role"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/example.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`},
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", createResp.StatusCode, readBody(t, createResp))
	}

	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/my-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {validWebIdentityToken},
		"DurationSeconds":  {"7200"}, // role's default MaxSessionDuration is 3600
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "ValidationError",
		"The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityNoMatchingPrincipal(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// The trust policy's Federated principal never corresponds to a real,
	// registered OIDC provider (it was never created) — this is reported
	// identically to a nonexistent role, never confirming or denying
	// whether the role itself exists.
	createResp := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"dangling-trust-role"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/never-created.example.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`},
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", createResp.StatusCode, readBody(t, createResp))
	}

	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/dangling-trust-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {validWebIdentityToken},
	})
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityRejectsUnsupportedParams(t *testing.T) {
	tests := []struct {
		name      string
		wantParam string // the parameter name UnsupportedParameter's message names; defaults to name if empty
		params    url.Values
	}{
		{
			name: "PolicyArns",
			params: url.Values{
				"Action":                  {"AssumeRoleWithWebIdentity"},
				"RoleArn":                 {"arn:aws:iam::000000000000:role/does-not-exist"},
				"RoleSessionName":         {"session1"},
				"WebIdentityToken":        {validWebIdentityToken},
				"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:policy/some-policy"},
			},
		},
		{
			name:      "PolicyArns member 2",
			wantParam: "PolicyArns",
			params: url.Values{
				"Action":                  {"AssumeRoleWithWebIdentity"},
				"RoleArn":                 {"arn:aws:iam::000000000000:role/does-not-exist"},
				"RoleSessionName":         {"session1"},
				"WebIdentityToken":        {validWebIdentityToken},
				"PolicyArns.member.2.arn": {"arn:aws:iam::000000000000:policy/some-policy"},
			},
		},
		{
			name:      "PolicyArns member 10",
			wantParam: "PolicyArns",
			params: url.Values{
				"Action":                   {"AssumeRoleWithWebIdentity"},
				"RoleArn":                  {"arn:aws:iam::000000000000:role/does-not-exist"},
				"RoleSessionName":          {"session1"},
				"WebIdentityToken":         {validWebIdentityToken},
				"PolicyArns.member.10.arn": {"arn:aws:iam::000000000000:policy/some-policy"},
			},
		},
		{
			name:      "PolicyArns with an index gap (member 3 only, no 1 or 2)",
			wantParam: "PolicyArns",
			params: url.Values{
				"Action":                  {"AssumeRoleWithWebIdentity"},
				"RoleArn":                 {"arn:aws:iam::000000000000:role/does-not-exist"},
				"RoleSessionName":         {"session1"},
				"WebIdentityToken":        {validWebIdentityToken},
				"PolicyArns.member.3.arn": {"arn:aws:iam::000000000000:policy/some-policy"},
			},
		},
		{
			name:      "PolicyArns empty-but-present value",
			wantParam: "PolicyArns",
			params: url.Values{
				"Action":                  {"AssumeRoleWithWebIdentity"},
				"RoleArn":                 {"arn:aws:iam::000000000000:role/does-not-exist"},
				"RoleSessionName":         {"session1"},
				"WebIdentityToken":        {validWebIdentityToken},
				"PolicyArns.member.1.arn": {""},
			},
		},
		{
			name: "ProviderId",
			params: url.Values{
				"Action":           {"AssumeRoleWithWebIdentity"},
				"RoleArn":          {"arn:aws:iam::000000000000:role/does-not-exist"},
				"RoleSessionName":  {"session1"},
				"WebIdentityToken": {validWebIdentityToken},
				"ProviderId":       {"www.amazon.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newIAMControllerTestServer(t)
			resp := doSTSAction(t, server, tt.params)
			wantParam := tt.wantParam
			if wantParam == "" {
				wantParam = tt.name
			}
			requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidInput", wantParam+" is not supported by this implementation.")
		})
	}
}

func TestIAMApiControllerAssumeRoleWithWebIdentityRejectsPolicyArnsInQueryString(t *testing.T) {
	server := newIAMControllerTestServer(t)

	params := url.Values{
		"Action":                  {"AssumeRoleWithWebIdentity"},
		"Version":                 {stsAPIVersion},
		"RoleArn":                 {"arn:aws:iam::000000000000:role/does-not-exist"},
		"RoleSessionName":         {"session1"},
		"WebIdentityToken":        {validWebIdentityToken},
		"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:policy/some-policy"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/?"+params.Encode(), nil)
	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidInput", "PolicyArns is not supported by this implementation.")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityRoleArnPathMismatch(t *testing.T) {
	server := newIAMControllerTestServer(t)

	createResp := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {"path-role"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/never-created.example.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`},
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", createResp.StatusCode, readBody(t, createResp))
	}

	// "path-role" was created with the default "/" path, so its real Arn is
	// arn:...:role/path-role — not arn:...:role/some/path/path-role. Only
	// the role name matched; the full ARN (path included) must not.
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/some/path/path-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {validWebIdentityToken},
	})
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")
}

// webIdentityTokenWithClaims builds an unverified (but structurally valid)
// JWT carrying claims — sufficient for every AssumeRoleWithWebIdentity trust
// evaluation test below, since none of them ever reach real signature
// verification (a trust-policy mismatch, audience mismatch, or condition
// failure is always detected first).
func webIdentityTokenWithClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2lnbmF0dXJl"
}

// createTestOIDCProviderForTrust creates a real, registered OIDC provider at
// url (scheme included) with clientIDs, returning its ARN for use as a role
// trust policy's Federated principal.
func createTestOIDCProviderForTrust(t *testing.T, server *IAMApiServer, url_, clientID string) string {
	t.Helper()
	params := url.Values{
		"Action":                  {"CreateOpenIDConnectProvider"},
		"Url":                     {url_},
		"ThumbprintList.member.1": {"6938fd4d98bab03faadb97b34396831e3780aea1"},
	}
	if clientID != "" {
		params.Set("ClientIDList.member.1", clientID)
	}
	resp := doIAMAction(t, server, params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateOpenIDConnectProvider status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out iamtypes.CreateOpenIDConnectProviderResponse
	unmarshalXML(t, readBody(t, resp), &out)
	return out.Result.OpenIDConnectProviderArn
}

func createTestRoleForTrust(t *testing.T, server *IAMApiServer, roleName, trustPolicy string) {
	t.Helper()
	resp := doIAMAction(t, server, url.Values{
		"Action":                   {"CreateRole"},
		"RoleName":                 {roleName},
		"AssumeRolePolicyDocument": {trustPolicy},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}
}

func TestIAMApiControllerAssumeRoleWithWebIdentityNoIssuerMatch(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// The trust policy's Federated principal resolves to a real, registered
	// provider — but that provider's own Url doesn't match the token's iss
	// claim. Unlike NoPrincipal (no such provider at all), this is reported
	// as InvalidIdentityToken, confirming the role's existence is no longer
	// masked once its trust policy references at least one real provider.
	providerArn := createTestOIDCProviderForTrust(t, server, "https://registered.example.com", "client1")
	createTestRoleForTrust(t, server, "no-issuer-match-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)

	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://different-issuer.example.com", "aud": "client1", "sub": "user1", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/no-issuer-match-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidIdentityToken",
		"The web identity token provided could not be validated. See the AssumeRoleWithWebIdentity documentation for requirements.")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityConditionFailed(t *testing.T) {
	server := newIAMControllerTestServer(t)

	providerArn := createTestOIDCProviderForTrust(t, server, "https://cond.example.com", "client1")
	createTestRoleForTrust(t, server, "condition-failed-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"cond.example.com:sub":"expected-user"}}}]}`)

	// Provider matches (iss == cond.example.com) but sub doesn't satisfy the
	// trust statement's Condition block.
	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://cond.example.com", "aud": "client1", "sub": "someone-else", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/condition-failed-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidIdentityToken",
		"The web identity token provided could not be validated. See the AssumeRoleWithWebIdentity documentation for requirements.")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityExplicitDeny(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// A broad Allow is present, but a Deny statement matching the same
	// provider/action/condition takes precedence — reported as AccessDenied,
	// identically to a role that doesn't authorize the caller at all, never
	// as InvalidIdentityToken (Deny is a distinct outcome from a mismatched
	// condition on an Allow).
	providerArn := createTestOIDCProviderForTrust(t, server, "https://deny.example.com", "client1")
	createTestRoleForTrust(t, server, "explicit-deny-role",
		`{"Version":"2012-10-17","Statement":[`+
			`{"Effect":"Allow","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity"},`+
			`{"Effect":"Deny","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"deny.example.com:sub":"blocked-user"}}}]}`)

	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://deny.example.com", "aud": "client1", "sub": "blocked-user", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/explicit-deny-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityAudienceNotInClientIDList(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// Trust evaluation passes (the provider matches iss, no Condition to
	// fail), but the token's audience isn't among the provider's own
	// ClientIDList — a distinct check, made only after trust evaluation
	// succeeds, that still reports the same InvalidIdentityToken as a
	// Condition failure would.
	providerArn := createTestOIDCProviderForTrust(t, server, "https://aud-mismatch.example.com", "allowed-client")
	createTestRoleForTrust(t, server, "audience-mismatch-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)

	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://aud-mismatch.example.com", "aud": "not-the-allowed-client", "sub": "user1", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/audience-mismatch-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidIdentityToken",
		"The web identity token provided could not be validated. See the AssumeRoleWithWebIdentity documentation for requirements.")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityEmptyClientIDList(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// A provider with no registered client IDs at all can never satisfy the
	// audience check, no matter what the token's aud claim is.
	providerArn := createTestOIDCProviderForTrust(t, server, "https://no-clients.example.com", "")
	createTestRoleForTrust(t, server, "empty-client-list-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)

	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://no-clients.example.com", "aud": "anything", "sub": "user1", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/empty-client-list-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidIdentityToken",
		"The web identity token provided could not be validated. See the AssumeRoleWithWebIdentity documentation for requirements.")
}

func TestIAMApiControllerAssumeRoleWithWebIdentityMultiplePrincipalsInArray(t *testing.T) {
	server := newIAMControllerTestServer(t)

	// A Federated principal can be a JSON array of ARNs, not just a bare
	// string — the token's issuer only needs to match one of them. Both
	// providers use loopback IP hosts (rather than DNS names) so that once
	// the flow reaches signature verification, the SSRF guard rejects the
	// dial immediately and deterministically instead of the test depending
	// on (and being slowed or flaked by) real DNS resolution.
	otherProviderArn := createTestOIDCProviderForTrust(t, server, "https://127.0.0.2", "client1")
	matchingProviderArn := createTestOIDCProviderForTrust(t, server, "https://127.0.0.3", "client1")
	createTestRoleForTrust(t, server, "multi-principal-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":["`+otherProviderArn+`","`+matchingProviderArn+`"]},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)

	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://127.0.0.3", "aud": "client1", "sub": "user1", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/multi-principal-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	// Passes trust evaluation and the audience check; fails only at the
	// network-dependent signature verification step — here it's enough to
	// confirm it gets that far rather than being rejected as
	// AccessDenied/InvalidIdentityToken.
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidIdentityToken",
		"Couldn't retrieve verification key from your identity provider,  please reference AssumeRoleWithWebIdentity documentation for requirements")
}

// TestIAMApiControllerAssumeRoleWithWebIdentityIDPCommunicationError confirms
// the network-dependent signature-verification step is wired all the way
// through the real HTTP action handler: a provider Url that's an IP literal
// in a private/loopback range is rejected by VerifyWebIdentitySignature's
// mandatory SSRF guard before any real network attempt, deterministically
// and without requiring outbound network access from the test environment —
// the same technique
// IAMCreateOpenIDConnectProvider_thumbprint_autofetch_communication_error
// uses for CreateOpenIDConnectProvider's auto-fetch path.
func TestIAMApiControllerAssumeRoleWithWebIdentityIDPCommunicationError(t *testing.T) {
	server := newIAMControllerTestServer(t)

	providerArn := createTestOIDCProviderForTrust(t, server, "https://127.0.0.1", "client1")
	createTestRoleForTrust(t, server, "idp-comm-error-role",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+providerArn+`"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)

	token := webIdentityTokenWithClaims(t, map[string]any{
		"iss": "https://127.0.0.1", "aud": "client1", "sub": "user1", "exp": 9999999999,
	})
	resp := doSTSAction(t, server, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:aws:iam::000000000000:role/idp-comm-error-role"},
		"RoleSessionName":  {"session1"},
		"WebIdentityToken": {token},
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidIdentityToken",
		"Couldn't retrieve verification key from your identity provider,  please reference AssumeRoleWithWebIdentity documentation for requirements")
}

func TestIAMApiControllerGetCallerIdentityRoot(t *testing.T) {
	server := newIAMControllerTestServer(t)

	resp := doSignedSTSAction(t, server, testRoot.Access, testRoot.Secret, "", url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	body := readBody(t, resp)
	var out iamtypes.GetCallerIdentityResponse
	unmarshalXML(t, body, &out)
	if out.Result.Arn != "arn:aws:iam::000000000000:root" {
		t.Fatalf("GetCallerIdentity root Arn = %q", out.Result.Arn)
	}
	if out.Result.UserId != "000000000000" || out.Result.Account != "000000000000" {
		t.Fatalf("GetCallerIdentity root UserId/Account = %q/%q", out.Result.UserId, out.Result.Account)
	}
	if !strings.Contains(body, `xmlns="https://sts.amazonaws.com/doc/2011-06-15/"`) {
		t.Fatalf("success response missing STS namespace: %s", body)
	}
}

func TestIAMApiControllerGetCallerIdentityNoAuth(t *testing.T) {
	server := newIAMControllerTestServer(t)
	resp := doSTSAction(t, server, url.Values{"Action": {"GetCallerIdentity"}})
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "MissingAuthenticationToken", "Request is missing Authentication Token")
}

func TestIAMApiControllerGetCallerIdentityWrongVersionIsInvalidAction(t *testing.T) {
	server := newIAMControllerTestServer(t)
	resp := doSignedSTSAction(t, server, testRoot.Access, testRoot.Secret, "", url.Values{
		"Action":  {"GetCallerIdentity"},
		"Version": {iamAPIVersion},
	})
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "InvalidAction", "Could not find operation GetCallerIdentity for version "+iamAPIVersion)
}

func TestIAMApiControllerGetCallerIdentityWithSession(t *testing.T) {
	server := newIAMControllerTestServer(t)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTSESSION1234567",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         "arn:aws:iam::000000000000:role/my-role",
		RoleName:        "my-role",
		RoleID:          "AROAtESTROLE123456789",
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	resp := doSignedSTSAction(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out iamtypes.GetCallerIdentityResponse
	unmarshalXML(t, readBody(t, resp), &out)
	if out.Result.Arn != "arn:aws:sts::000000000000:assumed-role/my-role/my-session" {
		t.Fatalf("GetCallerIdentity session Arn = %q", out.Result.Arn)
	}
	if out.Result.UserId != "AROAtESTROLE123456789:my-session" {
		t.Fatalf("GetCallerIdentity session UserId = %q", out.Result.UserId)
	}
	if out.Result.Account != "000000000000" {
		t.Fatalf("GetCallerIdentity session Account = %q", out.Result.Account)
	}
}

func TestIAMApiControllerGetCallerIdentityWithSessionWrongToken(t *testing.T) {
	server := newIAMControllerTestServer(t)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTSESSION7654321",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         "arn:aws:iam::000000000000:role/my-role",
		RoleName:        "my-role",
		RoleID:          "AROAtESTROLE123456789",
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Right access key and secret, but a security token that doesn't match
	// the stored session must still be rejected.
	resp := doSignedSTSAction(t, server, session.AccessKeyId, session.SecretAccessKey, "wrong-token",
		url.Values{"Action": {"GetCallerIdentity"}})
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
}

func TestIAMApiControllerGetCallerIdentityWithExpiredSession(t *testing.T) {
	server := newIAMControllerTestServer(t)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTEXPIRED1234567",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         "arn:aws:iam::000000000000:role/my-role",
		RoleName:        "my-role",
		RoleID:          "AROAtESTROLE123456789",
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(-time.Minute),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	resp := doSignedSTSAction(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetCallerIdentity"}})
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
}

// TestIAMApiControllerGetCallerIdentityWithSessionAfterRoleDeleted confirms
// resolveSessionIdentity's documented behavior: a signature-valid, unexpired
// session still authenticates and answers GetCallerIdentity even after its
// assumed role has since been deleted — real STS credentials are
// self-contained and don't re-check role existence on every call.
func TestIAMApiControllerGetCallerIdentityWithSessionAfterRoleDeleted(t *testing.T) {
	server := newIAMControllerTestServer(t)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTDELETEDROLE123",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         "arn:aws:iam::000000000000:role/ephemeral-role",
		RoleName:        "ephemeral-role",
		RoleID:          "AROAtESTROLE987654321",
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Note: no CreateRole call — the role this session names never existed
	// (or, equivalently, was deleted after the session was minted).

	resp := doSignedSTSAction(t, server, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		url.Values{"Action": {"GetCallerIdentity"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCallerIdentity status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out iamtypes.GetCallerIdentityResponse
	unmarshalXML(t, readBody(t, resp), &out)
	if out.Result.Arn != "arn:aws:sts::000000000000:assumed-role/ephemeral-role/my-session" {
		t.Fatalf("GetCallerIdentity session Arn = %q", out.Result.Arn)
	}
	if out.Result.UserId != "AROAtESTROLE987654321:my-session" {
		t.Fatalf("GetCallerIdentity session UserId = %q", out.Result.UserId)
	}
}

// TestIAMApiControllerGetCallerIdentityIncorrectServiceScope confirms the
// shared sigv4 auth pipeline reports the STS-specific service name ("sts",
// not "iam") when GetCallerIdentity is signed with a Credential scoped to
// the wrong service — the same generic mapIAMSigV4Error path
// authentication_test.go already exercises for "iam"-scoped actions,
// parameterized here by the "sts" service GetCallerIdentity actually signs
// for.
func TestIAMApiControllerGetCallerIdentityIncorrectServiceScope(t *testing.T) {
	server := newIAMControllerTestServer(t)

	req := signedSTSRequest(t, testRoot.Access, testRoot.Secret, "", url.Values{"Action": {"GetCallerIdentity"}})
	authHdr := req.Header.Get("Authorization")
	authHdr = strings.Replace(authHdr, "/sts/aws4_request", "/iam/aws4_request", 1)
	req.Header.Set("Authorization", authHdr)

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	requireSTSError(t, resp, http.StatusBadRequest, "Sender", "SignatureDoesNotMatch", "Credential should be scoped to correct service: 'sts'.")
}

// querySignedSTSRequest builds a genuinely presigned (query-string SigV4)
// GET request scoped to "sts" (matching a real STS SDK client's presigned
// URL), signed with the given credentials. When sessionToken is non-empty,
// the real v4 signer adds X-Amz-Security-Token to the query string itself
// — the same way AWS's own SDKs presign a request for temporary
// credentials.
func querySignedSTSRequest(t *testing.T, access, secret, sessionToken, target string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	hash := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(hash[:])

	creds := aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: sessionToken}
	signer := awsv4.NewSigner()
	signedURL, _, err := signer.PresignHTTP(context.Background(), creds, req, payloadHash, "sts", iammiddleware.SigningRegion, time.Now().UTC())
	if err != nil {
		t.Fatalf("presign sts request: %v", err)
	}

	return httptest.NewRequest(http.MethodGet, signedURL, nil)
}

// TestIAMApiControllerGetCallerIdentityQueryAuthWithSessionToken confirms a
// temporary (ASIA…) session CAN authenticate via query-string (presigned
// URL) auth when X-Amz-Security-Token matches the session, matching a
// genuine sts.PresignClient-generated presigned GetCallerIdentity request.
func TestIAMApiControllerGetCallerIdentityQueryAuthWithSessionToken(t *testing.T) {
	server := newIAMControllerTestServer(t)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTQUERYAUTH12345",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         "arn:aws:iam::000000000000:role/my-role",
		RoleName:        "my-role",
		RoleID:          "AROAtESTROLE123456789",
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	req := querySignedSTSRequest(t, session.AccessKeyId, session.SecretAccessKey, session.SessionToken,
		"http://example.com/?Action=GetCallerIdentity&Version="+stsAPIVersion)

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var out iamtypes.GetCallerIdentityResponse
	unmarshalXML(t, readBody(t, resp), &out)
	if out.Result.Arn != "arn:aws:sts::000000000000:assumed-role/my-role/my-session" {
		t.Fatalf("GetCallerIdentity session Arn = %q", out.Result.Arn)
	}
}

// TestIAMApiControllerGetCallerIdentityQueryAuthWithMismatchedSessionToken
// confirms a session presented via query auth still must carry the correct
// X-Amz-Security-Token — an unrelated token doesn't let a stolen/guessed
// temporary access key and secret through.
func TestIAMApiControllerGetCallerIdentityQueryAuthWithMismatchedSessionToken(t *testing.T) {
	server := newIAMControllerTestServer(t)

	now := time.Now().UTC()
	session := iamtypes.Session{
		AccessKeyId:     "ASIAtESTQUERYAUTH99999",
		SecretAccessKey: "sessionsecret",
		SessionToken:    "sessiontoken",
		RoleArn:         "arn:aws:iam::000000000000:role/my-role",
		RoleName:        "my-role",
		RoleID:          "AROAtESTROLE123456789",
		RoleSessionName: "my-session",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}
	if _, err := server.store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	req := querySignedSTSRequest(t, session.AccessKeyId, session.SecretAccessKey, "wrong-token",
		"http://example.com/?Action=GetCallerIdentity&Version="+stsAPIVersion)

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
}

// TestIAMApiControllerGetCallerIdentityQueryAuthLongTermCredentialWithTokenRejected
// confirms a long-term (AKIA…) user credential carrying a security token in
// the query string is still always rejected outright — that combination
// can never be legitimate, since a long-term secret never has a
// corresponding session token to match.
func TestIAMApiControllerGetCallerIdentityQueryAuthLongTermCredentialWithTokenRejected(t *testing.T) {
	server := newIAMControllerTestServer(t)
	accessKeyID, secret := createTestUserWithAccessKey(t, server, "heidi", "")

	req := querySignedSTSRequest(t, accessKeyID, secret, "",
		"http://example.com/?Action=GetCallerIdentity&Version="+stsAPIVersion)
	q := req.URL.Query()
	q.Set(sigv4auth.QuerySecurityToken, "bogus-token")
	req.URL.RawQuery = q.Encode()

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	requireSTSError(t, resp, http.StatusForbidden, "Sender", "InvalidClientTokenId", "The security token included in the request is invalid.")
}
