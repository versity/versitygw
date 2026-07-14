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
	"encoding/xml"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
	iamtypes "github.com/versity/versitygw/iamapi/types"
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

func TestIAMApiControllerGetRootUser(t *testing.T) {
	server := newIAMControllerTestServer(t)
	resp := doIAMAction(t, server, url.Values{
		"Action":   {"GetUser"},
		"UserName": {""},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetUser root status = %d, body=%s", resp.StatusCode, readBody(t, resp))
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

	missing := doIAMAction(t, server, url.Values{"Action": {"GetUser"}})
	requireIAMError(t, missing, http.StatusBadRequest, "Sender", "MissingParameter", "The request must contain the parameter UserName.")
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
			code:    "MissingParameter",
			message: "The request must contain the parameter Tags.member.1.Key.",
		},
		{
			name: "missing tag value",
			params: url.Values{
				"Action":            {"CreateUser"},
				"UserName":          {"alice"},
				"Tags.member.1.Key": {"env"},
			},
			status:  http.StatusBadRequest,
			code:    "MissingParameter",
			message: "The request must contain the parameter Tags.member.1.Value.",
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
			message:   "1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000",
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

func newIAMControllerTestServer(t *testing.T) *IAMApiServer {
	t.Helper()

	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	server, err := New(store, WithQuiet(), WithRootUserCreds(testRoot))
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
