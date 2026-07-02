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

	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
	iamtypes "github.com/versity/versitygw/iamapi/types"
)

var userIDPattern = regexp.MustCompile(`^AIDA[A-Z2-7]{17}$`)

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
