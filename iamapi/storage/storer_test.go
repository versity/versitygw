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

package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

func TestNewRequiresConfig(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New returned nil error without a storer config")
	}
	if !strings.Contains(err.Error(), "no IAM storer config specified") {
		t.Fatalf("error = %q, want missing storer config", err)
	}
}

func TestNewCreatesInternalStore(t *testing.T) {
	dir := t.TempDir()

	_, err := New(Config{Dir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "iam.json")); err != nil {
		t.Fatalf("stat initialized IAM file: %v", err)
	}
}

func TestNewRejectsMultipleConfigs(t *testing.T) {
	_, err := New(Config{
		Dir: t.TempDir(),
		Vault: VaultConfig{
			EndpointURL: "https://vault.example.test",
		},
	})
	if err == nil {
		t.Fatal("New returned nil error with multiple storer configs")
	}
	if !strings.Contains(err.Error(), "multiple IAM storer configs specified") {
		t.Fatalf("error = %q, want multiple storer configs", err)
	}
}

func TestNewVaultRequiresAuth(t *testing.T) {
	_, err := New(Config{
		Vault: VaultConfig{
			EndpointURL: "https://vault.example.test",
		},
	})
	if err == nil {
		t.Fatal("New returned nil error for vault storer without auth credentials")
	}
	if !strings.Contains(err.Error(), "vault authentication requires either roleid/rolesecret or root token") {
		t.Fatalf("error = %q, want auth required error", err)
	}
}

func TestInternalStoreUserCRUDAndPagination(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	created := time.Date(2026, 6, 23, 18, 0, 0, 0, time.UTC)
	users := []types.User{
		{
			Path:       "/engineering/",
			UserName:   "alice",
			UserID:     "AIDAx2222222222222222",
			Arn:        "arn:aws:iam::000000000000:user/engineering/alice",
			CreateDate: created,
			Tags: []types.Tag{
				{Key: "env", Value: "test"},
				{Key: "empty", Value: ""},
			},
		},
		{
			Path:       "/engineering/platform/",
			UserName:   "bob",
			UserID:     "AIDAx3333333333333333",
			Arn:        "arn:aws:iam::000000000000:user/engineering/platform/bob",
			CreateDate: created.Add(time.Second),
		},
		{
			Path:       "/ops/",
			UserName:   "carol",
			UserID:     "AIDAx4444444444444444",
			Arn:        "arn:aws:iam::000000000000:user/ops/carol",
			CreateDate: created.Add(2 * time.Second),
		},
	}
	for _, user := range users {
		if _, err := store.CreateUser(ctx, user); err != nil {
			t.Fatalf("CreateUser(%s): %v", user.UserName, err)
		}
	}

	if _, err := store.CreateUser(ctx, users[0]); !errors.Is(err, iamerr.EntityAlreadyExistsUser("alice")) {
		t.Fatalf("CreateUser duplicate err = %v, want EntityAlreadyExists", err)
	}
	duplicateID := users[2]
	duplicateID.UserName = "dave"
	if _, err := store.CreateUser(ctx, duplicateID); !errors.Is(err, ErrUserIDAlreadyExists) {
		t.Fatalf("CreateUser duplicate id err = %v, want ErrUserIDAlreadyExists", err)
	}

	got, err := store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.UserName != "alice" || got.UserID != users[0].UserID {
		t.Fatalf("GetUser = %#v, want alice with stable id", got)
	}
	if !reflect.DeepEqual(got.Tags, users[0].Tags) {
		t.Fatalf("GetUser tags = %#v, want %#v", got.Tags, users[0].Tags)
	}

	page1, err := store.ListUsers(ctx, ListUsersInput{PathPrefix: "/engineering/", MaxItems: 1})
	if err != nil {
		t.Fatalf("ListUsers page1: %v", err)
	}
	if len(page1.Users) != 1 || page1.Users[0].UserName != "alice" || !page1.IsTruncated || page1.Marker != "alice" {
		t.Fatalf("page1 = %#v, want truncated alice page", page1)
	}
	if !reflect.DeepEqual(page1.Users[0].Tags, users[0].Tags) {
		t.Fatalf("ListUsers tags = %#v, want %#v", page1.Users[0].Tags, users[0].Tags)
	}

	page2, err := store.ListUsers(ctx, ListUsersInput{PathPrefix: "/engineering/", Marker: page1.Marker, MaxItems: 10})
	if err != nil {
		t.Fatalf("ListUsers page2: %v", err)
	}
	if len(page2.Users) != 1 || page2.Users[0].UserName != "bob" || page2.IsTruncated {
		t.Fatalf("page2 = %#v, want final bob page", page2)
	}

	updated, err := store.UpdateUser(ctx, UpdateUserInput{
		UserName:    "alice",
		NewPath:     "/ops/",
		NewUserName: "zoe",
		NewArn:      "arn:aws:iam::000000000000:user/ops/zoe",
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.UserName != "zoe" || updated.Path != "/ops/" || updated.Arn != "arn:aws:iam::000000000000:user/ops/zoe" {
		t.Fatalf("updated = %#v, want renamed/path-updated user", updated)
	}
	if updated.UserID != users[0].UserID || !updated.CreateDate.Equal(users[0].CreateDate) {
		t.Fatalf("updated identity changed: %#v", updated)
	}
	if !reflect.DeepEqual(updated.Tags, users[0].Tags) {
		t.Fatalf("updated tags = %#v, want %#v", updated.Tags, users[0].Tags)
	}
	if _, err := store.GetUser(ctx, "alice"); !errors.Is(err, iamerr.NoSuchEntityUser("alice")) {
		t.Fatalf("GetUser old name err = %v, want NoSuchEntity", err)
	}
	if _, err := store.UpdateUser(ctx, UpdateUserInput{UserName: "zoe", NewUserName: "bob"}); !errors.Is(err, iamerr.EntityAlreadyExistsUser("bob")) {
		t.Fatalf("UpdateUser duplicate err = %v, want EntityAlreadyExists", err)
	}

	reopened, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("reopen NewInternal: %v", err)
	}
	reopenedUser, err := reopened.GetUser(ctx, "zoe")
	if err != nil {
		t.Fatalf("GetUser after reopen: %v", err)
	}
	if !reflect.DeepEqual(reopenedUser.Tags, users[0].Tags) {
		t.Fatalf("reopened tags = %#v, want %#v", reopenedUser.Tags, users[0].Tags)
	}

	if _, err := reopened.CreateAccessKey(ctx, CreateAccessKeyInput{
		UserName:        "zoe",
		AccessKeyID:     "AKIAzZZZZZZZZZZZZZZZ",
		SecretAccessKey: "secret",
		Status:          "Active",
		CreateDate:      created,
	}); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	if err := reopened.DeleteUser(ctx, "zoe"); !errors.Is(err, iamerr.GetAPIError(iamerr.ErrDeleteConflict)) {
		t.Fatalf("DeleteUser with access keys err = %v, want DeleteConflict", err)
	}
	if err := reopened.DeleteAccessKey(ctx, "zoe", "AKIAzZZZZZZZZZZZZZZZ"); err != nil {
		t.Fatalf("DeleteAccessKey: %v", err)
	}

	if err := reopened.DeleteUser(ctx, "zoe"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := reopened.DeleteUser(ctx, "zoe"); !errors.Is(err, iamerr.NoSuchEntityUser("zoe")) {
		t.Fatalf("DeleteUser missing err = %v, want NoSuchEntity", err)
	}
}

func TestInternalStoreGetUserByAccessKeyID(t *testing.T) {
	ctx := context.Background()
	store, err := NewInternal(t.TempDir())
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	if _, err := store.CreateUser(ctx, types.User{UserName: "alice", UserID: "AIDAx1111111111111111"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.CreateAccessKey(ctx, CreateAccessKeyInput{
		UserName:        "alice",
		AccessKeyID:     "AKIAALICE0000000000",
		SecretAccessKey: "secret",
		Status:          "Active",
		CreateDate:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}

	got, err := store.GetUserByAccessKeyID(ctx, "AKIAALICE0000000000")
	if err != nil {
		t.Fatalf("GetUserByAccessKeyID: %v", err)
	}
	if got.UserName != "alice" {
		t.Fatalf("GetUserByAccessKeyID = %#v, want alice", got)
	}

	if _, err := store.GetUserByAccessKeyID(ctx, "AKIAuNKNOWN0000000000"); !errors.Is(err, iamerr.NoSuchEntityAccessKey("AKIAuNKNOWN0000000000")) {
		t.Fatalf("GetUserByAccessKeyID unknown key err = %v, want NoSuchEntityAccessKey", err)
	}
}

func TestInternalStoreUserNameCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	store, err := NewInternal(t.TempDir())
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	if _, err := store.CreateUser(ctx, types.User{UserName: "alice", UserID: "AIDAx1111111111111111"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.CreateUser(ctx, types.User{UserName: "ALICE", UserID: "AIDAx2222222222222222"}); !errors.Is(err, iamerr.EntityAlreadyExistsUser("ALICE")) {
		t.Fatalf("CreateUser case-variant duplicate err = %v, want EntityAlreadyExists", err)
	}

	got, err := store.GetUser(ctx, "ALICE")
	if err != nil {
		t.Fatalf("GetUser case-insensitive lookup: %v", err)
	}
	if got.UserName != "alice" {
		t.Fatalf("GetUser case-insensitive lookup = %#v, want canonical casing preserved", got)
	}

	if err := store.DeleteUser(ctx, "ALICE"); err != nil {
		t.Fatalf("DeleteUser case-insensitive lookup: %v", err)
	}
	if _, err := store.GetUser(ctx, "alice"); !errors.Is(err, iamerr.NoSuchEntityUser("alice")) {
		t.Fatalf("GetUser after case-insensitive delete err = %v, want NoSuchEntity", err)
	}
}

func TestInternalStoreRoleCRUDAndPagination(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	created := time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC)
	roles := []types.Role{
		{
			Path:                     "/engineering/",
			RoleName:                 "alice-role",
			RoleID:                   "AROAx2222222222222222",
			Arn:                      "arn:aws:iam::000000000000:role/engineering/alice-role",
			CreateDate:               created,
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
			MaxSessionDuration:       3600,
			Tags: []types.Tag{
				{Key: "env", Value: "test"},
			},
		},
		{
			Path:                     "/engineering/platform/",
			RoleName:                 "bob-role",
			RoleID:                   "AROAx3333333333333333",
			Arn:                      "arn:aws:iam::000000000000:role/engineering/platform/bob-role",
			CreateDate:               created.Add(time.Second),
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
			MaxSessionDuration:       3600,
		},
		{
			Path:                     "/ops/",
			RoleName:                 "carol-role",
			RoleID:                   "AROAx4444444444444444",
			Arn:                      "arn:aws:iam::000000000000:role/ops/carol-role",
			CreateDate:               created.Add(2 * time.Second),
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
			MaxSessionDuration:       3600,
		},
	}
	for _, role := range roles {
		created, err := store.CreateRole(ctx, role)
		if err != nil {
			t.Fatalf("CreateRole(%s): %v", role.RoleName, err)
		}
		if created.RoleLastUsed == nil {
			t.Fatalf("CreateRole(%s) RoleLastUsed = nil, want non-nil empty element", role.RoleName)
		}
	}

	if _, err := store.CreateRole(ctx, roles[0]); !errors.Is(err, iamerr.EntityAlreadyExistsRole("alice-role")) {
		t.Fatalf("CreateRole duplicate err = %v, want EntityAlreadyExists", err)
	}
	if _, err := store.CreateRole(ctx, types.Role{RoleName: "ALICE-ROLE", RoleID: "AROAx5555555555555555"}); !errors.Is(err, iamerr.EntityAlreadyExistsRole("ALICE-ROLE")) {
		t.Fatalf("CreateRole case-variant duplicate err = %v, want EntityAlreadyExists", err)
	}
	duplicateID := roles[2]
	duplicateID.RoleName = "dave-role"
	if _, err := store.CreateRole(ctx, duplicateID); !errors.Is(err, ErrRoleIDAlreadyExists) {
		t.Fatalf("CreateRole duplicate id err = %v, want ErrRoleIDAlreadyExists", err)
	}

	got, err := store.GetRole(ctx, "ALICE-ROLE")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.RoleName != "alice-role" || got.RoleID != roles[0].RoleID {
		t.Fatalf("GetRole = %#v, want alice-role with stable id and preserved casing", got)
	}
	if !reflect.DeepEqual(got.Tags, roles[0].Tags) {
		t.Fatalf("GetRole tags = %#v, want %#v", got.Tags, roles[0].Tags)
	}
	if got.RoleLastUsed == nil {
		t.Fatal("GetRole RoleLastUsed = nil, want non-nil empty element")
	}

	page1, err := store.ListRoles(ctx, ListRolesInput{PathPrefix: "/engineering/", MaxItems: 1})
	if err != nil {
		t.Fatalf("ListRoles page1: %v", err)
	}
	if len(page1.Roles) != 1 || page1.Roles[0].RoleName != "alice-role" || !page1.IsTruncated || page1.Marker != "alice-role" {
		t.Fatalf("page1 = %#v, want truncated alice-role page", page1)
	}
	if page1.Roles[0].RoleLastUsed != nil {
		t.Fatalf("ListRoles RoleLastUsed = %#v, want nil (list/get asymmetry)", page1.Roles[0].RoleLastUsed)
	}

	page2, err := store.ListRoles(ctx, ListRolesInput{PathPrefix: "/engineering/", Marker: page1.Marker, MaxItems: 10})
	if err != nil {
		t.Fatalf("ListRoles page2: %v", err)
	}
	if len(page2.Roles) != 1 || page2.Roles[0].RoleName != "bob-role" || page2.IsTruncated {
		t.Fatalf("page2 = %#v, want final bob-role page", page2)
	}

	updatedRole, err := store.UpdateAssumeRolePolicy(ctx, UpdateAssumeRolePolicyInput{
		RoleName:       "alice-role",
		PolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
	})
	if err != nil {
		t.Fatalf("UpdateAssumeRolePolicy: %v", err)
	}
	if updatedRole.AssumeRolePolicyDocument != `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}` {
		t.Fatalf("UpdateAssumeRolePolicy result = %#v", updatedRole)
	}
	if updatedRole.RoleID != roles[0].RoleID {
		t.Fatalf("UpdateAssumeRolePolicy identity changed: %#v", updatedRole)
	}
	if _, err := store.UpdateAssumeRolePolicy(ctx, UpdateAssumeRolePolicyInput{RoleName: "missing-role", PolicyDocument: "{}"}); !errors.Is(err, iamerr.NoSuchEntityRole("missing-role")) {
		t.Fatalf("UpdateAssumeRolePolicy missing role err = %v, want NoSuchEntity", err)
	}

	reopened, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("reopen NewInternal: %v", err)
	}
	reopenedRole, err := reopened.GetRole(ctx, "alice-role")
	if err != nil {
		t.Fatalf("GetRole after reopen: %v", err)
	}
	if reopenedRole.AssumeRolePolicyDocument != updatedRole.AssumeRolePolicyDocument {
		t.Fatalf("reopened AssumeRolePolicyDocument = %q, want %q", reopenedRole.AssumeRolePolicyDocument, updatedRole.AssumeRolePolicyDocument)
	}

	if err := reopened.DeleteRole(ctx, "carol-role"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if err := reopened.DeleteRole(ctx, "carol-role"); !errors.Is(err, iamerr.NoSuchEntityRole("carol-role")) {
		t.Fatalf("DeleteRole missing err = %v, want NoSuchEntity", err)
	}
}

func TestInternalStoreRecordRoleUsage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	role := types.Role{
		Path:                     "/",
		RoleName:                 "used-role",
		RoleID:                   "AROAx5555555555555555",
		Arn:                      "arn:aws:iam::000000000000:role/used-role",
		CreateDate:               time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC),
		AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
	}
	created, err := store.CreateRole(ctx, role)
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if created.RoleLastUsed.LastUsedDate != nil {
		t.Fatalf("CreateRole RoleLastUsed = %#v, want the never-used empty element", created.RoleLastUsed)
	}

	when := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)
	if err := store.RecordRoleUsage(ctx, "USED-ROLE", "us-east-1", when); err != nil {
		t.Fatalf("RecordRoleUsage: %v", err)
	}

	// Reopened from disk, so this also covers the record surviving the
	// JSON round trip rather than only living in the returned copy.
	reopened, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("reopen NewInternal: %v", err)
	}
	got, err := reopened.GetRole(ctx, "used-role")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.RoleLastUsed == nil || got.RoleLastUsed.LastUsedDate == nil || !got.RoleLastUsed.LastUsedDate.Equal(when) {
		t.Fatalf("RoleLastUsed = %#v, want LastUsedDate %v", got.RoleLastUsed, when)
	}
	if got.RoleLastUsed.Region != "us-east-1" {
		t.Fatalf("RoleLastUsed.Region = %q, want us-east-1", got.RoleLastUsed.Region)
	}

	listed, err := reopened.ListRoles(ctx, ListRolesInput{})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(listed.Roles) != 1 || listed.Roles[0].RoleLastUsed != nil {
		t.Fatalf("ListRoles = %#v, want the used role with no RoleLastUsed", listed.Roles)
	}

	if err := store.RecordRoleUsage(ctx, "missing-role", "us-east-1", when); !errors.Is(err, iamerr.NoSuchEntityRole("missing-role")) {
		t.Fatalf("RecordRoleUsage missing role err = %v, want NoSuchEntity", err)
	}
}

func TestShouldRecordUsage(t *testing.T) {
	base := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)

	for _, tt := range []struct {
		name                    string
		prev                    time.Time
		prevService, prevRegion string
		service, region         string
		when                    time.Time
		want                    bool
	}{
		{
			name: "nothing recorded yet",
			when: base, service: "s3", region: "us-east-1",
			want: true,
		},
		{
			name: "same service and region inside the window",
			prev: base, prevService: "s3", prevRegion: "us-east-1",
			service: "s3", region: "us-east-1", when: base.Add(UsageRecordCoalesceWindow - time.Second),
			want: false,
		},
		{
			name: "same service and region past the window",
			prev: base, prevService: "s3", prevRegion: "us-east-1",
			service: "s3", region: "us-east-1", when: base.Add(UsageRecordCoalesceWindow),
			want: true,
		},
		{
			name: "a different service is never coalesced",
			prev: base, prevService: "iam", prevRegion: "us-east-1",
			service: "s3", region: "us-east-1", when: base.Add(time.Second),
			want: true,
		},
		{
			name: "a different region is never coalesced",
			prev: base, prevService: "s3", prevRegion: "us-east-1",
			service: "s3", region: "eu-west-1", when: base.Add(time.Second),
			want: true,
		},
		{
			name: "an older use never replaces a newer record",
			prev: base, prevService: "s3", prevRegion: "us-east-1",
			service: "s3", region: "us-east-1", when: base.Add(-time.Hour),
			want: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldRecordUsage(tt.prev, tt.prevService, tt.prevRegion, tt.service, tt.region, tt.when)
			if got != tt.want {
				t.Errorf("shouldRecordUsage = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestInternalStoreRecordAccessKeyUsageCoalesces confirms the storer applies
// shouldRecordUsage rather than rewriting the IAM file on every recorded
// use, and that a service change still lands immediately.
func TestInternalStoreRecordAccessKeyUsageCoalesces(t *testing.T) {
	ctx := context.Background()
	store, err := NewInternal(t.TempDir())
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	if _, err := store.CreateUser(ctx, types.User{UserName: "nina", Path: "/"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.CreateAccessKey(ctx, CreateAccessKeyInput{
		UserName: "nina", AccessKeyID: "AKIDNINA", SecretAccessKey: "s", Status: "Active", CreateDate: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}

	first := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)
	if err := store.RecordAccessKeyUsage(ctx, "AKIDNINA", "s3", "us-east-1", first); err != nil {
		t.Fatalf("RecordAccessKeyUsage: %v", err)
	}
	if err := store.RecordAccessKeyUsage(ctx, "AKIDNINA", "s3", "us-east-1", first.Add(time.Second)); err != nil {
		t.Fatalf("RecordAccessKeyUsage (repeat): %v", err)
	}

	got, err := store.GetAccessKeyLastUsed(ctx, "AKIDNINA")
	if err != nil {
		t.Fatalf("GetAccessKeyLastUsed: %v", err)
	}
	if !got.LastUsedDate.Equal(first) {
		t.Fatalf("LastUsedDate = %v after a coalesced repeat, want %v", got.LastUsedDate, first)
	}

	if err := store.RecordAccessKeyUsage(ctx, "AKIDNINA", "iam", "us-east-1", first.Add(time.Second)); err != nil {
		t.Fatalf("RecordAccessKeyUsage (service change): %v", err)
	}
	got, err = store.GetAccessKeyLastUsed(ctx, "AKIDNINA")
	if err != nil {
		t.Fatalf("GetAccessKeyLastUsed: %v", err)
	}
	if got.ServiceName != "iam" || !got.LastUsedDate.Equal(first.Add(time.Second)) {
		t.Fatalf("last used = %s at %v, want iam at %v", got.ServiceName, got.LastUsedDate, first.Add(time.Second))
	}

	if err := store.RecordAccessKeyUsage(ctx, "missing", "s3", "us-east-1", first); !errors.Is(err, iamerr.NoSuchEntityAccessKey("missing")) {
		t.Fatalf("RecordAccessKeyUsage missing key err = %v, want NoSuchEntity", err)
	}
}

func TestInternalStoreRolePolicyCRUD(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	if _, err := store.CreateRole(ctx, types.Role{
		RoleName:                 "alice-role",
		RoleID:                   "AROAx2222222222222222",
		AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	if err := store.PutRolePolicy(ctx, PutRolePolicyInput{
		RoleName:       "ALICE-ROLE",
		PolicyName:     "ReadOnly",
		PolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
	}); err != nil {
		t.Fatalf("PutRolePolicy: %v", err)
	}
	if err := store.PutRolePolicy(ctx, PutRolePolicyInput{RoleName: "missing-role", PolicyName: "P", PolicyDocument: "{}"}); !errors.Is(err, iamerr.NoSuchEntityRole("missing-role")) {
		t.Fatalf("PutRolePolicy missing role err = %v, want NoSuchEntity", err)
	}

	entry, err := store.GetRolePolicy(ctx, "alice-role", "ReadOnly")
	if err != nil {
		t.Fatalf("GetRolePolicy: %v", err)
	}
	if entry.PolicyDocument != `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}` {
		t.Fatalf("GetRolePolicy document = %q", entry.PolicyDocument)
	}
	if entry.CreateDate.IsZero() || entry.UpdateDate.IsZero() {
		t.Fatalf("GetRolePolicy CreateDate/UpdateDate zero: %#v", entry)
	}
	if _, err := store.GetRolePolicy(ctx, "alice-role", "NoSuchPolicy"); !errors.Is(err, iamerr.NoSuchEntityRolePolicy("alice-role", "NoSuchPolicy")) {
		t.Fatalf("GetRolePolicy missing policy err = %v, want NoSuchEntity", err)
	}
	if _, err := store.GetRolePolicy(ctx, "missing-role", "P"); !errors.Is(err, iamerr.NoSuchEntityRole("missing-role")) {
		t.Fatalf("GetRolePolicy missing role err = %v, want NoSuchEntity", err)
	}

	// Overwriting an existing PolicyName replaces its document rather than
	// stacking toward the aggregate size quota.
	if err := store.PutRolePolicy(ctx, PutRolePolicyInput{
		RoleName:       "alice-role",
		PolicyName:     "ReadOnly",
		PolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`,
	}); err != nil {
		t.Fatalf("overwrite PutRolePolicy: %v", err)
	}
	overwritten, err := store.GetRolePolicy(ctx, "alice-role", "ReadOnly")
	if err != nil {
		t.Fatalf("GetRolePolicy after overwrite: %v", err)
	}
	if !strings.Contains(overwritten.PolicyDocument, "Deny") {
		t.Fatalf("GetRolePolicy after overwrite = %q, want the Deny statement", overwritten.PolicyDocument)
	}

	// Aggregate inline policy size for a role is capped at
	// MaxInlinePolicyBytesPerRole (10240), distinct from and larger than
	// the 2048 byte cap for users.
	oversized := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 10300) + `","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	if err := store.PutRolePolicy(ctx, PutRolePolicyInput{RoleName: "alice-role", PolicyName: "TooBig", PolicyDocument: oversized}); !errors.Is(err, iamerr.InlinePolicyQuotaExceeded("role", "alice-role", MaxInlinePolicyBytesPerRole)) {
		t.Fatalf("PutRolePolicy oversized err = %v, want LimitExceeded", err)
	}

	if err := store.PutRolePolicy(ctx, PutRolePolicyInput{
		RoleName:       "alice-role",
		PolicyName:     "SecondPolicy",
		PolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`,
	}); err != nil {
		t.Fatalf("PutRolePolicy second policy: %v", err)
	}

	list, err := store.ListRolePolicies(ctx, ListRolePoliciesInput{RoleName: "ALICE-ROLE", MaxItems: 1})
	if err != nil {
		t.Fatalf("ListRolePolicies page1: %v", err)
	}
	if len(list.PolicyNames) != 1 || list.PolicyNames[0] != "ReadOnly" || !list.IsTruncated || list.Marker != "ReadOnly" {
		t.Fatalf("ListRolePolicies page1 = %#v, want truncated ReadOnly page", list)
	}
	page2, err := store.ListRolePolicies(ctx, ListRolePoliciesInput{RoleName: "alice-role", Marker: list.Marker, MaxItems: 10})
	if err != nil {
		t.Fatalf("ListRolePolicies page2: %v", err)
	}
	if len(page2.PolicyNames) != 1 || page2.PolicyNames[0] != "SecondPolicy" || page2.IsTruncated {
		t.Fatalf("ListRolePolicies page2 = %#v, want final SecondPolicy page", page2)
	}
	if _, err := store.ListRolePolicies(ctx, ListRolePoliciesInput{RoleName: "missing-role"}); !errors.Is(err, iamerr.NoSuchEntityRole("missing-role")) {
		t.Fatalf("ListRolePolicies missing role err = %v, want NoSuchEntity", err)
	}

	// A role with attached inline policies cannot be deleted until they are
	// all removed first.
	if err := store.DeleteRole(ctx, "alice-role"); !errors.Is(err, iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)) {
		t.Fatalf("DeleteRole with policies err = %v, want DeleteConflict", err)
	}

	if err := store.DeleteRolePolicy(ctx, "alice-role", "SecondPolicy"); err != nil {
		t.Fatalf("DeleteRolePolicy: %v", err)
	}
	if err := store.DeleteRolePolicy(ctx, "alice-role", "NoSuchPolicy"); !errors.Is(err, iamerr.NoSuchEntityRolePolicy("alice-role", "NoSuchPolicy")) {
		t.Fatalf("DeleteRolePolicy missing policy err = %v, want NoSuchEntity", err)
	}
	if err := store.DeleteRolePolicy(ctx, "missing-role", "P"); !errors.Is(err, iamerr.NoSuchEntityRole("missing-role")) {
		t.Fatalf("DeleteRolePolicy missing role err = %v, want NoSuchEntity", err)
	}

	reopened, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("reopen NewInternal: %v", err)
	}
	if _, err := reopened.GetRolePolicy(ctx, "alice-role", "ReadOnly"); err != nil {
		t.Fatalf("GetRolePolicy after reopen: %v", err)
	}

	if err := reopened.DeleteRolePolicy(ctx, "alice-role", "ReadOnly"); err != nil {
		t.Fatalf("DeleteRolePolicy: %v", err)
	}
	if err := reopened.DeleteRole(ctx, "alice-role"); err != nil {
		t.Fatalf("DeleteRole after removing all policies: %v", err)
	}
}

func TestInternalStoreSessionCRUDAndExpiry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	// GetSession compares Expiration against the real wall clock, so (unlike
	// most other timestamps in this package's tests) now must track it.
	now := time.Now().UTC()
	session := types.Session{
		AccessKeyId:     "ASIAeXAMPLE1234567890",
		SecretAccessKey: "secret",
		SessionToken:    "token",
		RoleArn:         "arn:aws:iam::000000000000:role/my-role",
		RoleName:        "my-role",
		RoleID:          "AROAeXAMPLE1234567890",
		RoleSessionName: "my-session",
		Provider:        "arn:aws:iam::000000000000:oidc-provider/example.com",
		Audience:        "client1",
		Subject:         "user1",
		CreateDate:      now,
		Expiration:      now.Add(time.Hour),
	}

	if _, err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := store.GetSession(ctx, session.AccessKeyId)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !reflect.DeepEqual(*got, session) {
		t.Fatalf("GetSession = %#v, want %#v", *got, session)
	}

	if _, err := store.GetSession(ctx, "ASIAUNKNOWN"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("GetSession unknown access key err = %v, want ErrSessionNotFound", err)
	}

	// A session persists across process restarts (round-trips through the
	// same on-disk file the rest of the IAM store uses).
	reopened, err := NewInternal(dir)
	if err != nil {
		t.Fatalf("reopen NewInternal: %v", err)
	}
	if _, err := reopened.GetSession(ctx, session.AccessKeyId); err != nil {
		t.Fatalf("GetSession after reopen: %v", err)
	}

	expired := types.Session{
		AccessKeyId: "ASIAeXPIRED1234567890",
		CreateDate:  now,
		Expiration:  now.Add(-time.Minute),
	}
	if _, err := reopened.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession expired: %v", err)
	}
	if _, err := reopened.GetSession(ctx, expired.AccessKeyId); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("GetSession expired err = %v, want ErrSessionNotFound", err)
	}

	// Creating a new session opportunistically prunes the already-expired
	// one from storage rather than letting it accumulate forever.
	another := types.Session{
		AccessKeyId: "ASIAaNOTHER1234567890",
		CreateDate:  now,
		Expiration:  now.Add(time.Hour),
	}
	if _, err := reopened.CreateSession(ctx, another); err != nil {
		t.Fatalf("CreateSession another: %v", err)
	}
	internal := reopened.(*InternalStore)
	conf, err := internal.engine.GetIAM()
	if err != nil {
		t.Fatalf("GetIAM: %v", err)
	}
	if _, ok := conf.Sessions[expired.AccessKeyId]; ok {
		t.Fatalf("expired session %q was not pruned: %#v", expired.AccessKeyId, conf.Sessions)
	}
	if _, ok := conf.Sessions[another.AccessKeyId]; !ok {
		t.Fatalf("unexpired session %q missing after prune: %#v", another.AccessKeyId, conf.Sessions)
	}
}

func TestInternalStoreSessionCapPerRole(t *testing.T) {
	// Each CreateSession call rewrites the whole IAM file, so hitting the
	// real 1000 cap here would mean O(n^2) JSON work just to prove the cap
	// is enforced. Lower it for the duration of the test instead.
	orig := MaxActiveSessionsPerRole
	MaxActiveSessionsPerRole = 5
	t.Cleanup(func() { MaxActiveSessionsPerRole = orig })

	ctx := context.Background()
	store, err := NewInternal(t.TempDir())
	if err != nil {
		t.Fatalf("NewInternal: %v", err)
	}

	now := time.Now().UTC()
	newSession := func(i int, roleArn string) types.Session {
		return types.Session{
			AccessKeyId: fmt.Sprintf("ASIACAPPEDROLE%06d", i),
			RoleArn:     roleArn,
			CreateDate:  now,
			Expiration:  now.Add(time.Hour),
		}
	}

	const roleArn = "arn:aws:iam::000000000000:role/capped-role"
	for i := range MaxActiveSessionsPerRole {
		if _, err := store.CreateSession(ctx, newSession(i, roleArn)); err != nil {
			t.Fatalf("CreateSession %d: %v", i, err)
		}
	}

	// The role is now at its cap - one more session for the same role must
	// be rejected rather than accepted unboundedly.
	_, err = store.CreateSession(ctx, newSession(MaxActiveSessionsPerRole, roleArn))
	var apiErr iamerr.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode() != 400 {
		t.Fatalf("CreateSession at cap err = %v, want a Throttling APIError", err)
	}

	// A different role is entirely unaffected by the first role's cap.
	const otherRoleArn = "arn:aws:iam::000000000000:role/other-role"
	if _, err := store.CreateSession(ctx, newSession(MaxActiveSessionsPerRole+1, otherRoleArn)); err != nil {
		t.Fatalf("CreateSession for a different role: %v", err)
	}
}
