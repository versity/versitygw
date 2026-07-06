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
			UserID:     "AIDA22222222222222222",
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
			UserID:     "AIDA33333333333333333",
			Arn:        "arn:aws:iam::000000000000:user/engineering/platform/bob",
			CreateDate: created.Add(time.Second),
		},
		{
			Path:       "/ops/",
			UserName:   "carol",
			UserID:     "AIDA44444444444444444",
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
		AccessKeyID:     "AKIAZZZZZZZZZZZZZZZZ",
		SecretAccessKey: "secret",
		Status:          "Active",
		CreateDate:      created,
	}); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	if err := reopened.DeleteUser(ctx, "zoe"); !errors.Is(err, iamerr.GetAPIError(iamerr.ErrDeleteConflict)) {
		t.Fatalf("DeleteUser with access keys err = %v, want DeleteConflict", err)
	}
	if err := reopened.DeleteAccessKey(ctx, "zoe", "AKIAZZZZZZZZZZZZZZZZ"); err != nil {
		t.Fatalf("DeleteAccessKey: %v", err)
	}

	if err := reopened.DeleteUser(ctx, "zoe"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := reopened.DeleteUser(ctx, "zoe"); !errors.Is(err, iamerr.NoSuchEntityUser("zoe")) {
		t.Fatalf("DeleteUser missing err = %v, want NoSuchEntity", err)
	}
}
