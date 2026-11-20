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

package iamutil

import (
	"context"
	"errors"
	"testing"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

var errStoreDown = errors.New("503 Service Unavailable: Vault is sealed")

// fakeIdentityStore answers only the lookups the resolvers make; the embedded
// nil IdentityStore panics on any other, so a resolver reaching for something
// unexpected fails loudly.
type fakeIdentityStore struct {
	IdentityStore

	user       *types.User
	userErr    error
	session    *types.Session
	sessionErr error
	role       *types.Role
	roleErr    error
}

func (f fakeIdentityStore) GetUserByAccessKeyID(context.Context, string) (*types.User, error) {
	return f.user, f.userErr
}

func (f fakeIdentityStore) GetSession(context.Context, string) (*types.Session, error) {
	return f.session, f.sessionErr
}

func (f fakeIdentityStore) GetRole(context.Context, string) (*types.Role, error) {
	return f.role, f.roleErr
}

func TestResolveUserIdentity(t *testing.T) {
	const accessKeyID = "AKIAALICE"

	userWithKeyStatus := func(status string) *types.User {
		return &types.User{
			UserName:   "alice",
			AccessKeys: []types.AccessKeyEntry{{AccessKeyId: accessKeyID, SecretAccessKey: "alicesecret", Status: status}},
		}
	}

	tests := []struct {
		name    string
		store   fakeIdentityStore
		wantErr error
	}{
		{name: "active key resolves", store: fakeIdentityStore{user: userWithKeyStatus(AccessKeyStatusActive)}},
		{name: "unknown key", store: fakeIdentityStore{userErr: iamerr.NoSuchEntityAccessKey(accessKeyID)}, wantErr: ErrIdentityNotFound},
		{name: "inactive key", store: fakeIdentityStore{user: userWithKeyStatus("Inactive")}, wantErr: ErrIdentityNotFound},
		{name: "store failure", store: fakeIdentityStore{userErr: errStoreDown}, wantErr: errStoreDown},
		// Only a NoSuchEntity answer means the key is absent: any other
		// iamerr error is the store failing in its own words.
		{name: "store failure with an API error", store: fakeIdentityStore{userErr: iamerr.GetAPIError(iamerr.ErrInternalFailure)}, wantErr: iamerr.GetAPIError(iamerr.ErrInternalFailure)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, secret, err := ResolveUserIdentity(context.Background(), tt.store, accessKeyID)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ResolveUserIdentity() error = %v", err)
				}
				if identity.User == nil || secret != "alicesecret" {
					t.Fatalf("ResolveUserIdentity() = %+v, %q", identity, secret)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ResolveUserIdentity() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != ErrIdentityNotFound && errors.Is(err, ErrIdentityNotFound) {
				t.Fatalf("ResolveUserIdentity() reported a store failure as a missing identity: %v", err)
			}
		})
	}
}

func TestResolveSessionByToken(t *testing.T) {
	const (
		accessKeyID = "ASIASESSION"
		token       = "session-token"
	)

	session := &types.Session{
		AccessKeyId:     accessKeyID,
		SecretAccessKey: "sessionsecret",
		SessionToken:    token,
		RoleName:        "reader",
		RoleID:          "AROAREADER",
		RoleArn:         "arn:aws:iam::000000000000:role/reader",
	}
	role := &types.Role{
		RoleName: "reader",
		RoleID:   session.RoleID,
		Arn:      session.RoleArn,
		Policies: types.Policies{Inline: []types.PolicyEntry{{PolicyName: "P"}}},
	}

	tests := []struct {
		name     string
		store    fakeIdentityStore
		token    string
		wantErr  error
		wantRole bool
	}{
		{name: "resolves with its role", store: fakeIdentityStore{session: session, role: role}, token: token, wantRole: true},
		{name: "no token", store: fakeIdentityStore{session: session, role: role}, token: "", wantErr: ErrIdentityNotFound},
		{name: "unknown or expired session", store: fakeIdentityStore{sessionErr: ErrSessionNotFound}, token: token, wantErr: ErrIdentityNotFound},
		{name: "session store failure", store: fakeIdentityStore{sessionErr: errStoreDown}, token: token, wantErr: errStoreDown},
		{name: "wrong token", store: fakeIdentityStore{session: session, role: role}, token: "other", wantErr: ErrInvalidSessionToken},
		// A session outlives its role, and still authenticates without it.
		{name: "role deleted", store: fakeIdentityStore{session: session, roleErr: iamerr.NoSuchEntityRole("reader")}, token: token},
		{name: "role recreated under the same name", store: fakeIdentityStore{session: session, role: &types.Role{RoleName: "reader", RoleID: "AROAOTHER", Arn: session.RoleArn}}, token: token},
		// A role the store could not read is not a role that is gone.
		{name: "role store failure", store: fakeIdentityStore{session: session, roleErr: errStoreDown}, token: token, wantErr: errStoreDown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, secret, err := ResolveSessionByToken(context.Background(), tt.store, accessKeyID, tt.token)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ResolveSessionByToken() error = %v, want %v", err, tt.wantErr)
				}
				if tt.wantErr != ErrIdentityNotFound && errors.Is(err, ErrIdentityNotFound) {
					t.Fatalf("ResolveSessionByToken() reported a store failure as a missing identity: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSessionByToken() error = %v", err)
			}
			if identity.Session == nil || secret != "sessionsecret" {
				t.Fatalf("ResolveSessionByToken() = %+v, %q", identity, secret)
			}
			if gotRole := identity.Role != nil; gotRole != tt.wantRole {
				t.Fatalf("identity.Role set = %v, want %v", gotRole, tt.wantRole)
			}
		})
	}
}
