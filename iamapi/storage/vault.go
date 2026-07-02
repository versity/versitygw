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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

const vaultRequestTimeout = 10 * time.Second

// VaultConfig holds all configuration options for the Vault-backed IAM storer.
type VaultConfig struct {
	EndpointURL            string
	Namespace              string
	SecretStoragePath      string
	SecretStorageNamespace string
	AuthMethod             string
	AuthNamespace          string
	MountPath              string
	RootToken              string
	RoleID                 string
	RoleSecret             string
	ServerCert             string
	ClientCert             string
	ClientCertKey          string
}

// VaultStore is a Vault KV v2-backed implementation of Storer.
type VaultStore struct {
	client            *vault.Client
	authReqOpts       []vault.RequestOption
	kvReqOpts         []vault.RequestOption
	secretStoragePath string
	creds             schema.AppRoleLoginRequest
}

var _ Storer = (*VaultStore)(nil)

func NewVault(cfg VaultConfig) (Storer, error) {
	opts := []vault.ClientOption{
		vault.WithAddress(strings.TrimSpace(cfg.EndpointURL)),
		vault.WithRequestTimeout(vaultRequestTimeout),
	}

	serverCert := strings.TrimSpace(cfg.ServerCert)
	clientCert := strings.TrimSpace(cfg.ClientCert)
	clientCertKey := strings.TrimSpace(cfg.ClientCertKey)

	if serverCert != "" {
		tls := vault.TLSConfiguration{}
		tls.ServerCertificate.FromBytes = []byte(serverCert)
		if clientCert != "" {
			if clientCertKey == "" {
				return nil, fmt.Errorf("client certificate and client certificate key should both be specified")
			}
			tls.ClientCertificate.FromBytes = []byte(clientCert)
			tls.ClientCertificateKey.FromBytes = []byte(clientCertKey)
		}
		opts = append(opts, vault.WithTLS(tls))
	}

	client, err := vault.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("init vault client: %w", err)
	}

	authMethod := strings.TrimSpace(cfg.AuthMethod)
	mountPath := strings.TrimSpace(cfg.MountPath)

	authReqOpts := []vault.RequestOption{}
	if authMethod != "" {
		authReqOpts = append(authReqOpts, vault.WithMountPath(authMethod))
	}

	kvReqOpts := []vault.RequestOption{}
	if mountPath != "" {
		kvReqOpts = append(kvReqOpts, vault.WithMountPath(mountPath))
	}

	// Resolve namespaces: specific namespace overrides the generic fallback.
	authNS := strings.TrimSpace(cfg.AuthNamespace)
	secretNS := strings.TrimSpace(cfg.SecretStorageNamespace)
	fallback := strings.TrimSpace(cfg.Namespace)
	if authNS == "" {
		authNS = fallback
	}
	if secretNS == "" {
		secretNS = fallback
	}

	rootToken := strings.TrimSpace(cfg.RootToken)
	roleID := strings.TrimSpace(cfg.RoleID)
	roleSecret := strings.TrimSpace(cfg.RoleSecret)

	// AppRole tokens are namespace-scoped; cross-namespace use requires a root token.
	if rootToken == "" && authNS != "" && secretNS != "" && authNS != secretNS {
		return nil, fmt.Errorf(
			"approle tokens are namespace scoped. auth namespace %q and secret storage namespace %q differ. "+
				"use the same namespace or authenticate with a root token",
			authNS, secretNS,
		)
	}

	if rootToken == "" && authNS != "" {
		authReqOpts = append(authReqOpts, vault.WithNamespace(authNS))
	}
	if secretNS != "" {
		kvReqOpts = append(kvReqOpts, vault.WithNamespace(secretNS))
	}

	creds := schema.AppRoleLoginRequest{
		RoleId:   roleID,
		SecretId: roleSecret,
	}

	switch {
	case rootToken != "":
		if err := client.SetToken(rootToken); err != nil {
			return nil, fmt.Errorf("root token authentication failure: %w", err)
		}
	case roleID != "":
		if roleSecret == "" {
			return nil, fmt.Errorf("role id and role secret must both be specified")
		}
		resp, err := client.Auth.AppRoleLogin(context.Background(), creds, authReqOpts...)
		if err != nil {
			return nil, fmt.Errorf("approle authentication failure: %w", err)
		}
		if err := client.SetToken(resp.Auth.ClientToken); err != nil {
			return nil, fmt.Errorf("approle authentication set token failure: %w", err)
		}
	default:
		return nil, fmt.Errorf("vault authentication requires either roleid/rolesecret or root token")
	}

	secretStoragePath := strings.TrimSpace(cfg.SecretStoragePath)
	if secretStoragePath == "" {
		secretStoragePath = "iam"
	}

	return &VaultStore{
		client:            client,
		authReqOpts:       authReqOpts,
		kvReqOpts:         kvReqOpts,
		secretStoragePath: secretStoragePath,
		creds:             creds,
	}, nil
}

// reAuthIfNeeded attempts AppRole re-authentication when vault returns 403.
// It returns nil only when the original error was nil or re-auth succeeded.
func (s *VaultStore) reAuthIfNeeded(err error) error {
	if err == nil {
		return nil
	}
	if !vault.IsErrorStatus(err, http.StatusForbidden) {
		return err
	}
	resp, authErr := s.client.Auth.AppRoleLogin(context.Background(), s.creds, s.authReqOpts...)
	if authErr != nil {
		return fmt.Errorf("vault re-authentication failure: %w", authErr)
	}
	if err := s.client.SetToken(resp.Auth.ClientToken); err != nil {
		return fmt.Errorf("vault re-authentication set token failure: %w", err)
	}
	return nil
}

func (s *VaultStore) CreateUser(_ context.Context, user types.User) (*types.User, error) {
	userMap, err := userToVaultMap(user)
	if err != nil {
		return nil, fmt.Errorf("serialize user: %w", err)
	}

	path := s.secretStoragePath + "/" + user.UserName
	req := schema.KvV2WriteRequest{
		Data: map[string]any{user.UserName: userMap},
		Options: map[string]any{
			"cas": 0,
		},
	}

	_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return nil, iamerr.EntityAlreadyExistsUser(user.UserName)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		// retry once after re-auth
		_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return nil, iamerr.EntityAlreadyExistsUser(user.UserName)
			}
			if vault.IsErrorStatus(err, http.StatusForbidden) {
				return nil, fmt.Errorf("vault 403 permission denied on path %q. check KV mount path and policy. original: %w", path, err)
			}
			return nil, err
		}
	}
	return cloneUser(user), nil
}

func (s *VaultStore) DeleteUser(ctx context.Context, username string) error {
	if _, err := s.GetUser(ctx, username); err != nil {
		return err
	}
	return s.deleteByPath(username)
}

func (s *VaultStore) GetUser(_ context.Context, username string) (*types.User, error) {
	path := s.secretStoragePath + "/" + username
	resp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, iamerr.NoSuchEntityUser(username)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return nil, iamerr.NoSuchEntityUser(username)
			}
			return nil, err
		}
	}

	user, err := parseVaultUser(resp.Data.Data, username)
	if err != nil {
		return nil, err
	}
	return cloneUser(user), nil
}

func (s *VaultStore) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersOutput, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.secretStoragePath, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return &ListUsersOutput{Users: []types.User{}}, nil
		}
		reauthErr := s.reAuthIfNeeded(err)
		if reauthErr != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return &ListUsersOutput{Users: []types.User{}}, nil
			}
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.secretStoragePath, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return &ListUsersOutput{Users: []types.User{}}, nil
			}
			return nil, err
		}
	}

	users := make([]types.User, 0, len(resp.Data.Keys))
	for _, key := range resp.Data.Keys {
		user, err := s.GetUser(ctx, key)
		if err != nil {
			return nil, err
		}
		if input.PathPrefix != "" && !strings.HasPrefix(user.Path, input.PathPrefix) {
			continue
		}
		users = append(users, *user)
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].UserName < users[j].UserName
	})

	start := 0
	if input.Marker != "" {
		start = len(users)
		for i, user := range users {
			if user.UserName == input.Marker {
				start = i + 1
				break
			}
		}
	}
	users = users[start:]

	limit := len(users)
	if input.MaxItems > 0 && int(input.MaxItems) < limit {
		limit = int(input.MaxItems)
	}

	out := &ListUsersOutput{
		Users: make([]types.User, limit),
	}
	copy(out.Users, users[:limit])
	if limit < len(users) {
		out.IsTruncated = true
		out.Marker = out.Users[limit-1].UserName
	}

	return out, nil
}

func (s *VaultStore) UpdateUser(ctx context.Context, input UpdateUserInput) (*types.User, error) {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return nil, err
	}

	finalName := user.UserName
	if input.NewUserName != "" {
		finalName = input.NewUserName
	}

	if finalName != input.UserName {
		existing, err := s.GetUser(ctx, finalName)
		if err != nil && !errors.Is(err, iamerr.NoSuchEntityUser(finalName)) {
			return nil, err
		}
		if existing != nil {
			return nil, iamerr.EntityAlreadyExistsUser(finalName)
		}
	}

	if input.NewPath != "" {
		user.Path = input.NewPath
	}
	if input.NewUserName != "" {
		user.UserName = input.NewUserName
	}
	if input.NewArn != "" {
		user.Arn = input.NewArn
	}

	if user.UserName != input.UserName {
		// Create at new path first to detect conflicts before deleting the old entry.
		if _, err := s.CreateUser(ctx, *user); err != nil {
			return nil, err
		}
		if err := s.deleteByPath(input.UserName); err != nil {
			return nil, err
		}
	} else {
		// Delete all versions then re-create so CAS=0 succeeds.
		if err := s.deleteByPath(input.UserName); err != nil {
			return nil, err
		}
		if _, err := s.CreateUser(ctx, *user); err != nil {
			return nil, err
		}
	}

	return cloneUser(*user), nil
}

// deleteByPath permanently removes a secret and all its versions without
// checking for existence first.
func (s *VaultStore) deleteByPath(username string) error {
	path := s.secretStoragePath + "/" + username
	_, err := s.client.Secrets.KvV2DeleteMetadataAndAllVersions(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return reauthErr
		}
		_, err = s.client.Secrets.KvV2DeleteMetadataAndAllVersions(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}

var errInvalidVaultUser = errors.New("invalid user entry in vault secrets engine")

// userToVaultMap round-trips User through JSON to produce a map[string]any
// that vault can store without losing type information on read-back.
func userToVaultMap(user types.User) (map[string]any, error) {
	b, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseVaultUser reconstructs a User from the raw map[string]any that vault
// returns.  The outer key is the username.
func parseVaultUser(data map[string]any, username string) (types.User, error) {
	raw, ok := data[username]
	if !ok {
		return types.User{}, errInvalidVaultUser
	}
	userMap, ok := raw.(map[string]any)
	if !ok {
		return types.User{}, errInvalidVaultUser
	}
	b, err := json.Marshal(userMap)
	if err != nil {
		return types.User{}, fmt.Errorf("re-marshal vault user: %w", err)
	}
	var user types.User
	if err := json.Unmarshal(b, &user); err != nil {
		return types.User{}, fmt.Errorf("unmarshal vault user: %w", err)
	}
	return user, nil
}
