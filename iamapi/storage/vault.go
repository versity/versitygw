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
	"slices"
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

// findUserKey resolves name to the exact stored KV path segment (the
// original UserName casing used at creation), case-insensitively, by
// listing the users under secretStoragePath and comparing with EqualFold.
// AWS enforces case-insensitive UserName uniqueness but Vault's KV paths
// are plain case-sensitive strings, so a list+compare fallback is needed —
// KV has no native case-insensitive lookup. ok is false both when nothing
// matches and (harmlessly) when the prefix has no children at all.
func (s *VaultStore) findUserKey(name string) (string, bool, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.secretStoragePath, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return "", false, nil
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return "", false, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.secretStoragePath, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return "", false, nil
			}
			return "", false, err
		}
	}
	for _, key := range resp.Data.Keys {
		if strings.EqualFold(key, name) {
			return key, true, nil
		}
	}
	return "", false, nil
}

func (s *VaultStore) CreateUser(_ context.Context, user types.User) (*types.User, error) {
	if _, ok, err := s.findUserKey(user.UserName); err != nil {
		return nil, err
	} else if ok {
		return nil, iamerr.EntityAlreadyExistsUser(user.UserName)
	}

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
	user, err := s.GetUser(ctx, username)
	if err != nil {
		return err
	}
	if len(user.Policies.Inline) > 0 {
		return iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)
	}
	if len(user.AccessKeys) > 0 {
		return iamerr.GetAPIError(iamerr.ErrDeleteConflict)
	}
	return s.deleteByPath(user.UserName)
}

func (s *VaultStore) GetUser(_ context.Context, username string) (*types.User, error) {
	canonical, ok, err := s.findUserKey(username)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, iamerr.NoSuchEntityUser(username)
	}

	path := s.secretStoragePath + "/" + canonical
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

	user, err := parseVaultUser(resp.Data.Data, canonical)
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
	originalName := user.UserName

	finalName := user.UserName
	if input.NewUserName != "" {
		finalName = input.NewUserName
	}

	if !strings.EqualFold(finalName, originalName) {
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

	if user.UserName != originalName {
		// Create at new path first to detect conflicts before deleting the old entry.
		if _, err := s.CreateUser(ctx, *user); err != nil {
			return nil, err
		}
		if err := s.deleteByPath(originalName); err != nil {
			return nil, err
		}
	} else if _, err := s.replaceUser(ctx, *user); err != nil {
		return nil, err
	}

	return cloneUser(*user), nil
}

// replaceUser overwrites the stored document for user.UserName by deleting
// all existing versions and recreating with CAS=0.
func (s *VaultStore) replaceUser(ctx context.Context, user types.User) (*types.User, error) {
	if err := s.deleteByPath(user.UserName); err != nil {
		return nil, err
	}
	return s.CreateUser(ctx, user)
}

func (s *VaultStore) CreateAccessKey(ctx context.Context, input CreateAccessKeyInput) (*types.AccessKey, error) {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return nil, err
	}

	if len(user.AccessKeys) >= MaxAccessKeysPerUser {
		return nil, iamerr.AccessKeysLimitExceeded(MaxAccessKeysPerUser)
	}
	for _, key := range user.AccessKeys {
		if key.AccessKeyId == input.AccessKeyID {
			return nil, ErrAccessKeyIDAlreadyExists
		}
	}

	user.AccessKeys = append(user.AccessKeys, types.AccessKeyEntry{
		AccessKeyId:     input.AccessKeyID,
		SecretAccessKey: input.SecretAccessKey,
		Status:          input.Status,
		CreateDate:      input.CreateDate,
	})

	if _, err := s.replaceUser(ctx, *user); err != nil {
		return nil, err
	}

	return &types.AccessKey{
		UserName:        input.UserName,
		AccessKeyId:     input.AccessKeyID,
		Status:          input.Status,
		SecretAccessKey: input.SecretAccessKey,
		CreateDate:      input.CreateDate,
	}, nil
}

func (s *VaultStore) UpdateAccessKey(ctx context.Context, input UpdateAccessKeyInput) error {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return err
	}

	found := false
	for i, key := range user.AccessKeys {
		if key.AccessKeyId == input.AccessKeyID {
			user.AccessKeys[i].Status = input.Status
			found = true
			break
		}
	}
	if !found {
		return iamerr.NoSuchEntityAccessKey(input.AccessKeyID)
	}

	_, err = s.replaceUser(ctx, *user)
	return err
}

func (s *VaultStore) DeleteAccessKey(ctx context.Context, username, accessKeyID string) error {
	user, err := s.GetUser(ctx, username)
	if err != nil {
		return err
	}

	idx := -1
	for i, key := range user.AccessKeys {
		if key.AccessKeyId == accessKeyID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return iamerr.NoSuchEntityAccessKey(accessKeyID)
	}

	user.AccessKeys = slices.Delete(user.AccessKeys, idx, idx+1)

	_, err = s.replaceUser(ctx, *user)
	return err
}

func (s *VaultStore) GetAccessKeyLastUsed(ctx context.Context, accessKeyID string) (*GetAccessKeyLastUsedOutput, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.secretStoragePath, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.secretStoragePath, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
			}
			return nil, err
		}
	}

	for _, username := range resp.Data.Keys {
		user, err := s.GetUser(ctx, username)
		if err != nil {
			return nil, err
		}
		for _, key := range user.AccessKeys {
			if key.AccessKeyId == accessKeyID {
				return &GetAccessKeyLastUsedOutput{
					UserName:     username,
					LastUsedDate: key.LastUsedDate,
					ServiceName:  key.LastUsedService,
					Region:       key.LastUsedRegion,
				}, nil
			}
		}
	}

	return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
}

func (s *VaultStore) ListAccessKeys(ctx context.Context, input ListAccessKeysInput) (*ListAccessKeysOutput, error) {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return nil, err
	}

	keys := make([]types.AccessKeyMetadata, 0, len(user.AccessKeys))
	for _, key := range user.AccessKeys {
		keys = append(keys, types.AccessKeyMetadata{
			UserName:    input.UserName,
			AccessKeyId: key.AccessKeyId,
			Status:      key.Status,
			CreateDate:  key.CreateDate,
		})
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].AccessKeyId < keys[j].AccessKeyId
	})

	start := 0
	if input.Marker != "" {
		start = len(keys)
		for i, key := range keys {
			if key.AccessKeyId == input.Marker {
				start = i + 1
				break
			}
		}
	}
	keys = keys[start:]

	limit := len(keys)
	if input.MaxItems > 0 && int(input.MaxItems) < limit {
		limit = int(input.MaxItems)
	}

	out := &ListAccessKeysOutput{
		AccessKeys: make([]types.AccessKeyMetadata, limit),
	}
	copy(out.AccessKeys, keys[:limit])
	if limit < len(keys) {
		out.IsTruncated = true
		out.Marker = out.AccessKeys[limit-1].AccessKeyId
	}

	return out, nil
}

func (s *VaultStore) PutUserPolicy(ctx context.Context, input PutUserPolicyInput) error {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return err
	}

	newTotal := len(input.PolicyDocument)
	replaceAt := -1
	for i, p := range user.Policies.Inline {
		if p.PolicyName == input.PolicyName {
			replaceAt = i
			continue
		}
		newTotal += len(p.PolicyDocument)
	}
	if newTotal > MaxInlinePolicyBytesPerUser {
		return iamerr.InlinePolicyQuotaExceeded("user", input.UserName, MaxInlinePolicyBytesPerUser)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if replaceAt >= 0 {
		user.Policies.Inline[replaceAt].PolicyDocument = input.PolicyDocument
		user.Policies.Inline[replaceAt].UpdateDate = now
	} else {
		user.Policies.Inline = append(user.Policies.Inline, types.PolicyEntry{
			PolicyName:     input.PolicyName,
			PolicyDocument: input.PolicyDocument,
			CreateDate:     now,
			UpdateDate:     now,
		})
	}

	_, err = s.replaceUser(ctx, *user)
	return err
}

func (s *VaultStore) GetUserPolicy(ctx context.Context, userName, policyName string) (*types.PolicyEntry, error) {
	user, err := s.GetUser(ctx, userName)
	if err != nil {
		return nil, err
	}

	for _, p := range user.Policies.Inline {
		if p.PolicyName == policyName {
			cloned := p
			return &cloned, nil
		}
	}

	return nil, iamerr.NoSuchEntityUserPolicy(userName, policyName)
}

func (s *VaultStore) DeleteUserPolicy(ctx context.Context, userName, policyName string) error {
	user, err := s.GetUser(ctx, userName)
	if err != nil {
		return err
	}

	idx := -1
	for i, p := range user.Policies.Inline {
		if p.PolicyName == policyName {
			idx = i
			break
		}
	}
	if idx == -1 {
		return iamerr.NoSuchEntityUserPolicy(userName, policyName)
	}

	user.Policies.Inline = slices.Delete(user.Policies.Inline, idx, idx+1)

	_, err = s.replaceUser(ctx, *user)
	return err
}

func (s *VaultStore) ListUserPolicies(ctx context.Context, input ListUserPoliciesInput) (*ListUserPoliciesOutput, error) {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(user.Policies.Inline))
	for _, p := range user.Policies.Inline {
		names = append(names, p.PolicyName)
	}
	sort.Strings(names)

	start := 0
	if input.Marker != "" {
		start = len(names)
		for i, name := range names {
			if name == input.Marker {
				start = i + 1
				break
			}
		}
	}
	names = names[start:]

	limit := len(names)
	if input.MaxItems > 0 && int(input.MaxItems) < limit {
		limit = int(input.MaxItems)
	}

	out := &ListUserPoliciesOutput{
		PolicyNames: make([]string, limit),
	}
	copy(out.PolicyNames, names[:limit])
	if limit < len(names) {
		out.IsTruncated = true
		out.Marker = out.PolicyNames[limit-1]
	}

	return out, nil
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

// rolesPath is the KV prefix under which roles are stored, kept distinct
// from secretStoragePath (which holds users) so listing one entity kind
// never has to filter out the other's keys.
func (s *VaultStore) rolesPath() string {
	return s.secretStoragePath + "/roles"
}

// findRoleKey is findUserKey's counterpart for roles.
func (s *VaultStore) findRoleKey(name string) (string, bool, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.rolesPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return "", false, nil
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return "", false, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.rolesPath(), s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return "", false, nil
			}
			return "", false, err
		}
	}
	for _, key := range resp.Data.Keys {
		if strings.EqualFold(key, name) {
			return key, true, nil
		}
	}
	return "", false, nil
}

func (s *VaultStore) CreateRole(_ context.Context, role types.Role) (*types.Role, error) {
	if _, ok, err := s.findRoleKey(role.RoleName); err != nil {
		return nil, err
	} else if ok {
		return nil, iamerr.EntityAlreadyExistsRole(role.RoleName)
	}

	role.EnsureRoleLastUsed()

	roleMap, err := roleToVaultMap(role)
	if err != nil {
		return nil, fmt.Errorf("serialize role: %w", err)
	}

	path := s.rolesPath() + "/" + role.RoleName
	req := schema.KvV2WriteRequest{
		Data: map[string]any{role.RoleName: roleMap},
		Options: map[string]any{
			"cas": 0,
		},
	}

	_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return nil, iamerr.EntityAlreadyExistsRole(role.RoleName)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		// retry once after re-auth
		_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return nil, iamerr.EntityAlreadyExistsRole(role.RoleName)
			}
			if vault.IsErrorStatus(err, http.StatusForbidden) {
				return nil, fmt.Errorf("vault 403 permission denied on path %q. check KV mount path and policy. original: %w", path, err)
			}
			return nil, err
		}
	}
	return cloneRole(role), nil
}

func (s *VaultStore) GetRole(_ context.Context, roleName string) (*types.Role, error) {
	canonical, ok, err := s.findRoleKey(roleName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, iamerr.NoSuchEntityRole(roleName)
	}

	path := s.rolesPath() + "/" + canonical
	resp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, iamerr.NoSuchEntityRole(roleName)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return nil, iamerr.NoSuchEntityRole(roleName)
			}
			return nil, err
		}
	}

	role, err := parseVaultRole(resp.Data.Data, canonical)
	if err != nil {
		return nil, err
	}
	return cloneRole(role), nil
}

func (s *VaultStore) ListRoles(ctx context.Context, input ListRolesInput) (*ListRolesOutput, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.rolesPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return &ListRolesOutput{Roles: []types.Role{}}, nil
		}
		reauthErr := s.reAuthIfNeeded(err)
		if reauthErr != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return &ListRolesOutput{Roles: []types.Role{}}, nil
			}
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.rolesPath(), s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return &ListRolesOutput{Roles: []types.Role{}}, nil
			}
			return nil, err
		}
	}

	roles := make([]types.Role, 0, len(resp.Data.Keys))
	for _, key := range resp.Data.Keys {
		role, err := s.GetRole(ctx, key)
		if err != nil {
			return nil, err
		}
		if input.PathPrefix != "" && !strings.HasPrefix(role.Path, input.PathPrefix) {
			continue
		}
		// ListRoles entries omit RoleLastUsed even though GetRole (reused
		// above to fetch each entry) attaches it — matches the documented
		// list/get field asymmetry.
		role.RoleLastUsed = nil
		roles = append(roles, *role)
	}

	sort.Slice(roles, func(i, j int) bool {
		return roles[i].RoleName < roles[j].RoleName
	})

	start := 0
	if input.Marker != "" {
		start = len(roles)
		for i, role := range roles {
			if role.RoleName == input.Marker {
				start = i + 1
				break
			}
		}
	}
	roles = roles[start:]

	limit := len(roles)
	if input.MaxItems > 0 && int(input.MaxItems) < limit {
		limit = int(input.MaxItems)
	}

	out := &ListRolesOutput{
		Roles: make([]types.Role, limit),
	}
	copy(out.Roles, roles[:limit])
	if limit < len(roles) {
		out.IsTruncated = true
		out.Marker = out.Roles[limit-1].RoleName
	}

	return out, nil
}

func (s *VaultStore) DeleteRole(ctx context.Context, roleName string) error {
	role, err := s.GetRole(ctx, roleName)
	if err != nil {
		return err
	}
	if len(role.Policies.Inline) > 0 {
		return iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)
	}
	return s.deleteRoleByPath(role.RoleName)
}

func (s *VaultStore) UpdateAssumeRolePolicy(ctx context.Context, input UpdateAssumeRolePolicyInput) (*types.Role, error) {
	role, err := s.GetRole(ctx, input.RoleName)
	if err != nil {
		return nil, err
	}
	role.AssumeRolePolicyDocument = input.PolicyDocument

	return s.replaceRole(ctx, *role)
}

// replaceRole overwrites the stored document for role.RoleName by deleting
// all existing versions and recreating with CAS=0.
func (s *VaultStore) replaceRole(ctx context.Context, role types.Role) (*types.Role, error) {
	if err := s.deleteRoleByPath(role.RoleName); err != nil {
		return nil, err
	}
	return s.CreateRole(ctx, role)
}

// deleteRoleByPath permanently removes a role secret and all its versions
// without checking for existence first.
func (s *VaultStore) deleteRoleByPath(roleName string) error {
	path := s.rolesPath() + "/" + roleName
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

var errInvalidVaultRole = errors.New("invalid role entry in vault secrets engine")

// roleToVaultMap is userToVaultMap's counterpart for roles.
func roleToVaultMap(role types.Role) (map[string]any, error) {
	b, err := json.Marshal(role)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseVaultRole reconstructs a Role from the raw map[string]any that vault
// returns. The outer key is the role name.
func parseVaultRole(data map[string]any, roleName string) (types.Role, error) {
	raw, ok := data[roleName]
	if !ok {
		return types.Role{}, errInvalidVaultRole
	}
	roleMap, ok := raw.(map[string]any)
	if !ok {
		return types.Role{}, errInvalidVaultRole
	}
	b, err := json.Marshal(roleMap)
	if err != nil {
		return types.Role{}, fmt.Errorf("re-marshal vault role: %w", err)
	}
	var role types.Role
	if err := json.Unmarshal(b, &role); err != nil {
		return types.Role{}, fmt.Errorf("unmarshal vault role: %w", err)
	}
	return role, nil
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
