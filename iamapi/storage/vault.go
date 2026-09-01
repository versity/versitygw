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
	"encoding/base64"
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
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

const vaultRequestTimeout = 10 * time.Second

// maxCASRetries bounds the read-modify-write retry loop withUserCAS/
// withRoleCAS/withOIDCProviderCAS run when a version-checked (CAS) write
// loses a race against a concurrent writer updating the same entity —
// mirroring the 3-attempt collision-retry loops already used elsewhere in
// this package for ID generation.
const maxCASRetries = 3

// errConcurrentModification is withUserCAS/withRoleCAS/withOIDCProviderCAS's
// internal signal that a replace* call's CAS write lost a race against
// another writer and should be retried; it never escapes to a caller
// directly — once retries are exhausted it's surfaced as
// iamerr.ConcurrentModification(), matching real IAM's documented
// ConcurrentModificationException.
var errConcurrentModification = errors.New("iamapi: concurrent modification")

// errRenameCleanupFailed marks an error from deleteOldUserAfterRename: the
// rename's new record was created successfully, but deleting the stale
// record at the old name failed even after retrying (see
// renameDeleteRetries). It is surfaced only via errors.Is/wrapping —
// Vault's KV store has no multi-key transaction to make the two writes
// atomic, so this signals a state that needs operator attention rather than
// one an automatic retry of the whole operation can resolve (a caller
// retrying UpdateUser from scratch would now fail with EntityAlreadyExists
// against the very record it just created).
var errRenameCleanupFailed = errors.New("iamapi: rename cleanup failed")

// kvVersion extracts a KV v2 secret version from a read response's metadata
// map. The generated schema client types Metadata as map[string]interface{},
// but vault-client-go decodes its JSON body with a decoder configured to
// produce json.Number for numeric fields, not float64 — a plain
// metadata["version"].(float64) assertion never matches, so it silently fell
// through to the zero value on every call. Every version-checked (CAS)
// write's readVersion was therefore always 0 — the "create if it doesn't
// exist yet" sentinel — so any write to an already-existing document (i.e.
// every one of them past its first) sent cas:0 and was unconditionally
// rejected by Vault as a check-and-set mismatch. That surfaced as
// ConcurrentModificationException on withUserCAS/withRoleCAS/
// withOIDCProviderCAS's every retry, deterministically, with no concurrent
// writer involved at all — confirmed by reproducing it single-threaded
// against a live Vault (CreateRole then PutRolePolicy, nothing else
// touching the record, still failed every time before this fix).
func kvVersion(metadata map[string]any) int32 {
	switch v := metadata["version"].(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int32(n)
		}
	case float64:
		return int32(v)
	}
	return 0
}

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

// usersPath is the KV prefix under which users are stored, kept distinct
// from rolesPath/oidcProvidersPath/sessionsPath — mirroring their own
// isolation rationale — so listing users never picks up a sibling entity
// type's directory marker (e.g. "roles/") as if it were a username.
func (s *VaultStore) usersPath() string {
	return s.secretStoragePath + "/users"
}

// caseFoldKey case-folds name to the KV path segment (and inner data map
// key) an identity of that name is stored under. AWS enforces
// case-insensitive uniqueness for IAM names (UserName, RoleName) but
// Vault's KV paths are plain case-sensitive strings; storing every identity
// under its case-folded name — rather than the as-given casing, resolved by
// a separate list-and-compare lookup — makes uniqueness a property Vault's
// own CAS write enforces atomically, instead of a check-then-write race
// between two callers using different casings of the same name (e.g.
// "Alice" and "alice" both passing a list-based existence check and then
// both succeeding at CAS 0 on two different paths). The original,
// as-given casing is preserved in the identity's own UserName/RoleName
// field within the stored document.
func caseFoldKey(name string) string {
	return strings.ToLower(name)
}

func (s *VaultStore) CreateUser(_ context.Context, user types.User) (*types.User, error) {
	key := caseFoldKey(user.UserName)

	userMap, err := userToVaultMap(user)
	if err != nil {
		return nil, fmt.Errorf("serialize user: %w", err)
	}

	path := s.usersPath() + "/" + key
	req := schema.KvV2WriteRequest{
		Data: map[string]any{key: userMap},
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

// DeleteUser checks user against its dependency preconditions (no inline
// policies, no access keys) and then deletes it. The metadata-delete call
// Vault exposes has no CAS parameter of its own (unlike a KV write), so a
// plain read-check-then-delete would leave a window where a concurrent
// CreateAccessKey or PutUserPolicy lands between the check and the delete,
// and the delete proceeds anyway, orphaning the new key/policy against a
// user that no longer exists. Closing that window: after the
// dependency check, replaceUser writes the same (unchanged) record back
// with a CAS matching the version just read — succeeding only if nothing
// else has modified the record since — immediately before the actual
// delete, shrinking the race to the gap between two back-to-back Vault
// calls instead of the whole request lifecycle. A CAS conflict there means
// something changed after the check, so the whole check is retried
// (bounded by maxCASRetries) rather than deleting against stale
// information.
func (s *VaultStore) DeleteUser(ctx context.Context, username string) error {
	for range maxCASRetries {
		user, version, err := s.readUserVersion(username)
		if err != nil {
			return err
		}
		if len(user.Policies.Inline) > 0 {
			return iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)
		}
		if len(user.AccessKeys) > 0 {
			return iamerr.GetAPIError(iamerr.ErrDeleteConflict)
		}

		if _, err := s.replaceUser(ctx, *user, version); err != nil {
			if errors.Is(err, errConcurrentModification) {
				continue
			}
			return err
		}

		return s.deleteByPath("users/" + caseFoldKey(user.UserName))
	}
	return iamerr.ConcurrentModification()
}

func (s *VaultStore) GetUser(_ context.Context, username string) (*types.User, error) {
	user, _, err := s.readUserVersion(username)
	return user, err
}

// readUserVersion resolves username the same way GetUser does, additionally
// returning the KV version the record was read at, so a mutation can write
// back with a matching CAS value instead of racing on a blind
// delete-then-recreate.
func (s *VaultStore) readUserVersion(username string) (*types.User, int32, error) {
	key := caseFoldKey(username)
	path := s.usersPath() + "/" + key
	resp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, 0, iamerr.NoSuchEntityUser(username)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, 0, reauthErr
		}
		resp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return nil, 0, iamerr.NoSuchEntityUser(username)
			}
			return nil, 0, err
		}
	}

	user, err := parseVaultUser(resp.Data.Data, key)
	if err != nil {
		return nil, 0, err
	}
	return cloneUser(user), kvVersion(resp.Data.Metadata), nil
}

// GetUserByAccessKeyID has no index to consult (unlike InternalStore's
// AccessKeyIndex) so it scans every user's access keys, mirroring
// GetAccessKeyLastUsed's existing linear scan.
func (s *VaultStore) GetUserByAccessKeyID(ctx context.Context, accessKeyID string) (*types.User, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.usersPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.usersPath(), s.kvReqOpts...)
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
				return user, nil
			}
		}
	}

	return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
}

func (s *VaultStore) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersOutput, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.usersPath(), s.kvReqOpts...)
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
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.usersPath(), s.kvReqOpts...)
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
	user, version, err := s.readUserVersion(input.UserName)
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

	if caseFoldKey(user.UserName) != caseFoldKey(originalName) {
		// A genuine rename to a different case-folded key (and therefore a
		// different KV path): create at the new path first — its cas:0
		// write atomically detects a conflict, including one from a
		// concurrent create/rename racing for the same new name — before
		// deleting the old entry. A UserName change that's case-only (e.g.
		// "Alice" -> "alice") case-folds to the *same* path, so it's handled
		// below as an in-place update instead: routing it through
		// CreateUser here would spuriously fail with EntityAlreadyExists
		// against the very record being renamed.
		if _, err := s.CreateUser(ctx, *user); err != nil {
			return nil, err
		}
		if err := s.deleteOldUserAfterRename(originalName); err != nil {
			return nil, err
		}
	} else if _, err := s.replaceUser(ctx, *user, version); err != nil {
		return nil, err
	}

	return cloneUser(*user), nil
}

// renameDeleteRetries bounds deleteOldUserAfterRename's retries of the
// old-path delete that follows a successful create-at-new-path during a
// rename (roles have no rename operation, so only users need this). Vault
// has no multi-key transaction to make "create new, delete old" atomic, so
// a delete failure here (after the new record already exists) is the one
// window where two live records for the same identity can coexist;
// retrying a bounded number of times, with a short backoff, absorbs a
// transient failure (network blip, momentary 403) rather than leaving that
// window open on the first error.
const (
	renameDeleteRetries = 3
	renameDeleteBackoff = 200 * time.Millisecond
)

// deleteOldUserAfterRename deletes the pre-rename user record at
// originalName after UpdateUser has already created the record at its new
// name, retrying up to renameDeleteRetries times. If every attempt fails,
// the error returned wraps errRenameCleanupFailed so callers/operators can
// recognize that the new record was created and the stale record at
// originalName still exists and needs manual removal — better than
// masking that state as an ordinary write error.
func (s *VaultStore) deleteOldUserAfterRename(originalName string) error {
	var err error
	for attempt := range renameDeleteRetries {
		if attempt > 0 {
			time.Sleep(renameDeleteBackoff)
		}
		if err = s.deleteByPath("users/" + caseFoldKey(originalName)); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: stale user record %q must be removed manually: %v", errRenameCleanupFailed, originalName, err)
}

// replaceUser overwrites the stored document for user.UserName using a
// version-checked (CAS) write tied to readVersion — the KV version the
// caller most recently read the record at — instead of an unconditional
// delete-then-recreate. This way, two concurrent updates to the same user
// (e.g. a DeleteAccessKey revocation racing a PutUserPolicy call) can't
// have the second writer silently discard the first writer's change: a CAS
// mismatch fails with errConcurrentModification, for withUserCAS to retry.
func (s *VaultStore) replaceUser(ctx context.Context, user types.User, readVersion int32) (*types.User, error) {
	userMap, err := userToVaultMap(user)
	if err != nil {
		return nil, fmt.Errorf("serialize user: %w", err)
	}

	key := caseFoldKey(user.UserName)
	path := s.usersPath() + "/" + key
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{key: userMap},
		Options: map[string]any{"cas": readVersion},
	}

	_, err = s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return nil, errConcurrentModification
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		_, err = s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return nil, errConcurrentModification
			}
			return nil, err
		}
	}
	return cloneUser(user), nil
}

// withUserCAS resolves username, applies mutate to the fetched user, and
// writes it back with a CAS matching the version it was read at, retrying
// (bounded by maxCASRetries) if a concurrent writer's update lands first —
// closing the lost-update race described in replaceUser's doc comment.
// mutate's own error (e.g. a quota or not-found error) is returned
// immediately, never retried — only a genuine CAS conflict is.
func (s *VaultStore) withUserCAS(ctx context.Context, username string, mutate func(*types.User) error) (*types.User, error) {
	for range maxCASRetries {
		user, version, err := s.readUserVersion(username)
		if err != nil {
			return nil, err
		}
		if err := mutate(user); err != nil {
			return nil, err
		}
		result, err := s.replaceUser(ctx, *user, version)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, errConcurrentModification) {
			return nil, err
		}
	}
	return nil, iamerr.ConcurrentModification()
}

func (s *VaultStore) TagUser(ctx context.Context, userName string, tags []types.Tag) error {
	_, err := s.withUserCAS(ctx, userName, func(user *types.User) error {
		merged, err := mergeTags(user.Tags, tags, iamutil.TagKeysFolded)
		if err != nil {
			return err
		}
		user.Tags = merged
		return nil
	})
	return err
}

func (s *VaultStore) UntagUser(ctx context.Context, userName string, tagKeys []string) error {
	_, err := s.withUserCAS(ctx, userName, func(user *types.User) error {
		user.Tags = removeTags(user.Tags, tagKeys, iamutil.TagKeysFolded)
		return nil
	})
	return err
}

func (s *VaultStore) ListUserTags(ctx context.Context, input ListUserTagsInput) (*ListTagsOutput, error) {
	user, err := s.GetUser(ctx, input.UserName)
	if err != nil {
		return nil, err
	}

	return paginateTags(user.Tags, input.Marker, input.MaxItems, iamutil.TagKeysFolded), nil
}

func (s *VaultStore) CreateAccessKey(ctx context.Context, input CreateAccessKeyInput) (*types.AccessKey, error) {
	var created types.AccessKey
	if _, err := s.withUserCAS(ctx, input.UserName, func(user *types.User) error {
		if len(user.AccessKeys) >= MaxAccessKeysPerUser {
			return iamerr.AccessKeysLimitExceeded(MaxAccessKeysPerUser)
		}
		for _, key := range user.AccessKeys {
			if key.AccessKeyId == input.AccessKeyID {
				return ErrAccessKeyIDAlreadyExists
			}
		}

		user.AccessKeys = append(user.AccessKeys, types.AccessKeyEntry{
			AccessKeyId:     input.AccessKeyID,
			SecretAccessKey: input.SecretAccessKey,
			Status:          input.Status,
			CreateDate:      input.CreateDate,
		})
		created = types.AccessKey{
			UserName:        input.UserName,
			AccessKeyId:     input.AccessKeyID,
			Status:          input.Status,
			SecretAccessKey: input.SecretAccessKey,
			CreateDate:      input.CreateDate,
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &created, nil
}

func (s *VaultStore) UpdateAccessKey(ctx context.Context, input UpdateAccessKeyInput) error {
	_, err := s.withUserCAS(ctx, input.UserName, func(user *types.User) error {
		for i, key := range user.AccessKeys {
			if key.AccessKeyId == input.AccessKeyID {
				user.AccessKeys[i].Status = input.Status
				return nil
			}
		}
		return iamerr.NoSuchEntityAccessKey(input.AccessKeyID)
	})
	return err
}

func (s *VaultStore) DeleteAccessKey(ctx context.Context, username, accessKeyID string) error {
	_, err := s.withUserCAS(ctx, username, func(user *types.User) error {
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
		return nil
	})
	return err
}

func (s *VaultStore) GetAccessKeyLastUsed(ctx context.Context, accessKeyID string) (*GetAccessKeyLastUsedOutput, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.usersPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.usersPath(), s.kvReqOpts...)
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
					UserName:     user.UserName,
					LastUsedDate: key.LastUsedDate,
					ServiceName:  key.LastUsedService,
					Region:       key.LastUsedRegion,
				}, nil
			}
		}
	}

	return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
}

// recordAccessKeyUsageTimeout bounds RecordAccessKeyUsage's detached
// background update.
const recordAccessKeyUsageTimeout = 5 * time.Second

// RecordAccessKeyUsage updates accessKeyID's GetAccessKeyLastUsed metadata
// in its own background goroutine, detached from ctx, and always returns
// nil immediately: this runs on the hot path of every authenticated
// request, and a Vault round trip — plus, on a CAS conflict, withUserCAS's
// retry loop — is too expensive to add synchronously to every one of them.
// A failure (including one that exhausts those retries) is only logged,
// never surfaced: this is purely informational metadata, and a lost update
// under concurrent use is immaterial.
func (s *VaultStore) RecordAccessKeyUsage(_ context.Context, accessKeyID, service, region string, when time.Time) error {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), recordAccessKeyUsageTimeout)
		defer cancel()
		if err := s.recordAccessKeyUsage(ctx, accessKeyID, service, region, when); err != nil {
			debuglogger.Logf("failed to record Vault access key last-used metadata for %q: %v", accessKeyID, err)
		}
	}()
	return nil
}

func (s *VaultStore) recordAccessKeyUsage(ctx context.Context, accessKeyID, service, region string, when time.Time) error {
	resp, err := s.client.Secrets.KvV2List(ctx, s.usersPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return iamerr.NoSuchEntityAccessKey(accessKeyID)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(ctx, s.usersPath(), s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return iamerr.NoSuchEntityAccessKey(accessKeyID)
			}
			return err
		}
	}

	for _, username := range resp.Data.Keys {
		user, err := s.GetUser(ctx, username)
		if err != nil {
			continue
		}
		idx := slices.IndexFunc(user.AccessKeys, func(k types.AccessKeyEntry) bool { return k.AccessKeyId == accessKeyID })
		if idx == -1 {
			continue
		}

		// The user was just read, so the redundant-update check costs
		// nothing here and saves the read-modify-write below on every
		// request after the first within the coalescing window.
		key := user.AccessKeys[idx]
		if !shouldRecordUsage(key.LastUsedDate, key.LastUsedService, key.LastUsedRegion, service, region, when) {
			return nil
		}

		_, err = s.withUserCAS(ctx, username, func(u *types.User) error {
			for i, key := range u.AccessKeys {
				if key.AccessKeyId == accessKeyID {
					u.AccessKeys[i].LastUsedDate = when
					u.AccessKeys[i].LastUsedService = service
					u.AccessKeys[i].LastUsedRegion = region
					return nil
				}
			}
			return iamerr.NoSuchEntityAccessKey(accessKeyID)
		})
		return err
	}

	return iamerr.NoSuchEntityAccessKey(accessKeyID)
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
	_, err := s.withUserCAS(ctx, input.UserName, func(user *types.User) error {
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
		return nil
	})
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
	_, err := s.withUserCAS(ctx, userName, func(user *types.User) error {
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
		return nil
	})
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
// checking for existence first. relPath is relative to secretStoragePath
// (e.g. "users/alice" or "sessions/AKIA...").
func (s *VaultStore) deleteByPath(relPath string) error {
	path := s.secretStoragePath + "/" + relPath
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
// from usersPath so listing one entity kind never has to filter out the
// other's keys.
func (s *VaultStore) rolesPath() string {
	return s.secretStoragePath + "/roles"
}

func (s *VaultStore) CreateRole(_ context.Context, role types.Role) (*types.Role, error) {
	key := caseFoldKey(role.RoleName)

	role.EnsureRoleLastUsed()

	roleMap, err := roleToVaultMap(role)
	if err != nil {
		return nil, fmt.Errorf("serialize role: %w", err)
	}

	path := s.rolesPath() + "/" + key
	req := schema.KvV2WriteRequest{
		Data: map[string]any{key: roleMap},
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
	role, _, err := s.readRoleVersion(roleName)
	return role, err
}

// readRoleVersion is GetRole's counterpart to readUserVersion: it
// additionally returns the KV version the record was read at, so a
// mutation can write back with a matching CAS value instead of racing on a
// blind delete-then-recreate.
func (s *VaultStore) readRoleVersion(roleName string) (*types.Role, int32, error) {
	key := caseFoldKey(roleName)
	path := s.rolesPath() + "/" + key
	resp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, 0, iamerr.NoSuchEntityRole(roleName)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, 0, reauthErr
		}
		resp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return nil, 0, iamerr.NoSuchEntityRole(roleName)
			}
			return nil, 0, err
		}
	}

	role, err := parseVaultRole(resp.Data.Data, key)
	if err != nil {
		return nil, 0, err
	}
	return cloneRole(role), kvVersion(resp.Data.Metadata), nil
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

// DeleteRole is DeleteUser's counterpart for roles - see its doc comment for
// why the dependency check (no inline policies) is confirmed via a same-data
// CAS write (replaceRole) immediately before the actual delete, instead of
// an unconditional delete straight after the check.
func (s *VaultStore) DeleteRole(ctx context.Context, roleName string) error {
	for range maxCASRetries {
		role, version, err := s.readRoleVersion(roleName)
		if err != nil {
			return err
		}
		if len(role.Policies.Inline) > 0 {
			return iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)
		}

		if _, err := s.replaceRole(ctx, *role, version); err != nil {
			if errors.Is(err, errConcurrentModification) {
				continue
			}
			return err
		}

		return s.deleteRoleByPath(role.RoleName)
	}
	return iamerr.ConcurrentModification()
}

func (s *VaultStore) UpdateAssumeRolePolicy(ctx context.Context, input UpdateAssumeRolePolicyInput) (*types.Role, error) {
	return s.withRoleCAS(ctx, input.RoleName, func(role *types.Role) error {
		role.AssumeRolePolicyDocument = input.PolicyDocument
		return nil
	})
}

// recordRoleUsageTimeout bounds RecordRoleUsage's detached background
// update, the way recordAccessKeyUsageTimeout does for access keys.
const recordRoleUsageTimeout = 5 * time.Second

// RecordRoleUsage updates roleName's RoleLastUsed metadata in its own
// background goroutine, detached from ctx, and always returns nil
// immediately — for the same reasons RecordAccessKeyUsage does: it runs on
// the hot path of every request authenticated with a session credential,
// and the metadata is purely informational, so a Vault round trip (plus a
// CAS retry loop) must not be charged to the request, and a lost or failed
// update is only logged.
func (s *VaultStore) RecordRoleUsage(_ context.Context, roleName, region string, when time.Time) error {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), recordRoleUsageTimeout)
		defer cancel()
		if err := s.recordRoleUsage(ctx, roleName, region, when); err != nil {
			debuglogger.Logf("failed to record Vault role last-used metadata for %q: %v", roleName, err)
		}
	}()
	return nil
}

func (s *VaultStore) recordRoleUsage(ctx context.Context, roleName, region string, when time.Time) error {
	role, _, err := s.readRoleVersion(roleName)
	if err != nil {
		return err
	}

	// A redundant update is dropped after the read, before the far more
	// expensive read-modify-write — see shouldRecordUsage.
	prev, prevRegion := roleLastUsedRecord(*role)
	if !shouldRecordUsage(prev, "", prevRegion, "", region, when) {
		return nil
	}

	_, err = s.withRoleCAS(ctx, roleName, func(role *types.Role) error {
		role.RoleLastUsed = &types.RoleLastUsed{
			LastUsedDate: &when,
			Region:       region,
		}
		return nil
	})
	return err
}

func (s *VaultStore) TagRole(ctx context.Context, roleName string, tags []types.Tag) error {
	_, err := s.withRoleCAS(ctx, roleName, func(role *types.Role) error {
		merged, err := mergeTags(role.Tags, tags, iamutil.TagKeysFolded)
		if err != nil {
			return err
		}
		role.Tags = merged
		return nil
	})
	return err
}

func (s *VaultStore) UntagRole(ctx context.Context, roleName string, tagKeys []string) error {
	_, err := s.withRoleCAS(ctx, roleName, func(role *types.Role) error {
		role.Tags = removeTags(role.Tags, tagKeys, iamutil.TagKeysFolded)
		return nil
	})
	return err
}

func (s *VaultStore) ListRoleTags(ctx context.Context, input ListRoleTagsInput) (*ListTagsOutput, error) {
	role, err := s.GetRole(ctx, input.RoleName)
	if err != nil {
		return nil, err
	}

	return paginateTags(role.Tags, input.Marker, input.MaxItems, iamutil.TagKeysFolded), nil
}

func (s *VaultStore) PutRolePolicy(ctx context.Context, input PutRolePolicyInput) error {
	_, err := s.withRoleCAS(ctx, input.RoleName, func(role *types.Role) error {
		newTotal := len(input.PolicyDocument)
		replaceAt := -1
		for i, p := range role.Policies.Inline {
			if p.PolicyName == input.PolicyName {
				replaceAt = i
				continue
			}
			newTotal += len(p.PolicyDocument)
		}
		if newTotal > MaxInlinePolicyBytesPerRole {
			return iamerr.InlinePolicyQuotaExceeded("role", input.RoleName, MaxInlinePolicyBytesPerRole)
		}

		now := time.Now().UTC().Truncate(time.Second)
		if replaceAt >= 0 {
			role.Policies.Inline[replaceAt].PolicyDocument = input.PolicyDocument
			role.Policies.Inline[replaceAt].UpdateDate = now
		} else {
			role.Policies.Inline = append(role.Policies.Inline, types.PolicyEntry{
				PolicyName:     input.PolicyName,
				PolicyDocument: input.PolicyDocument,
				CreateDate:     now,
				UpdateDate:     now,
			})
		}
		return nil
	})
	return err
}

func (s *VaultStore) GetRolePolicy(ctx context.Context, roleName, policyName string) (*types.PolicyEntry, error) {
	role, err := s.GetRole(ctx, roleName)
	if err != nil {
		return nil, err
	}

	for _, p := range role.Policies.Inline {
		if p.PolicyName == policyName {
			cloned := p
			return &cloned, nil
		}
	}

	return nil, iamerr.NoSuchEntityRolePolicy(roleName, policyName)
}

func (s *VaultStore) DeleteRolePolicy(ctx context.Context, roleName, policyName string) error {
	_, err := s.withRoleCAS(ctx, roleName, func(role *types.Role) error {
		idx := -1
		for i, p := range role.Policies.Inline {
			if p.PolicyName == policyName {
				idx = i
				break
			}
		}
		if idx == -1 {
			return iamerr.NoSuchEntityRolePolicy(roleName, policyName)
		}
		role.Policies.Inline = slices.Delete(role.Policies.Inline, idx, idx+1)
		return nil
	})
	return err
}

func (s *VaultStore) ListRolePolicies(ctx context.Context, input ListRolePoliciesInput) (*ListRolePoliciesOutput, error) {
	role, err := s.GetRole(ctx, input.RoleName)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(role.Policies.Inline))
	for _, p := range role.Policies.Inline {
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

	out := &ListRolePoliciesOutput{
		PolicyNames: make([]string, limit),
	}
	copy(out.PolicyNames, names[:limit])
	if limit < len(names) {
		out.IsTruncated = true
		out.Marker = out.PolicyNames[limit-1]
	}

	return out, nil
}

// replaceRole overwrites the stored document for role.RoleName using a
// version-checked (CAS) write tied to readVersion, instead of an
// unconditional delete-then-recreate — see replaceUser for the rationale.
func (s *VaultStore) replaceRole(ctx context.Context, role types.Role, readVersion int32) (*types.Role, error) {
	roleMap, err := roleToVaultMap(role)
	if err != nil {
		return nil, fmt.Errorf("serialize role: %w", err)
	}

	key := caseFoldKey(role.RoleName)
	path := s.rolesPath() + "/" + key
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{key: roleMap},
		Options: map[string]any{"cas": readVersion},
	}

	_, err = s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return nil, errConcurrentModification
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		_, err = s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return nil, errConcurrentModification
			}
			return nil, err
		}
	}
	return cloneRole(role), nil
}

// withRoleCAS is withUserCAS's counterpart for roles.
func (s *VaultStore) withRoleCAS(ctx context.Context, roleName string, mutate func(*types.Role) error) (*types.Role, error) {
	for range maxCASRetries {
		role, version, err := s.readRoleVersion(roleName)
		if err != nil {
			return nil, err
		}
		if err := mutate(role); err != nil {
			return nil, err
		}
		result, err := s.replaceRole(ctx, *role, version)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, errConcurrentModification) {
			return nil, err
		}
	}
	return nil, iamerr.ConcurrentModification()
}

// deleteRoleByPath permanently removes a role secret and all its versions
// without checking for existence first.
func (s *VaultStore) deleteRoleByPath(roleName string) error {
	path := s.rolesPath() + "/" + caseFoldKey(roleName)
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

// oidcProvidersPath is the KV prefix under which OIDC providers are stored,
// kept distinct from secretStoragePath/rolesPath.
func (s *VaultStore) oidcProvidersPath() string {
	return s.secretStoragePath + "/oidc-providers"
}

// oidcProviderPathSegment returns the literal KV path segment for a
// provider identified by its scheme-stripped url. OIDC provider URLs may
// themselves contain "/" (e.g. "host/" and "host/path" are distinct valid
// providers) and Vault KV paths treat "/" as a path
// separator, so — unlike RoleName/UserName, which never contain "/" and are
// used as literal path segments directly — the raw url cannot safely be
// used as a KV path segment. base64url-encoding (RawURLEncoding: lossless,
// produces only [A-Za-z0-9_-], no "/" or "=" padding) collapses it to one
// opaque, path-safe segment. The same segment is reused as the single outer
// JSON key inside the KV secret body (a deliberate deviation from
// roleToVaultMap/userToVaultMap's convention of keying on the
// human-readable name — simpler here since only one identifier needs to be
// tracked for read-back, not two).
func oidcProviderPathSegment(url string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(url))
}

func (s *VaultStore) CreateOIDCProvider(_ context.Context, provider types.OIDCProvider) (*types.OIDCProvider, error) {
	segment := oidcProviderPathSegment(provider.Url)
	path := s.oidcProvidersPath() + "/" + segment
	displayURL := "https://" + provider.Url

	resp, err := s.client.Secrets.KvV2List(context.Background(), s.oidcProvidersPath(), s.kvReqOpts...)
	if err != nil && !vault.IsErrorStatus(err, http.StatusNotFound) {
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.oidcProvidersPath(), s.kvReqOpts...)
		if err != nil && !vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, err
		}
	}
	if resp != nil {
		if slices.Contains(resp.Data.Keys, segment) {
			return nil, iamerr.EntityAlreadyExistsOIDCProvider(displayURL)
		}
		if len(resp.Data.Keys) >= MaxOIDCProvidersPerAccount {
			return nil, iamerr.OIDCProvidersPerAccountLimitExceeded(MaxOIDCProvidersPerAccount)
		}
	}

	providerMap, err := oidcProviderToVaultMap(provider)
	if err != nil {
		return nil, fmt.Errorf("serialize oidc provider: %w", err)
	}
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{segment: providerMap},
		Options: map[string]any{"cas": 0},
	}

	_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return nil, iamerr.EntityAlreadyExistsOIDCProvider(displayURL)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return nil, iamerr.EntityAlreadyExistsOIDCProvider(displayURL)
			}
			if vault.IsErrorStatus(err, http.StatusForbidden) {
				return nil, fmt.Errorf("vault 403 permission denied on path %q. check KV mount path and policy. original: %w", path, err)
			}
			return nil, err
		}
	}
	return cloneOIDCProvider(provider), nil
}

func (s *VaultStore) GetOIDCProvider(_ context.Context, arn string) (*types.OIDCProvider, error) {
	provider, _, err := s.readOIDCProviderVersion(arn, iamerr.NoSuchEntityOIDCProviderGet)
	return provider, err
}

// readOIDCProviderVersion is GetOIDCProvider's counterpart to
// readUserVersion/readRoleVersion: it additionally returns the KV version
// the record was read at, so a mutation can write back with a matching CAS
// value instead of racing on a blind delete-then-recreate (see
// replaceOIDCProvider). notFound supplies the NoSuchEntity error the
// calling action reports, which the tagging actions word differently from
// the rest.
func (s *VaultStore) readOIDCProviderVersion(arn string, notFound func(string) iamerr.Error) (*types.OIDCProvider, int32, error) {
	url, err := iamutil.ParseOIDCProviderArn(arn)
	if err != nil {
		return nil, 0, err
	}
	segment := oidcProviderPathSegment(url)
	path := s.oidcProvidersPath() + "/" + segment

	resp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, 0, notFound(arn)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, 0, reauthErr
		}
		resp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return nil, 0, notFound(arn)
			}
			return nil, 0, err
		}
	}

	provider, err := parseVaultOIDCProvider(resp.Data.Data, segment)
	if err != nil {
		return nil, 0, err
	}
	return cloneOIDCProvider(provider), kvVersion(resp.Data.Metadata), nil
}

func (s *VaultStore) ListOIDCProviders(_ context.Context) (*ListOIDCProvidersOutput, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.oidcProvidersPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return &ListOIDCProvidersOutput{Providers: []types.OpenIDConnectProviderListEntry{}}, nil
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.oidcProvidersPath(), s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return &ListOIDCProvidersOutput{Providers: []types.OpenIDConnectProviderListEntry{}}, nil
			}
			return nil, err
		}
	}

	entries := make([]types.OpenIDConnectProviderListEntry, 0, len(resp.Data.Keys))
	for _, segment := range resp.Data.Keys {
		// Read each secret by its already-known key rather than decoding
		// segment back to a url, populating the list from each secret's own
		// stored fields.
		path := s.oidcProvidersPath() + "/" + segment
		secretResp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
				return nil, reauthErr
			}
			secretResp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
			if err != nil {
				return nil, err
			}
		}
		provider, err := parseVaultOIDCProvider(secretResp.Data.Data, segment)
		if err != nil {
			return nil, err
		}
		entries = append(entries, types.OpenIDConnectProviderListEntry{Arn: provider.Arn})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Arn < entries[j].Arn })
	return &ListOIDCProvidersOutput{Providers: entries}, nil
}

func (s *VaultStore) DeleteOIDCProvider(_ context.Context, arn string) error {
	url, err := iamutil.ParseOIDCProviderArn(arn)
	if err != nil {
		return err
	}
	path := s.oidcProvidersPath() + "/" + oidcProviderPathSegment(url)

	// Existence check first: unlike deleteRoleByPath (only reached after
	// DeleteRole's own prior GetRole existence check), Delete's own
	// not-found path is load-bearing here (NOT idempotent).
	if _, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...); err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return iamerr.NoSuchEntityOIDCProviderDelete(arn)
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return reauthErr
		}
		if _, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...); err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return iamerr.NoSuchEntityOIDCProviderDelete(arn)
			}
			return err
		}
	}

	return s.deleteOIDCProviderByURL(url)
}

func (s *VaultStore) deleteOIDCProviderByURL(url string) error {
	path := s.oidcProvidersPath() + "/" + oidcProviderPathSegment(url)
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

func (s *VaultStore) AddClientIDToOIDCProvider(ctx context.Context, arn, clientID string) error {
	return s.withOIDCProviderCAS(ctx, arn, iamerr.NoSuchEntityOIDCProviderGet, func(provider *types.OIDCProvider) error {
		if slices.Contains(provider.ClientIDList, clientID) {
			return nil
		}
		if len(provider.ClientIDList) >= MaxClientIDsPerOIDCProvider {
			return iamerr.ClientIdsPerOpenIdConnectProviderLimitExceeded(MaxClientIDsPerOIDCProvider)
		}
		provider.ClientIDList = append(provider.ClientIDList, clientID)
		return nil
	})
}

func (s *VaultStore) RemoveClientIDFromOIDCProvider(ctx context.Context, arn, clientID string) error {
	return s.withOIDCProviderCAS(ctx, arn, iamerr.NoSuchEntityOIDCProviderGet, func(provider *types.OIDCProvider) error {
		idx := slices.Index(provider.ClientIDList, clientID)
		if idx == -1 {
			return nil
		}
		provider.ClientIDList = slices.Delete(provider.ClientIDList, idx, idx+1)
		return nil
	})
}

func (s *VaultStore) UpdateOIDCProviderThumbprint(ctx context.Context, arn string, thumbprints []string) error {
	return s.withOIDCProviderCAS(ctx, arn, iamerr.NoSuchEntityOIDCProviderGet, func(provider *types.OIDCProvider) error {
		provider.ThumbprintList = thumbprints
		return nil
	})
}

func (s *VaultStore) TagOIDCProvider(ctx context.Context, arn string, tags []types.Tag) error {
	return s.withOIDCProviderCAS(ctx, arn, iamerr.NoSuchEntityOIDCProviderDelete, func(provider *types.OIDCProvider) error {
		merged, err := mergeTags(provider.Tags, tags, iamutil.TagKeysExact)
		if err != nil {
			return err
		}
		provider.Tags = merged
		return nil
	})
}

func (s *VaultStore) UntagOIDCProvider(ctx context.Context, arn string, tagKeys []string) error {
	return s.withOIDCProviderCAS(ctx, arn, iamerr.NoSuchEntityOIDCProviderDelete, func(provider *types.OIDCProvider) error {
		provider.Tags = removeTags(provider.Tags, tagKeys, iamutil.TagKeysExact)
		return nil
	})
}

func (s *VaultStore) ListOIDCProviderTags(_ context.Context, input ListOIDCProviderTagsInput) (*ListTagsOutput, error) {
	provider, _, err := s.readOIDCProviderVersion(input.Arn, iamerr.NoSuchEntityOIDCProviderDelete)
	if err != nil {
		return nil, err
	}

	return paginateTags(provider.Tags, input.Marker, input.MaxItems, iamutil.TagKeysExact), nil
}

// replaceOIDCProvider overwrites the stored document for provider.Url using
// a version-checked (CAS) write tied to readVersion, instead of an
// unconditional delete-then-recreate — see replaceUser for the rationale.
func (s *VaultStore) replaceOIDCProvider(ctx context.Context, provider types.OIDCProvider, readVersion int32) error {
	segment := oidcProviderPathSegment(provider.Url)
	path := s.oidcProvidersPath() + "/" + segment

	providerMap, err := oidcProviderToVaultMap(provider)
	if err != nil {
		return fmt.Errorf("serialize oidc provider: %w", err)
	}
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{segment: providerMap},
		Options: map[string]any{"cas": readVersion},
	}

	_, err = s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return errConcurrentModification
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return reauthErr
		}
		_, err = s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return errConcurrentModification
			}
			return err
		}
	}
	return nil
}

// withOIDCProviderCAS is withUserCAS's counterpart for OIDC providers.
func (s *VaultStore) withOIDCProviderCAS(ctx context.Context, arn string, notFound func(string) iamerr.Error, mutate func(*types.OIDCProvider) error) error {
	for range maxCASRetries {
		provider, version, err := s.readOIDCProviderVersion(arn, notFound)
		if err != nil {
			return err
		}
		if err := mutate(provider); err != nil {
			return err
		}
		err = s.replaceOIDCProvider(ctx, *provider, version)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errConcurrentModification) {
			return err
		}
	}
	return iamerr.ConcurrentModification()
}

var errInvalidVaultOIDCProvider = errors.New("invalid oidc provider entry in vault secrets engine")

func oidcProviderToVaultMap(provider types.OIDCProvider) (map[string]any, error) {
	b, err := json.Marshal(provider)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseVaultOIDCProvider reconstructs an OIDCProvider from the raw
// map[string]any vault returns. The outer key is the base64url path
// segment used at write time (oidcProviderPathSegment), not a
// human-readable value — unlike parseVaultRole/parseVaultUser.
func parseVaultOIDCProvider(data map[string]any, segment string) (types.OIDCProvider, error) {
	raw, ok := data[segment]
	if !ok {
		return types.OIDCProvider{}, errInvalidVaultOIDCProvider
	}
	providerMap, ok := raw.(map[string]any)
	if !ok {
		return types.OIDCProvider{}, errInvalidVaultOIDCProvider
	}
	b, err := json.Marshal(providerMap)
	if err != nil {
		return types.OIDCProvider{}, fmt.Errorf("re-marshal vault oidc provider: %w", err)
	}
	var provider types.OIDCProvider
	if err := json.Unmarshal(b, &provider); err != nil {
		return types.OIDCProvider{}, fmt.Errorf("unmarshal vault oidc provider: %w", err)
	}
	return provider, nil
}

// sessionsPath is the KV prefix under which AssumeRoleWithWebIdentity
// sessions are stored, kept distinct from secretStoragePath/rolesPath/
// oidcProvidersPath.
func (s *VaultStore) sessionsPath() string {
	return s.secretStoragePath + "/sessions"
}

func (s *VaultStore) CreateSession(ctx context.Context, session types.Session) (*types.Session, error) {
	// Bound how many concurrently-active sessions a single role can
	// accumulate — without this, one valid federated token replayed against
	// AssumeRoleWithWebIdentity indefinitely grows the number of KV paths
	// and metadata records this backend has to carry for that role.
	count, err := s.activeSessionCountForRole(ctx, session.RoleArn)
	if err != nil {
		return nil, err
	}
	if count >= MaxActiveSessionsPerRole {
		return nil, iamerr.GetAPIError(iamerr.ErrThrottling)
	}

	path := s.sessionsPath() + "/" + session.AccessKeyId

	// Pin the secret's own TTL to the session's expiration via Vault's
	// native KV v2 delete_version_after metadata, so an expired session is
	// eventually purged from storage by Vault itself even if GetSession is
	// never called again for it (e.g. a session minted once and never
	// reused) — GetSession's own expired-session delete only reclaims
	// storage for sessions someone actually looks up again.
	//
	// This must happen *before* the version below is written: Vault
	// computes a version's deletion_time from whatever delete_version_after
	// is in effect at the moment that version is written, not retroactively
	// — setting it afterward leaves an already-written version with no
	// deletion_time at all (confirmed against a live Vault server: a
	// version written before delete_version_after was set was never
	// scheduled for deletion, while one written after was). Best-effort: a
	// failure here still leaves a fully functional (if not self-cleaning)
	// session, so it's logged rather than failing the create.
	if err := s.setSessionTTL(path, session.Expiration); err != nil {
		debuglogger.Logf("failed to set Vault session TTL metadata for access key %q: %v", session.AccessKeyId, err)
	}

	sessionMap, err := sessionToVaultMap(session)
	if err != nil {
		return nil, fmt.Errorf("serialize session: %w", err)
	}
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{session.AccessKeyId: sessionMap},
		Options: map[string]any{"cas": 0},
	}

	_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
	if err != nil {
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		_, err = s.client.Secrets.KvV2Write(context.Background(), path, req, s.kvReqOpts...)
		if err != nil {
			return nil, err
		}
	}

	cloned := session
	return &cloned, nil
}

// activeSessionCountForRole counts this backend's currently-active sessions
// belonging to roleArn, so CreateSession can enforce
// MaxActiveSessionsPerRole. GetSession is reused to read each candidate
// entry: it already purges an expired-but-not-yet-Vault-reaped session on
// read, so an expired session is neither counted nor left to inflate a
// future count.
func (s *VaultStore) activeSessionCountForRole(ctx context.Context, roleArn string) (int, error) {
	resp, err := s.client.Secrets.KvV2List(context.Background(), s.sessionsPath(), s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return 0, nil
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return 0, reauthErr
		}
		resp, err = s.client.Secrets.KvV2List(context.Background(), s.sessionsPath(), s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return 0, nil
			}
			return 0, err
		}
	}

	count := 0
	for _, key := range resp.Data.Keys {
		session, err := s.GetSession(ctx, key)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				continue
			}
			return 0, err
		}
		if session.RoleArn == roleArn {
			count++
		}
	}
	return count, nil
}

// setSessionTTL sets path's KV v2 delete_version_after metadata to the
// duration remaining until expiration, so Vault purges the version itself
// once it's expired.
func (s *VaultStore) setSessionTTL(path string, expiration time.Time) error {
	ttl := time.Until(expiration)
	if ttl <= 0 {
		ttl = time.Second
	}

	req := schema.KvV2WriteMetadataRequest{DeleteVersionAfter: fmt.Sprintf("%.0fs", ttl.Seconds())}
	_, err := s.client.Secrets.KvV2WriteMetadata(context.Background(), path, req, s.kvReqOpts...)
	if err != nil {
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return reauthErr
		}
		_, err = s.client.Secrets.KvV2WriteMetadata(context.Background(), path, req, s.kvReqOpts...)
	}
	return err
}

func (s *VaultStore) GetSession(_ context.Context, accessKeyID string) (*types.Session, error) {
	path := s.sessionsPath() + "/" + accessKeyID

	resp, err := s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			// Either this access key never existed, or Vault's own
			// delete_version_after TTL already soft-deleted the version —
			// Vault answers a read for a soft-deleted-but-not-yet-destroyed
			// version with 404, not 200-with-null-data. Either way,
			// best-effort purge the lingering metadata record now, since
			// Vault doesn't appear to reclaim it on its own once merely
			// soft-deleted.
			s.purgeSession(accessKeyID)
			return nil, ErrSessionNotFound
		}
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return nil, reauthErr
		}
		resp, err = s.client.Secrets.KvV2Read(context.Background(), path, s.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				s.purgeSession(accessKeyID)
				return nil, ErrSessionNotFound
			}
			return nil, err
		}
	}

	session, err := parseVaultSession(resp.Data.Data, accessKeyID)
	if err == nil && session.Expiration.After(time.Now().UTC()) {
		cloned := session
		return &cloned, nil
	}

	// Readable but our own Expiration field says it's past due anyway
	// (should be rare/racy, since setSessionTTL pins Vault's own TTL to
	// this same value) — purge now rather than waiting on Vault.
	s.purgeSession(accessKeyID)
	return nil, ErrSessionNotFound
}

// purgeSession permanently deletes accessKeyID's session metadata and
// version record. Best-effort: a failure just leaves the (already
// not-found-to-the-caller) entry lingering until some later call retries
// the purge or Vault's own cleanup eventually catches it.
func (s *VaultStore) purgeSession(accessKeyID string) {
	if err := s.deleteByPath("sessions/" + accessKeyID); err != nil {
		debuglogger.Logf("failed to delete expired Vault session for access key %q: %v", accessKeyID, err)
	}
}

var errInvalidVaultSession = errors.New("invalid session entry in vault secrets engine")

func sessionToVaultMap(session types.Session) (map[string]any, error) {
	b, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseVaultSession reconstructs a Session from the raw map[string]any
// vault returns. The outer key is the AccessKeyId.
func parseVaultSession(data map[string]any, accessKeyID string) (types.Session, error) {
	raw, ok := data[accessKeyID]
	if !ok {
		return types.Session{}, errInvalidVaultSession
	}
	sessionMap, ok := raw.(map[string]any)
	if !ok {
		return types.Session{}, errInvalidVaultSession
	}
	b, err := json.Marshal(sessionMap)
	if err != nil {
		return types.Session{}, fmt.Errorf("re-marshal vault session: %w", err)
	}
	var session types.Session
	if err := json.Unmarshal(b, &session); err != nil {
		return types.Session{}, fmt.Errorf("unmarshal vault session: %w", err)
	}
	return session, nil
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
