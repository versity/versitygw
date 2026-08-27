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
	"fmt"
	"strings"
	"time"

	"github.com/versity/versitygw/iamapi/types"
)

// Storer is the IAM API storage backend contract.
type Storer interface {
	CreateUser(ctx context.Context, user types.User) (*types.User, error)
	DeleteUser(ctx context.Context, username string) error
	GetUser(ctx context.Context, username string) (*types.User, error)
	GetUserByAccessKeyID(ctx context.Context, accessKeyID string) (*types.User, error)
	ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersOutput, error)
	UpdateUser(ctx context.Context, input UpdateUserInput) (*types.User, error)

	TagUser(ctx context.Context, userName string, tags []types.Tag) error
	UntagUser(ctx context.Context, userName string, tagKeys []string) error
	ListUserTags(ctx context.Context, input ListUserTagsInput) (*ListTagsOutput, error)

	CreateAccessKey(ctx context.Context, input CreateAccessKeyInput) (*types.AccessKey, error)
	UpdateAccessKey(ctx context.Context, input UpdateAccessKeyInput) error
	DeleteAccessKey(ctx context.Context, username, accessKeyID string) error
	GetAccessKeyLastUsed(ctx context.Context, accessKeyID string) (*GetAccessKeyLastUsedOutput, error)
	ListAccessKeys(ctx context.Context, input ListAccessKeysInput) (*ListAccessKeysOutput, error)
	// RecordAccessKeyUsage updates accessKeyID's GetAccessKeyLastUsed
	// metadata (service, region, and timestamp) to reflect a successful
	// authentication at when. Called best-effort/asynchronously by the auth
	// middleware, so implementations should treat a lost update under
	// concurrent use as acceptable rather than something worth retrying hard.
	RecordAccessKeyUsage(ctx context.Context, accessKeyID, service, region string, when time.Time) error

	PutUserPolicy(ctx context.Context, input PutUserPolicyInput) error
	GetUserPolicy(ctx context.Context, userName, policyName string) (*types.PolicyEntry, error)
	DeleteUserPolicy(ctx context.Context, userName, policyName string) error
	ListUserPolicies(ctx context.Context, input ListUserPoliciesInput) (*ListUserPoliciesOutput, error)

	CreateRole(ctx context.Context, role types.Role) (*types.Role, error)
	GetRole(ctx context.Context, roleName string) (*types.Role, error)
	ListRoles(ctx context.Context, input ListRolesInput) (*ListRolesOutput, error)
	DeleteRole(ctx context.Context, roleName string) error
	UpdateAssumeRolePolicy(ctx context.Context, input UpdateAssumeRolePolicyInput) (*types.Role, error)

	TagRole(ctx context.Context, roleName string, tags []types.Tag) error
	UntagRole(ctx context.Context, roleName string, tagKeys []string) error
	ListRoleTags(ctx context.Context, input ListRoleTagsInput) (*ListTagsOutput, error)

	PutRolePolicy(ctx context.Context, input PutRolePolicyInput) error
	GetRolePolicy(ctx context.Context, roleName, policyName string) (*types.PolicyEntry, error)
	DeleteRolePolicy(ctx context.Context, roleName, policyName string) error
	ListRolePolicies(ctx context.Context, input ListRolePoliciesInput) (*ListRolePoliciesOutput, error)

	// OIDC Provider CRUD
	CreateOIDCProvider(ctx context.Context, provider types.OIDCProvider) (*types.OIDCProvider, error)
	GetOIDCProvider(ctx context.Context, arn string) (*types.OIDCProvider, error)
	ListOIDCProviders(ctx context.Context) (*ListOIDCProvidersOutput, error)
	DeleteOIDCProvider(ctx context.Context, arn string) error
	AddClientIDToOIDCProvider(ctx context.Context, arn, clientID string) error
	RemoveClientIDFromOIDCProvider(ctx context.Context, arn, clientID string) error
	UpdateOIDCProviderThumbprint(ctx context.Context, arn string, thumbprints []string) error

	TagOIDCProvider(ctx context.Context, arn string, tags []types.Tag) error
	UntagOIDCProvider(ctx context.Context, arn string, tagKeys []string) error
	ListOIDCProviderTags(ctx context.Context, input ListOIDCProviderTagsInput) (*ListTagsOutput, error)

	CreateSession(ctx context.Context, session types.Session) (*types.Session, error)
	GetSession(ctx context.Context, accessKeyID string) (*types.Session, error)
}

type Config struct {
	Dir   string
	Vault VaultConfig
}

func New(cfg Config) (Storer, error) {
	dir := strings.TrimSpace(cfg.Dir)
	vaultEndpoint := strings.TrimSpace(cfg.Vault.EndpointURL)

	selected := make([]string, 0, 2)
	if dir != "" {
		selected = append(selected, "dir")
	}
	if vaultEndpoint != "" {
		selected = append(selected, "vault")
	}

	switch len(selected) {
	case 0:
		return nil, fmt.Errorf("no IAM storer config specified")
	case 1:
	default:
		return nil, fmt.Errorf("multiple IAM storer configs specified: %s", strings.Join(selected, ", "))
	}

	switch {
	case dir != "":
		store, err := NewInternal(dir)
		if err != nil {
			return nil, fmt.Errorf("init internal IAM storer: %w", err)
		}
		return store, nil
	case vaultEndpoint != "":
		store, err := NewVault(cfg.Vault)
		if err != nil {
			return nil, fmt.Errorf("init vault IAM storer: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("no IAM storer config specified")
	}
}
