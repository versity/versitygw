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
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/iamstore"
)

const (
	iamFile       = "iam.json"
	iamBackupFile = "iam.json.backup"
)

type InternalStore struct {
	sync.RWMutex
	engine *iamstore.Engine[iamConfig]
}

var _ Storer = (*InternalStore)(nil)

func NewInternal(dir string) (Storer, error) {
	engine, err := iamstore.New(dir, iamFile, iamBackupFile, defaultIAMConfig(), normalizeIAMConfig)
	if err != nil {
		return nil, err
	}

	return &InternalStore{engine: engine}, nil
}

type iamConfig struct {
	Users map[string]types.User `json:"users"`
	// AccessKeyIndex maps an access key id to the username that owns it,
	// so GetAccessKeyLastUsed can resolve a key without scanning every user.
	AccessKeyIndex map[string]string `json:"accessKeyIndex"`
	// UserNameIndex maps a lowercased user name to the canonical (as-created)
	// stored user name, so lookups can enforce AWS's case-insensitive
	// uniqueness while still preserving the original casing in conf.Users's
	// key and the stored User.UserName.
	UserNameIndex map[string]string `json:"userNameIndex"`

	Roles map[string]types.Role `json:"roles"`
	// RoleNameIndex is UserNameIndex's counterpart for roles.
	RoleNameIndex map[string]string `json:"roleNameIndex"`
}

func defaultIAMConfig() iamConfig {
	return iamConfig{
		Users:          map[string]types.User{},
		AccessKeyIndex: map[string]string{},
		UserNameIndex:  map[string]string{},
		Roles:          map[string]types.Role{},
		RoleNameIndex:  map[string]string{},
	}
}

func normalizeIAMConfig(conf *iamConfig) {
	if conf.Users == nil {
		conf.Users = make(map[string]types.User)
	}
	if conf.AccessKeyIndex == nil {
		conf.AccessKeyIndex = make(map[string]string)
	}
	if conf.UserNameIndex == nil {
		conf.UserNameIndex = make(map[string]string)
	}
	for name := range conf.Users {
		key := strings.ToLower(name)
		if _, ok := conf.UserNameIndex[key]; !ok {
			conf.UserNameIndex[key] = name
		}
	}

	if conf.Roles == nil {
		conf.Roles = make(map[string]types.Role)
	}
	if conf.RoleNameIndex == nil {
		conf.RoleNameIndex = make(map[string]string)
	}
	for name := range conf.Roles {
		key := strings.ToLower(name)
		if _, ok := conf.RoleNameIndex[key]; !ok {
			conf.RoleNameIndex[key] = name
		}
	}
}

// lookupUser resolves name to the canonical stored user name and entry,
// case-insensitively, via conf.UserNameIndex.
func lookupUser(conf iamConfig, name string) (string, types.User, bool) {
	canonical, ok := conf.UserNameIndex[strings.ToLower(name)]
	if !ok {
		return "", types.User{}, false
	}
	user, ok := conf.Users[canonical]
	return canonical, user, ok
}

// lookupRole is lookupUser's counterpart for roles.
func lookupRole(conf iamConfig, name string) (string, types.Role, bool) {
	canonical, ok := conf.RoleNameIndex[strings.ToLower(name)]
	if !ok {
		return "", types.Role{}, false
	}
	role, ok := conf.Roles[canonical]
	return canonical, role, ok
}

func (s *InternalStore) CreateUser(_ context.Context, user types.User) (*types.User, error) {
	s.Lock()
	defer s.Unlock()

	if err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		key := strings.ToLower(user.UserName)
		if _, ok := conf.UserNameIndex[key]; ok {
			return nil, iamerr.EntityAlreadyExistsUser(user.UserName)
		}
		for _, existing := range conf.Users {
			if existing.UserID == user.UserID {
				return nil, ErrUserIDAlreadyExists
			}
		}

		conf.Users[user.UserName] = user
		conf.UserNameIndex[key] = user.UserName
		return json.Marshal(conf)
	}); err != nil {
		return nil, unwrapAPIError(err)
	}

	return cloneUser(user), nil
}

func (s *InternalStore) DeleteUser(_ context.Context, username string) error {
	s.Lock()
	defer s.Unlock()

	err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, username)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(username)
		}
		if len(user.Policies.Inline) > 0 {
			return nil, iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)
		}
		if len(user.AccessKeys) > 0 {
			return nil, iamerr.GetAPIError(iamerr.ErrDeleteConflict)
		}

		delete(conf.Users, canonical)
		delete(conf.UserNameIndex, strings.ToLower(canonical))
		return json.Marshal(conf)
	})
	return unwrapAPIError(err)
}

func (s *InternalStore) GetUser(_ context.Context, username string) (*types.User, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	_, user, ok := lookupUser(conf, username)
	if !ok {
		return nil, iamerr.NoSuchEntityUser(username)
	}

	return cloneUser(user), nil
}

func (s *InternalStore) ListUsers(_ context.Context, input ListUsersInput) (*ListUsersOutput, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	users := make([]types.User, 0, len(conf.Users))
	for _, user := range conf.Users {
		if input.PathPrefix != "" && !strings.HasPrefix(user.Path, input.PathPrefix) {
			continue
		}
		users = append(users, user)
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

func (s *InternalStore) UpdateUser(_ context.Context, input UpdateUserInput) (*types.User, error) {
	s.Lock()
	defer s.Unlock()

	var updated types.User
	if err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, input.UserName)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(input.UserName)
		}

		finalName := user.UserName
		if input.NewUserName != "" {
			finalName = input.NewUserName
		}
		if !strings.EqualFold(finalName, canonical) {
			if _, ok := conf.UserNameIndex[strings.ToLower(finalName)]; ok {
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

		if user.UserName != canonical {
			delete(conf.Users, canonical)
			delete(conf.UserNameIndex, strings.ToLower(canonical))
			for _, key := range user.AccessKeys {
				conf.AccessKeyIndex[key.AccessKeyId] = user.UserName
			}
		}
		conf.Users[user.UserName] = user
		conf.UserNameIndex[strings.ToLower(user.UserName)] = user.UserName
		updated = user

		return json.Marshal(conf)
	}); err != nil {
		return nil, unwrapAPIError(err)
	}

	return cloneUser(updated), nil
}

func (s *InternalStore) CreateAccessKey(_ context.Context, input CreateAccessKeyInput) (*types.AccessKey, error) {
	s.Lock()
	defer s.Unlock()

	var created types.AccessKey
	if err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, input.UserName)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(input.UserName)
		}
		if len(user.AccessKeys) >= MaxAccessKeysPerUser {
			return nil, iamerr.AccessKeysLimitExceeded(MaxAccessKeysPerUser)
		}
		if _, ok := conf.AccessKeyIndex[input.AccessKeyID]; ok {
			return nil, ErrAccessKeyIDAlreadyExists
		}

		user.AccessKeys = append(user.AccessKeys, types.AccessKeyEntry{
			AccessKeyId:     input.AccessKeyID,
			SecretAccessKey: input.SecretAccessKey,
			Status:          input.Status,
			CreateDate:      input.CreateDate,
		})
		conf.Users[canonical] = user
		conf.AccessKeyIndex[input.AccessKeyID] = canonical

		created = types.AccessKey{
			UserName:        canonical,
			AccessKeyId:     input.AccessKeyID,
			Status:          input.Status,
			SecretAccessKey: input.SecretAccessKey,
			CreateDate:      input.CreateDate,
		}

		return json.Marshal(conf)
	}); err != nil {
		return nil, unwrapAPIError(err)
	}

	return &created, nil
}

func (s *InternalStore) UpdateAccessKey(_ context.Context, input UpdateAccessKeyInput) error {
	s.Lock()
	defer s.Unlock()

	err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, input.UserName)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(input.UserName)
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
			return nil, iamerr.NoSuchEntityAccessKey(input.AccessKeyID)
		}

		conf.Users[canonical] = user
		return json.Marshal(conf)
	})
	return unwrapAPIError(err)
}

func (s *InternalStore) DeleteAccessKey(_ context.Context, username, accessKeyID string) error {
	s.Lock()
	defer s.Unlock()

	err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, username)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(username)
		}

		idx := -1
		for i, key := range user.AccessKeys {
			if key.AccessKeyId == accessKeyID {
				idx = i
				break
			}
		}
		if idx == -1 {
			return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
		}

		user.AccessKeys = slices.Delete(user.AccessKeys, idx, idx+1)
		conf.Users[canonical] = user
		delete(conf.AccessKeyIndex, accessKeyID)

		return json.Marshal(conf)
	})
	return unwrapAPIError(err)
}

func (s *InternalStore) GetAccessKeyLastUsed(_ context.Context, accessKeyID string) (*GetAccessKeyLastUsedOutput, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	username, ok := conf.AccessKeyIndex[accessKeyID]
	if !ok {
		return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
	}
	user, ok := conf.Users[username]
	if !ok {
		return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
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

	return nil, iamerr.NoSuchEntityAccessKey(accessKeyID)
}

func (s *InternalStore) ListAccessKeys(_ context.Context, input ListAccessKeysInput) (*ListAccessKeysOutput, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	canonical, user, ok := lookupUser(conf, input.UserName)
	if !ok {
		return nil, iamerr.NoSuchEntityUser(input.UserName)
	}

	keys := make([]types.AccessKeyMetadata, 0, len(user.AccessKeys))
	for _, key := range user.AccessKeys {
		keys = append(keys, types.AccessKeyMetadata{
			UserName:    canonical,
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

func (s *InternalStore) PutUserPolicy(_ context.Context, input PutUserPolicyInput) error {
	s.Lock()
	defer s.Unlock()

	err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, input.UserName)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(input.UserName)
		}

		now := time.Now().UTC().Truncate(time.Second)
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
			return nil, iamerr.InlinePolicyQuotaExceeded("user", input.UserName, MaxInlinePolicyBytesPerUser)
		}

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

		conf.Users[canonical] = user
		return json.Marshal(conf)
	})
	return unwrapAPIError(err)
}

func (s *InternalStore) GetUserPolicy(_ context.Context, userName, policyName string) (*types.PolicyEntry, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	_, user, ok := lookupUser(conf, userName)
	if !ok {
		return nil, iamerr.NoSuchEntityUser(userName)
	}

	for _, p := range user.Policies.Inline {
		if p.PolicyName == policyName {
			cloned := p
			return &cloned, nil
		}
	}

	return nil, iamerr.NoSuchEntityUserPolicy(userName, policyName)
}

func (s *InternalStore) DeleteUserPolicy(_ context.Context, userName, policyName string) error {
	s.Lock()
	defer s.Unlock()

	err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, user, ok := lookupUser(conf, userName)
		if !ok {
			return nil, iamerr.NoSuchEntityUser(userName)
		}

		idx := -1
		for i, p := range user.Policies.Inline {
			if p.PolicyName == policyName {
				idx = i
				break
			}
		}
		if idx == -1 {
			return nil, iamerr.NoSuchEntityUserPolicy(userName, policyName)
		}

		user.Policies.Inline = slices.Delete(user.Policies.Inline, idx, idx+1)
		conf.Users[canonical] = user
		return json.Marshal(conf)
	})
	return unwrapAPIError(err)
}

func (s *InternalStore) ListUserPolicies(_ context.Context, input ListUserPoliciesInput) (*ListUserPoliciesOutput, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	_, user, ok := lookupUser(conf, input.UserName)
	if !ok {
		return nil, iamerr.NoSuchEntityUser(input.UserName)
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

func (s *InternalStore) CreateRole(_ context.Context, role types.Role) (*types.Role, error) {
	s.Lock()
	defer s.Unlock()

	role.EnsureRoleLastUsed()

	if err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		key := strings.ToLower(role.RoleName)
		if _, ok := conf.RoleNameIndex[key]; ok {
			return nil, iamerr.EntityAlreadyExistsRole(role.RoleName)
		}
		for _, existing := range conf.Roles {
			if existing.RoleID == role.RoleID {
				return nil, ErrRoleIDAlreadyExists
			}
		}

		conf.Roles[role.RoleName] = role
		conf.RoleNameIndex[key] = role.RoleName
		return json.Marshal(conf)
	}); err != nil {
		return nil, unwrapAPIError(err)
	}

	return cloneRole(role), nil
}

func (s *InternalStore) GetRole(_ context.Context, roleName string) (*types.Role, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	_, role, ok := lookupRole(conf, roleName)
	if !ok {
		return nil, iamerr.NoSuchEntityRole(roleName)
	}

	return cloneRole(role), nil
}

func (s *InternalStore) ListRoles(_ context.Context, input ListRolesInput) (*ListRolesOutput, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return nil, err
	}

	roles := make([]types.Role, 0, len(conf.Roles))
	for _, role := range conf.Roles {
		if input.PathPrefix != "" && !strings.HasPrefix(role.Path, input.PathPrefix) {
			continue
		}
		// ListRoles entries omit RoleLastUsed even though it's persisted —
		// matches the documented list/get field asymmetry.
		role.RoleLastUsed = nil
		roles = append(roles, role)
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

func (s *InternalStore) DeleteRole(_ context.Context, roleName string) error {
	s.Lock()
	defer s.Unlock()

	err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, role, ok := lookupRole(conf, roleName)
		if !ok {
			return nil, iamerr.NoSuchEntityRole(roleName)
		}
		if len(role.Policies.Inline) > 0 {
			return nil, iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies)
		}

		delete(conf.Roles, canonical)
		delete(conf.RoleNameIndex, strings.ToLower(canonical))
		return json.Marshal(conf)
	})
	return unwrapAPIError(err)
}

func (s *InternalStore) UpdateAssumeRolePolicy(_ context.Context, input UpdateAssumeRolePolicyInput) (*types.Role, error) {
	s.Lock()
	defer s.Unlock()

	var updated types.Role
	if err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		canonical, role, ok := lookupRole(conf, input.RoleName)
		if !ok {
			return nil, iamerr.NoSuchEntityRole(input.RoleName)
		}

		role.AssumeRolePolicyDocument = input.PolicyDocument
		conf.Roles[canonical] = role
		updated = role

		return json.Marshal(conf)
	}); err != nil {
		return nil, unwrapAPIError(err)
	}

	return cloneRole(updated), nil
}

func cloneUser(user types.User) *types.User {
	cloned := user
	cloned.Tags = slices.Clone(user.Tags)
	cloned.AccessKeys = slices.Clone(user.AccessKeys)
	cloned.Policies.Inline = slices.Clone(user.Policies.Inline)
	return &cloned
}

func cloneRole(role types.Role) *types.Role {
	cloned := role
	cloned.Tags = slices.Clone(role.Tags)
	cloned.Policies.Inline = slices.Clone(role.Policies.Inline)
	return &cloned
}
