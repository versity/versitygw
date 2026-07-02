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
}

func defaultIAMConfig() iamConfig {
	return iamConfig{Users: map[string]types.User{}}
}

func normalizeIAMConfig(conf *iamConfig) {
	if conf.Users == nil {
		conf.Users = make(map[string]types.User)
	}
}

func (s *InternalStore) CreateUser(_ context.Context, user types.User) (*types.User, error) {
	s.Lock()
	defer s.Unlock()

	if err := s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := s.engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}

		if _, ok := conf.Users[user.UserName]; ok {
			return nil, iamerr.EntityAlreadyExistsUser(user.UserName)
		}
		for _, existing := range conf.Users {
			if existing.UserID == user.UserID {
				return nil, ErrUserIDAlreadyExists
			}
		}

		conf.Users[user.UserName] = user
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

		if _, ok := conf.Users[username]; !ok {
			return nil, iamerr.NoSuchEntityUser(username)
		}

		delete(conf.Users, username)
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

	user, ok := conf.Users[username]
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

		user, ok := conf.Users[input.UserName]
		if !ok {
			return nil, iamerr.NoSuchEntityUser(input.UserName)
		}

		finalName := user.UserName
		if input.NewUserName != "" {
			finalName = input.NewUserName
		}
		if finalName != input.UserName {
			if _, ok := conf.Users[finalName]; ok {
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
			delete(conf.Users, input.UserName)
		}
		conf.Users[user.UserName] = user
		updated = user

		return json.Marshal(conf)
	}); err != nil {
		return nil, unwrapAPIError(err)
	}

	return cloneUser(updated), nil
}

func cloneUser(user types.User) *types.User {
	cloned := user
	cloned.Tags = slices.Clone(user.Tags)
	return &cloned
}
