// Copyright 2023 Versity Software
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

package auth

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/versity/versitygw/internal/iamstore"
)

const (
	iamFile       = "users.json"
	iamBackupFile = "users.json.backup"
)

// IAMServiceInternal manages the internal IAM service
type IAMServiceInternal struct {
	// This mutex will help with racing updates to the IAM data
	// from multiple requests to this gateway instance, but
	// will not help with racing updates to multiple load balanced
	// gateway instances. This is a limitation of the internal
	// IAM service. All account updates should be sent to a single
	// gateway instance if possible.
	sync.RWMutex
	engine  *iamstore.Engine[iAMConfig]
	rootAcc Account
}

// iAMConfig stores all internal IAM accounts
type iAMConfig struct {
	AccessAccounts map[string]Account `json:"accessAccounts"`
}

var _ IAMService = &IAMServiceInternal{}

// NewInternal creates a new instance for the Internal IAM service
func NewInternal(rootAcc Account, dir string) (*IAMServiceInternal, error) {
	engine, err := iamstore.New(dir, iamFile, iamBackupFile, defaultIAMConfig(), normalizeIAMConfig)
	if err != nil {
		return nil, fmt.Errorf("init iam: %w", err)
	}

	i := &IAMServiceInternal{
		engine:  engine,
		rootAcc: rootAcc,
	}

	return i, nil
}

// CreateAccount creates a new IAM account. Returns an error if the account
// already exists.
func (s *IAMServiceInternal) CreateAccount(account Account) error {
	if account.Access == s.rootAcc.Access {
		return ErrUserExists
	}

	s.Lock()
	defer s.Unlock()

	return s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		_, ok := conf.AccessAccounts[account.Access]
		if ok {
			return nil, ErrUserExists
		}
		conf.AccessAccounts[account.Access] = account

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// GetUserAccount retrieves account info for the requested user. Returns
// ErrNoSuchUser if the account does not exist.
func (s *IAMServiceInternal) GetUserAccount(access string) (Account, error) {
	if access == s.rootAcc.Access {
		return s.rootAcc, nil
	}

	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return Account{}, fmt.Errorf("get iam data: %w", err)
	}

	acct, ok := conf.AccessAccounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}

	return acct, nil
}

// UpdateUserAccount updates the specified user account fields. Returns
// ErrNoSuchUser if the account does not exist.
func (s *IAMServiceInternal) UpdateUserAccount(access string, props MutableProps) error {
	s.Lock()
	defer s.Unlock()

	return s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		acc, found := conf.AccessAccounts[access]
		if !found {
			return nil, ErrNoSuchUser
		}

		updateAcc(&acc, props)
		conf.AccessAccounts[access] = acc

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// DeleteUserAccount deletes the specified user account. Does not check if
// account exists.
func (s *IAMServiceInternal) DeleteUserAccount(access string) error {
	s.Lock()
	defer s.Unlock()

	return s.engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		delete(conf.AccessAccounts, access)

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// ListUserAccounts lists all the user accounts stored.
func (s *IAMServiceInternal) ListUserAccounts() ([]Account, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.engine.GetIAM()
	if err != nil {
		return []Account{}, fmt.Errorf("get iam data: %w", err)
	}

	keys := make([]string, 0, len(conf.AccessAccounts))
	for k := range conf.AccessAccounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var accs []Account
	for _, k := range keys {
		accs = append(accs, Account{
			Access:    k,
			Secret:    conf.AccessAccounts[k].Secret,
			Role:      conf.AccessAccounts[k].Role,
			UserID:    conf.AccessAccounts[k].UserID,
			GroupID:   conf.AccessAccounts[k].GroupID,
			ProjectID: conf.AccessAccounts[k].ProjectID,
		})
	}

	return accs, nil
}

// Shutdown graceful termination of service
func (s *IAMServiceInternal) Shutdown() error {
	return nil
}

func parseIAM(b []byte) (iAMConfig, error) {
	return iamstore.ParseIAM(b, normalizeIAMConfig)
}

func defaultIAMConfig() iAMConfig {
	return iAMConfig{AccessAccounts: map[string]Account{}}
}

func normalizeIAMConfig(conf *iAMConfig) {
	if conf.AccessAccounts == nil {
		conf.AccessAccounts = make(map[string]Account)
	}
}
