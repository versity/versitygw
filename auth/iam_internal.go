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
	"hash/crc32"
	"sync"
)

// IAMServiceInternal manages the internal IAM service
type IAMServiceInternal struct {
	storer Storer

	mu     sync.RWMutex
	accts  IAMConfig
	serial uint32
}

// UpdateAcctFunc accepts the current data and returns the new data to be stored
type UpdateAcctFunc func([]byte) ([]byte, error)

// Storer is the interface to manage the peristent IAM data for the internal
// IAM service
type Storer interface {
	InitIAM() error
	GetIAM() ([]byte, error)
	StoreIAM(UpdateAcctFunc) error
}

// IAMConfig stores all internal IAM accounts
type IAMConfig struct {
	AccessAccounts map[string]Account `json:"accessAccounts"`
}

var _ IAMService = &IAMServiceInternal{}

// NewInternal creates a new instance for the Internal IAM service
func NewInternal(s Storer) (*IAMServiceInternal, error) {
	i := &IAMServiceInternal{
		storer: s,
	}

	err := i.updateCache()
	if err != nil {
		return nil, fmt.Errorf("refresh iam cache: %w", err)
	}

	return i, nil
}

// CreateAccount creates a new IAM account. Returns an error if the account
// already exists.
func (s *IAMServiceInternal) CreateAccount(access string, account Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storer.StoreIAM(func(data []byte) ([]byte, error) {
		var conf IAMConfig

		if len(data) > 0 {
			if err := json.Unmarshal(data, &conf); err != nil {
				return nil, fmt.Errorf("failed to parse iam: %w", err)
			}
		} else {
			conf.AccessAccounts = make(map[string]Account)
		}

		_, ok := conf.AccessAccounts[access]
		if ok {
			return nil, fmt.Errorf("account already exists")
		}
		conf.AccessAccounts[access] = account

		b, err := json.Marshal(s.accts)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// GetUserAccount retrieves account info for the requested user. Returns
// ErrNoSuchUser if the account does not exist.
func (s *IAMServiceInternal) GetUserAccount(access string) (Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.storer.GetIAM()
	if err != nil {
		return Account{}, fmt.Errorf("get iam data: %w", err)
	}

	serial := crc32.ChecksumIEEE(data)
	if serial != s.serial {
		s.mu.RUnlock()
		err := s.updateCache()
		s.mu.RLock()
		if err != nil {
			return Account{}, fmt.Errorf("refresh iam cache: %w", err)
		}
	}

	acct, ok := s.accts.AccessAccounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}

	return acct, nil
}

// updateCache must be called with no locks held
func (s *IAMServiceInternal) updateCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.storer.GetIAM()
	if err != nil {
		return fmt.Errorf("get iam data: %w", err)
	}

	serial := crc32.ChecksumIEEE(data)

	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.accts); err != nil {
			return fmt.Errorf("failed to parse the config file: %w", err)
		}
	} else {
		s.accts.AccessAccounts = make(map[string]Account)
	}

	s.serial = serial

	return nil
}

// DeleteUserAccount deletes the specified user account. Does not check if
// account exists.
func (s *IAMServiceInternal) DeleteUserAccount(access string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storer.StoreIAM(func(data []byte) ([]byte, error) {
		if len(data) == 0 {
			// empty config, do nothing
			return data, nil
		}

		var conf IAMConfig

		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, fmt.Errorf("failed to parse iam: %w", err)
		}

		delete(conf.AccessAccounts, access)

		b, err := json.Marshal(s.accts)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}
