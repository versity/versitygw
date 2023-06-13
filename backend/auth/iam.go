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
	"os"
	"sync"

	"github.com/versity/versitygw/s3err"
)

type Account struct {
	Secret string `json:"secret"`
	Role   string `json:"role"`
	Region string `json:"region"`
}

type IAMConfig struct {
	AccessAccounts map[string]Account `json:"accessAccounts"`
}

type AccountsCache struct {
	mu       sync.Mutex
	Accounts map[string]Account
}

func (c *AccountsCache) getAccount(access string) *Account {
	c.mu.Lock()
	defer c.mu.Unlock()

	acc, ok := c.Accounts[access]
	if !ok {
		return nil
	}

	return &acc
}

func (c *AccountsCache) updateAccounts() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var data IAMConfig

	file, err := os.ReadFile("users.json")
	if err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	if err := json.Unmarshal(file, &data); err != nil {
		return fmt.Errorf("error parsing the data: %w", err)
	}

	c.Accounts = data.AccessAccounts

	return nil
}

func (c *AccountsCache) deleteAccount(access string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Accounts, access)
}

type IAMService interface {
	GetIAMConfig() (*IAMConfig, error)
	CreateAccount(access string, account *Account) error
	GetUserAccount(access string) *Account
	DeleteUserAccount(access string) error
}

type IAMServiceUnsupported struct {
	accCache *AccountsCache
}

var _ IAMService = &IAMServiceUnsupported{}

func InitIAM() (IAMService, error) {
	_, err := os.ReadFile("users.json")
	if err != nil {
		jsonData, err := json.MarshalIndent(IAMConfig{AccessAccounts: map[string]Account{}}, "", "  ")
		if err != nil {
			return nil, err
		}

		if err := os.WriteFile("users.json", jsonData, 0644); err != nil {
			return nil, err
		}
	}
	return &IAMServiceUnsupported{accCache: &AccountsCache{Accounts: map[string]Account{}}}, nil
}

func (IAMServiceUnsupported) GetIAMConfig() (*IAMConfig, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (s IAMServiceUnsupported) CreateAccount(access string, account *Account) error {
	var data IAMConfig

	file, err := os.ReadFile("users.json")
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if err := json.Unmarshal(file, &data); err != nil {
		return err
	}

	_, ok := data.AccessAccounts[access]
	if ok {
		return fmt.Errorf("user with the given access already exists")
	}

	data.AccessAccounts[access] = *account

	updatedJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile("users.json", updatedJSON, 0644); err != nil {
		return err
	}

	return nil
}

func (s IAMServiceUnsupported) GetUserAccount(access string) *Account {
	acc := s.accCache.getAccount(access)
	if acc == nil {
		err := s.accCache.updateAccounts()
		if err != nil {
			return nil
		}

		return s.accCache.getAccount(access)
	}

	return acc
}

func (s IAMServiceUnsupported) DeleteUserAccount(access string) error {
	var data IAMConfig

	file, err := os.ReadFile("users.json")
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if err := json.Unmarshal(file, &data); err != nil {
		return fmt.Errorf("failed to parse the config file: %w", err)
	}

	_, ok := data.AccessAccounts[access]
	if !ok {
		return fmt.Errorf("invalid access for the user: user does not exist")
	}

	delete(data.AccessAccounts, access)

	updatedJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to parse the data: %w", err)
	}

	if err := os.WriteFile("users.json", updatedJSON, 0644); err != nil {
		return fmt.Errorf("failed to saved the changes: %w", err)
	}

	s.accCache.deleteAccount(access)

	return nil
}
