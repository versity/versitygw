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

	"github.com/versity/versitygw/s3err"
)

type Account struct {
	Access string `json:"access"`
	Secret string `json:"secret"`
	Role   string `json:"role"`
	Region string `json:"region"`
}

type IAMConfig struct {
	AccessAccounts []Account `json:"accessAccounts"`
}

type IAMService interface {
	GetIAMConfig() (*IAMConfig, error)
	CreateAccount(account *Account) error
	GetUserAccount(access string) *Account
}

type IAMServiceUnsupported struct{}

var _ IAMService = &IAMServiceUnsupported{}

func New() IAMService {
	return &IAMServiceUnsupported{}
}

func (IAMServiceUnsupported) GetIAMConfig() (*IAMConfig, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (s IAMServiceUnsupported) CreateAccount(account *Account) error {
	var data IAMConfig

	fmt.Printf("%+v\n", account)

	file, err := os.ReadFile("users.json")
	if err != nil {
		data = IAMConfig{AccessAccounts: []Account{*account}}
	} else {
		if err := json.Unmarshal(file, &data); err != nil {
			return err
		}

		existingUser := s.getUserByAccess(account.Access, data.AccessAccounts)
		if existingUser != nil {
			return fmt.Errorf("user with the given access already exists")
		}

		data.AccessAccounts = append(data.AccessAccounts, *account)
	}

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
	var data IAMConfig

	file, err := os.ReadFile("users.json")
	if err != nil {
		return nil
	}

	if err := json.Unmarshal(file, &data); err != nil {
		return nil
	}

	return s.getUserByAccess(access, data.AccessAccounts)
}

func (IAMServiceUnsupported) getUserByAccess(access string, users []Account) *Account {
	for i := range users {
		if users[i].Access == access {
			return &users[i]
		}
	}

	return nil
}
