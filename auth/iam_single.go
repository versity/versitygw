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
	"github.com/versity/versitygw/s3err"
)

// IAMServiceSingle manages the single tenant (root-only) IAM service
type IAMServiceSingle struct {
	root Account
}

var _ IAMService = &IAMServiceSingle{}

func NewIAMServiceSingle(r Account) IAMService {
	return &IAMServiceSingle{
		root: r,
	}
}

// CreateAccount not valid in single tenant mode
func (IAMServiceSingle) CreateAccount(account Account) error {
	return s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// GetUserAccount returns root account, if the root access key
// is provided and "ErrAdminUserNotFound" otherwise
func (s IAMServiceSingle) GetUserAccount(access string) (Account, error) {
	if access == s.root.Access {
		return s.root, nil
	}
	return Account{}, s3err.GetAPIError(s3err.ErrAdminUserNotFound)
}

// UpdateUserAccount no accounts in single tenant mode
func (IAMServiceSingle) UpdateUserAccount(access string, props MutableProps) error {
	return s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// DeleteUserAccount no accounts in single tenant mode
func (IAMServiceSingle) DeleteUserAccount(access string) error {
	return s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// ListUserAccounts no accounts in single tenant mode
func (IAMServiceSingle) ListUserAccounts() ([]Account, error) {
	return []Account{}, s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// Shutdown graceful termination of service
func (IAMServiceSingle) Shutdown() error {
	return nil
}
