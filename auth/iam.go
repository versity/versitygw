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
	"errors"
	"time"
)

// Account is a gateway IAM account
type Account struct {
	Access    string `json:"access"`
	Secret    string `json:"secret"`
	Role      string `json:"role"`
	UserID    int    `json:"userID"`
	GroupID   int    `json:"groupID"`
	ProjectID int    `json:"projectID"`
}

// IAMService is the interface for all IAM service implementations
type IAMService interface {
	CreateAccount(account Account) error
	GetUserAccount(access string) (Account, error)
	DeleteUserAccount(access string) error
	ListUserAccounts() ([]Account, error)
	Shutdown() error
}

var ErrNoSuchUser = errors.New("user not found")

type Opts struct {
	Dir            string
	LDAPServerURL  string
	LDAPBindDN     string
	LDAPPassword   string
	LDAPQueryBase  string
	LDAPObjClasses string
	LDAPAccessAtr  string
	LDAPSecretAtr  string
	LDAPRoleAtr    string
	CacheDisable   bool
	CacheTTL       int
	CachePrune     int
}

func New(o *Opts) (IAMService, error) {
	var svc IAMService
	var err error

	switch {
	case o.Dir != "":
		svc, err = NewInternal(o.Dir)
	case o.LDAPServerURL != "":
		svc, err = NewLDAPService(o.LDAPServerURL, o.LDAPBindDN, o.LDAPPassword,
			o.LDAPQueryBase, o.LDAPAccessAtr, o.LDAPSecretAtr, o.LDAPRoleAtr,
			o.LDAPObjClasses)
	default:
		// if no iam options selected, default to the single user mode
		return IAMServiceSingle{}, nil
	}

	if err != nil {
		return nil, err
	}

	if o.CacheDisable {
		return svc, nil
	}

	return NewCache(svc,
		time.Duration(o.CacheTTL)*time.Second,
		time.Duration(o.CachePrune)*time.Second), nil
}
