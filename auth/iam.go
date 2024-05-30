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
	"fmt"
	"time"
)

type Role string

const (
	RoleUser     Role = "user"
	RoleAdmin    Role = "admin"
	RoleUserPlus Role = "userplus"
)

// Account is a gateway IAM account
type Account struct {
	Access  string `json:"access"`
	Secret  string `json:"secret"`
	Role    Role   `json:"role"`
	UserID  int    `json:"userID"`
	GroupID int    `json:"groupID"`
}

// IAMService is the interface for all IAM service implementations
//
//go:generate moq -out ../s3api/controllers/iam_moq_test.go -pkg controllers . IAMService
type IAMService interface {
	CreateAccount(account Account) error
	GetUserAccount(access string) (Account, error)
	DeleteUserAccount(access string) error
	ListUserAccounts() ([]Account, error)
	Shutdown() error
}

var ErrNoSuchUser = errors.New("user not found")

type Opts struct {
	Dir                string
	LDAPServerURL      string
	LDAPBindDN         string
	LDAPPassword       string
	LDAPQueryBase      string
	LDAPObjClasses     string
	LDAPAccessAtr      string
	LDAPSecretAtr      string
	LDAPRoleAtr        string
	S3Access           string
	S3Secret           string
	S3Region           string
	S3Bucket           string
	S3Endpoint         string
	S3DisableSSlVerfiy bool
	S3Debug            bool
	CacheDisable       bool
	CacheTTL           int
	CachePrune         int
}

func New(o *Opts) (IAMService, error) {
	var svc IAMService
	var err error

	switch {
	case o.Dir != "":
		svc, err = NewInternal(o.Dir)
		fmt.Printf("initializing internal IAM with %q\n", o.Dir)
	case o.LDAPServerURL != "":
		svc, err = NewLDAPService(o.LDAPServerURL, o.LDAPBindDN, o.LDAPPassword,
			o.LDAPQueryBase, o.LDAPAccessAtr, o.LDAPSecretAtr, o.LDAPRoleAtr,
			o.LDAPObjClasses)
		fmt.Printf("initializing LDAP IAM with %q\n", o.LDAPServerURL)
	case o.S3Endpoint != "":
		svc, err = NewS3(o.S3Access, o.S3Secret, o.S3Region, o.S3Bucket,
			o.S3Endpoint, o.S3DisableSSlVerfiy, o.S3Debug)
		fmt.Printf("initializing S3 IAM with '%v/%v'\n",
			o.S3Endpoint, o.S3Bucket)
	default:
		// if no iam options selected, default to the single user mode
		fmt.Println("No IAM service configured, enabling single account mode")
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
