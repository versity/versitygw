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

	"github.com/versity/versitygw/s3err"
)

type Role string

const (
	RoleUser     Role = "user"
	RoleAdmin    Role = "admin"
	RoleUserPlus Role = "userplus"
)

func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin:
		return true
	case RoleUser:
		return true
	case RoleUserPlus:
		return true
	default:
		return false
	}
}

// Account is a gateway IAM account
type Account struct {
	Access  string `json:"access"`
	Secret  string `json:"secret"`
	Role    Role   `json:"role"`
	UserID  int    `json:"userID"`
	GroupID int    `json:"groupID"`
}

type ListUserAccountsResult struct {
	Accounts []Account
}

// Mutable props, which could be changed when updating an IAM account
type MutableProps struct {
	Secret  *string `json:"secret"`
	Role    Role    `json:"role"`
	UserID  *int    `json:"userID"`
	GroupID *int    `json:"groupID"`
}

func (m MutableProps) Validate() error {
	if m.Role != "" && !m.Role.IsValid() {
		return s3err.GetAPIError(s3err.ErrAdminInvalidUserRole)
	}

	return nil
}

func updateAcc(acc *Account, props MutableProps) {
	if props.Secret != nil {
		acc.Secret = *props.Secret
	}
	if props.GroupID != nil {
		acc.GroupID = *props.GroupID
	}
	if props.UserID != nil {
		acc.UserID = *props.UserID
	}
	if props.Role != "" {
		acc.Role = props.Role
	}
}

// IAMService is the interface for all IAM service implementations
//
//go:generate moq -out ../s3api/controllers/iam_moq_test.go -pkg controllers . IAMService
type IAMService interface {
	CreateAccount(account Account) error
	GetUserAccount(access string) (Account, error)
	UpdateUserAccount(access string, props MutableProps) error
	DeleteUserAccount(access string) error
	ListUserAccounts() ([]Account, error)
	Shutdown() error
}

var (
	// ErrUserExists is returned when the user already exists
	ErrUserExists = errors.New("user already exists")
	// ErrNoSuchUser is returned when the user does not exist
	ErrNoSuchUser = errors.New("user not found")
)

type Opts struct {
	RootAccount            Account
	Dir                    string
	LDAPServerURL          string
	LDAPBindDN             string
	LDAPPassword           string
	LDAPQueryBase          string
	LDAPObjClasses         string
	LDAPAccessAtr          string
	LDAPSecretAtr          string
	LDAPRoleAtr            string
	LDAPUserIdAtr          string
	LDAPGroupIdAtr         string
	VaultEndpointURL       string
	VaultSecretStoragePath string
	VaultAuthMethod        string
	VaultMountPath         string
	VaultRootToken         string
	VaultRoleId            string
	VaultRoleSecret        string
	VaultServerCert        string
	VaultClientCert        string
	VaultClientCertKey     string
	S3Access               string
	S3Secret               string
	S3Region               string
	S3Bucket               string
	S3Endpoint             string
	S3DisableSSlVerfiy     bool
	S3Debug                bool
	CacheDisable           bool
	CacheTTL               int
	CachePrune             int
	IpaHost                string
	IpaVaultName           string
	IpaUser                string
	IpaPassword            string
	IpaInsecure            bool
	IpaDebug               bool
}

func New(o *Opts) (IAMService, error) {
	var svc IAMService
	var err error

	switch {
	case o.Dir != "":
		svc, err = NewInternal(o.RootAccount, o.Dir)
		fmt.Printf("initializing internal IAM with %q\n", o.Dir)
	case o.LDAPServerURL != "":
		svc, err = NewLDAPService(o.RootAccount, o.LDAPServerURL, o.LDAPBindDN, o.LDAPPassword,
			o.LDAPQueryBase, o.LDAPAccessAtr, o.LDAPSecretAtr, o.LDAPRoleAtr, o.LDAPUserIdAtr,
			o.LDAPGroupIdAtr, o.LDAPObjClasses)
		fmt.Printf("initializing LDAP IAM with %q\n", o.LDAPServerURL)
	case o.S3Endpoint != "":
		svc, err = NewS3(o.RootAccount, o.S3Access, o.S3Secret, o.S3Region, o.S3Bucket,
			o.S3Endpoint, o.S3DisableSSlVerfiy, o.S3Debug)
		fmt.Printf("initializing S3 IAM with '%v/%v'\n",
			o.S3Endpoint, o.S3Bucket)
	case o.VaultEndpointURL != "":
		svc, err = NewVaultIAMService(o.RootAccount, o.VaultEndpointURL, o.VaultSecretStoragePath,
			o.VaultAuthMethod, o.VaultMountPath, o.VaultRootToken, o.VaultRoleId, o.VaultRoleSecret,
			o.VaultServerCert, o.VaultClientCert, o.VaultClientCertKey)
		fmt.Printf("initializing Vault IAM with %q\n", o.VaultEndpointURL)
	case o.IpaHost != "":
		svc, err = NewIpaIAMService(o.RootAccount, o.IpaHost, o.IpaVaultName, o.IpaUser, o.IpaPassword, o.IpaInsecure, o.IpaDebug)
		fmt.Printf("initializing IPA IAM with %q\n", o.IpaHost)
	default:
		// if no iam options selected, default to the single user mode
		fmt.Println("No IAM service configured, enabling single account mode")
		return NewIAMServiceSingle(o.RootAccount), nil
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
