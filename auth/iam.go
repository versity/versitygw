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

// resolveAccountsByLookup implements ResolveAccounts for backends that have
// no batch endpoint, by calling getUserAccount once per access key and
// collecting the ones that don't exist.
func resolveAccountsByLookup(accessKeyIDs []string, getUserAccount func(string) (Account, error)) ([]string, error) {
	missing := []string{}
	for _, access := range accessKeyIDs {
		_, err := getUserAccount(access)
		if err != nil {
			if err == ErrNoSuchUser || err == s3err.GetAPIError(s3err.ErrAdminUserNotFound) {
				missing = append(missing, access)
				continue
			}
			if errors.Is(err, s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)) {
				return nil, err
			}
			return nil, fmt.Errorf("check user account: %w", err)
		}
	}
	return missing, nil
}

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
	Access    string `json:"access"`
	Secret    string `json:"secret"`
	Role      Role   `json:"role"`
	UserID    int    `json:"userID"`
	GroupID   int    `json:"groupID"`
	ProjectID int    `json:"projectID"`

	// SessionToken and IsSession describe a temporary credential minted by
	// AssumeRoleWithWebIdentity, and are set only by the S3 auth
	// middlewares for the duration of one request. They ride on Account
	// rather than on auth.AccessOptions so the ~55 controller sites that
	// already forward the request's Account into an authorization check
	// carry them without a single edit.
	//
	// Both are json:"-": a session is request state, never persisted by an
	// IAM backend nor echoed by the admin API.
	SessionToken string `json:"-"`
	IsSession    bool   `json:"-"`

	// Arn and RoleArn name this account the way a bucket policy's Principal
	// element does, and are set only by IAM backends whose identities have
	// ARNs at all — currently just the standalone IAM service client. Arn is
	// the caller's own ARN (an IAM user's, or a session's
	// arn:aws:sts::…:assumed-role/<role>/<session>); RoleArn is the ARN of
	// the role a session assumed, and is empty for everything else.
	//
	// Both are needed to match a session, because a Principal naming a role
	// matches every session of that role while one naming a session matches
	// only that session. When Arn is empty the gateway matches principals by
	// access key id instead, which is what every other backend has always
	// done — see Principals.matchFor.
	Arn     string `json:"-"`
	RoleArn string `json:"-"`
}

// String elides the two credential-bearing fields so an Account can't leak
// them into a log line through a %v/%+v verb. debuglogger redacts the
// X-Amz-Security-Token *header*, which does nothing for a struct printed
// after the token has been parsed out of it.
func (a Account) String() string {
	return fmt.Sprintf("Account{Access:%s, Secret:REDACTED, Role:%s, UserID:%d, GroupID:%d, ProjectID:%d, SessionToken:REDACTED, IsSession:%t, Arn:%s, RoleArn:%s}",
		a.Access, a.Role, a.UserID, a.GroupID, a.ProjectID, a.IsSession, a.Arn, a.RoleArn)
}

type ListUserAccountsResult struct {
	Accounts []Account
}

// Mutable props, which could be changed when updating an IAM account
type MutableProps struct {
	Secret    *string `json:"secret"`
	Role      Role    `json:"role"`
	UserID    *int    `json:"userID"`
	GroupID   *int    `json:"groupID"`
	ProjectID *int    `json:"projectID"`
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
	if props.ProjectID != nil {
		acc.ProjectID = *props.ProjectID
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
	ResolveAccounts(accessKeyIDs []string) ([]string, error)
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
	// ErrInvalidSessionToken is returned when a request's
	// X-Amz-Security-Token is missing for a temporary (ASIA…) access key,
	// doesn't match the session that key belongs to, or is present
	// alongside a permanent credential. Callers render it as S3's
	// InvalidToken, distinct from the InvalidAccessKeyId that ErrNoSuchUser
	// produces — matching real S3, which reports the two separately.
	ErrInvalidSessionToken = errors.New("invalid session token")
)

type Opts struct {
	RootAccount                 Account
	Dir                         string
	LDAPServerURL               string
	LDAPBindDN                  string
	LDAPPassword                string
	LDAPQueryBase               string
	LDAPObjClasses              string
	LDAPAccessAtr               string
	LDAPSecretAtr               string
	LDAPRoleAtr                 string
	LDAPUserIdAtr               string
	LDAPGroupIdAtr              string
	LDAPProjectIdAtr            string
	LDAPTLSSkipVerify           bool
	VaultEndpointURL            string
	VaultNamespace              string
	VaultSecretStoragePath      string
	VaultSecretStorageNamespace string
	VaultAuthMethod             string
	VaultAuthNamespace          string
	VaultMountPath              string
	VaultRootToken              string
	VaultRoleId                 string
	VaultRoleSecret             string
	VaultServerCert             string
	VaultClientCert             string
	VaultClientCertKey          string
	S3Access                    string
	S3Secret                    string
	S3Region                    string
	S3Bucket                    string
	S3Endpoint                  string
	S3DisableSSlVerfiy          bool
	CacheDisable                bool
	CacheTTL                    int
	CachePrune                  int
	IpaHost                     string
	IpaVaultName                string
	IpaUser                     string
	IpaPassword                 string
	IpaInsecure                 bool
	StandaloneIAMEndpoint       string
	StandaloneIAMAccess         string
	StandaloneIAMSecret         string
	StandaloneClientCert        string
	StandaloneClientCertKey     string
	StandaloneServerCA          string
	StandaloneDefaultUserID     int
	StandaloneDefaultGroupID    int
	StandaloneDefaultProjectID  int
	StandaloneRegion            string
}

func New(o *Opts) (IAMService, error) {
	var svc IAMService
	var err error

	switch {
	case o.StandaloneIAMEndpoint != "":
		fmt.Printf("initializing standalone IAM with %q\n", o.StandaloneIAMEndpoint)
		svc, err = NewIAMServiceStandalone(o.RootAccount, IAMServiceStandaloneConfig{
			Endpoint:         o.StandaloneIAMEndpoint,
			Access:           o.StandaloneIAMAccess,
			Secret:           o.StandaloneIAMSecret,
			ClientCert:       o.StandaloneClientCert,
			ClientCertKey:    o.StandaloneClientCertKey,
			ServerCA:         o.StandaloneServerCA,
			DefaultUserID:    o.StandaloneDefaultUserID,
			DefaultGroupID:   o.StandaloneDefaultGroupID,
			DefaultProjectID: o.StandaloneDefaultProjectID,
			Region:           o.StandaloneRegion,
		})
		if err != nil {
			return nil, err
		}
		// Never cache-wrapped, unlike every other backend below: IAMCache
		// only implements the base IAMService methods, so wrapping this
		// backend in it would silently strip the SigningKeyProvider/
		// PolicyEvaluator interfaces signature verification and policy
		// enforcement depend on — not just skip a performance
		// optimization, but break both outright.
		//
		// TODO: Do we need to implement cache for this ?
		return svc, nil
	case o.Dir != "":
		svc, err = NewInternal(o.RootAccount, o.Dir)
		fmt.Printf("initializing internal IAM with %q\n", o.Dir)
	case o.LDAPServerURL != "":
		svc, err = NewLDAPService(o.RootAccount, o.LDAPServerURL, o.LDAPBindDN, o.LDAPPassword,
			o.LDAPQueryBase, o.LDAPAccessAtr, o.LDAPSecretAtr, o.LDAPRoleAtr, o.LDAPUserIdAtr,
			o.LDAPGroupIdAtr, o.LDAPProjectIdAtr, o.LDAPObjClasses, o.LDAPTLSSkipVerify)
		fmt.Printf("initializing LDAP IAM with %q\n", o.LDAPServerURL)
	case o.S3Endpoint != "":
		svc, err = NewS3(o.RootAccount, o.S3Access, o.S3Secret, o.S3Region, o.S3Bucket,
			o.S3Endpoint, o.S3DisableSSlVerfiy)
		fmt.Printf("initializing S3 IAM with '%v/%v'\n",
			o.S3Endpoint, o.S3Bucket)
	case o.VaultEndpointURL != "":
		svc, err = NewVaultIAMService(o.RootAccount, o.VaultEndpointURL, o.VaultNamespace, o.VaultSecretStoragePath, o.VaultSecretStorageNamespace,
			o.VaultAuthMethod, o.VaultAuthNamespace, o.VaultMountPath, o.VaultRootToken, o.VaultRoleId, o.VaultRoleSecret,
			o.VaultServerCert, o.VaultClientCert, o.VaultClientCertKey)
		fmt.Printf("initializing Vault IAM with %q\n", o.VaultEndpointURL)
	case o.IpaHost != "":
		svc, err = NewIpaIAMService(o.RootAccount, o.IpaHost, o.IpaVaultName, o.IpaUser, o.IpaPassword, o.IpaInsecure)
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
