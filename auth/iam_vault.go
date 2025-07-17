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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

const requestTimeout = 10 * time.Second

type VaultIAMService struct {
	client            *vault.Client
	authReqOpts       []vault.RequestOption
	kvReqOpts         []vault.RequestOption
	secretStoragePath string
	rootAcc           Account
	creds             schema.AppRoleLoginRequest
}

var _ IAMService = &VaultIAMService{}

func NewVaultIAMService(rootAcc Account, endpoint, secretStoragePath,
	authMethod, mountPath, rootToken, roleID, roleSecret, serverCert,
	clientCert, clientCertKey string) (IAMService, error) {
	opts := []vault.ClientOption{
		vault.WithAddress(endpoint),
		vault.WithRequestTimeout(requestTimeout),
	}
	if serverCert != "" {
		tls := vault.TLSConfiguration{}

		tls.ServerCertificate.FromBytes = []byte(serverCert)
		if clientCert != "" {
			if clientCertKey == "" {
				return nil, fmt.Errorf("client certificate and client certificate key should both be specified")
			}

			tls.ClientCertificate.FromBytes = []byte(clientCert)
			tls.ClientCertificateKey.FromBytes = []byte(clientCertKey)
		}

		opts = append(opts, vault.WithTLS(tls))
	}

	client, err := vault.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("init vault client: %w", err)
	}

	authReqOpts := []vault.RequestOption{}
	// if auth method path is not specified, it defaults to "approle"
	if authMethod != "" {
		authReqOpts = append(authReqOpts, vault.WithMountPath(authMethod))
	}

	kvReqOpts := []vault.RequestOption{}
	// if mount path is not specified, it defaults to "kv-v2"
	if mountPath != "" {
		kvReqOpts = append(kvReqOpts, vault.WithMountPath(mountPath))
	}

	creds := schema.AppRoleLoginRequest{
		RoleId:   roleID,
		SecretId: roleSecret,
	}

	// Authentication
	switch {
	case rootToken != "":
		err := client.SetToken(rootToken)
		if err != nil {
			return nil, fmt.Errorf("root token authentication failure: %w", err)
		}
	case roleID != "":
		if roleSecret == "" {
			return nil, fmt.Errorf("role id and role secret must both be specified")
		}

		resp, err := client.Auth.AppRoleLogin(context.Background(),
			creds, authReqOpts...)
		if err != nil {
			return nil, fmt.Errorf("approle authentication failure: %w", err)
		}

		if err := client.SetToken(resp.Auth.ClientToken); err != nil {
			return nil, fmt.Errorf("approle authentication set token failure: %w", err)
		}
	default:
		return nil, fmt.Errorf("vault authentication requires either roleid/rolesecret or root token")
	}

	return &VaultIAMService{
		client:            client,
		authReqOpts:       authReqOpts,
		kvReqOpts:         kvReqOpts,
		secretStoragePath: secretStoragePath,
		rootAcc:           rootAcc,
		creds:             creds,
	}, nil
}

func (vt *VaultIAMService) reAuthIfNeeded(err error) error {
	if err == nil {
		return nil
	}

	// Vault returns 403 for expired/revoked tokens
	// pass all other errors back unchanged
	if !vault.IsErrorStatus(err, http.StatusForbidden) {
		return err
	}

	resp, authErr := vt.client.Auth.AppRoleLogin(context.Background(),
		vt.creds, vt.authReqOpts...)
	if authErr != nil {
		return fmt.Errorf("vault re-authentication failure: %w", authErr)
	}
	if err := vt.client.SetToken(resp.Auth.ClientToken); err != nil {
		return fmt.Errorf("vault re-authentication set token failure: %w", err)
	}

	return nil
}

func (vt *VaultIAMService) CreateAccount(account Account) error {
	if vt.rootAcc.Access == account.Access {
		return ErrUserExists
	}
	_, err := vt.client.Secrets.KvV2Write(context.Background(),
		vt.secretStoragePath+"/"+account.Access, schema.KvV2WriteRequest{
			Data: map[string]any{
				account.Access: account,
			},
			Options: map[string]any{
				"cas": 0,
			},
		}, vt.kvReqOpts...)
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return ErrUserExists
		}

		reauthErr := vt.reAuthIfNeeded(err)
		if reauthErr != nil {
			return reauthErr
		}
		// retry once after re-auth
		_, err = vt.client.Secrets.KvV2Write(context.Background(),
			vt.secretStoragePath+"/"+account.Access, schema.KvV2WriteRequest{
				Data: map[string]any{
					account.Access: account,
				},
				Options: map[string]any{
					"cas": 0,
				},
			}, vt.kvReqOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "check-and-set") {
				return ErrUserExists
			}
			return err
		}
		return nil
	}
	return nil
}

func (vt *VaultIAMService) GetUserAccount(access string) (Account, error) {
	if vt.rootAcc.Access == access {
		return vt.rootAcc, nil
	}
	resp, err := vt.client.Secrets.KvV2Read(context.Background(),
		vt.secretStoragePath+"/"+access, vt.kvReqOpts...)
	if err != nil {
		reauthErr := vt.reAuthIfNeeded(err)
		if reauthErr != nil {
			return Account{}, reauthErr
		}
		// retry once after re-auth
		resp, err = vt.client.Secrets.KvV2Read(context.Background(),
			vt.secretStoragePath+"/"+access, vt.kvReqOpts...)
		if err != nil {
			return Account{}, err
		}
	}
	acc, err := parseVaultUserAccount(resp.Data.Data, access)
	if err != nil {
		return Account{}, err
	}
	return acc, nil
}

func (vt *VaultIAMService) UpdateUserAccount(access string, props MutableProps) error {
	acc, err := vt.GetUserAccount(access)
	if err != nil {
		return err
	}
	updateAcc(&acc, props)
	err = vt.DeleteUserAccount(access)
	if err != nil {
		return err
	}
	err = vt.CreateAccount(acc)
	if err != nil {
		return err
	}
	return nil
}

func (vt *VaultIAMService) DeleteUserAccount(access string) error {
	_, err := vt.client.Secrets.KvV2DeleteMetadataAndAllVersions(context.Background(),
		vt.secretStoragePath+"/"+access, vt.kvReqOpts...)
	if err != nil {
		reauthErr := vt.reAuthIfNeeded(err)
		if reauthErr != nil {
			return reauthErr
		}
		// retry once after re-auth
		_, err = vt.client.Secrets.KvV2DeleteMetadataAndAllVersions(context.Background(),
			vt.secretStoragePath+"/"+access, vt.kvReqOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}

func (vt *VaultIAMService) ListUserAccounts() ([]Account, error) {
	resp, err := vt.client.Secrets.KvV2List(context.Background(),
		vt.secretStoragePath, vt.kvReqOpts...)
	if err != nil {
		reauthErr := vt.reAuthIfNeeded(err)
		if reauthErr != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return []Account{}, nil
			}
			return nil, reauthErr
		}
		// retry once after re-auth
		resp, err = vt.client.Secrets.KvV2List(context.Background(),
			vt.secretStoragePath, vt.kvReqOpts...)
		if err != nil {
			if vault.IsErrorStatus(err, http.StatusNotFound) {
				return []Account{}, nil
			}
			return nil, err
		}
	}
	accs := []Account{}
	for _, acss := range resp.Data.Keys {
		acc, err := vt.GetUserAccount(acss)
		if err != nil {
			return nil, err
		}
		accs = append(accs, acc)
	}
	return accs, nil
}

// the client doesn't have explicit shutdown, as it uses http.Client
func (vt *VaultIAMService) Shutdown() error {
	return nil
}

var errInvalidUser error = errors.New("invalid user account entry in secrets engine")

func parseVaultUserAccount(data map[string]any, access string) (acc Account, err error) {
	usrAcc, ok := data[access].(map[string]any)
	if !ok {
		return acc, errInvalidUser
	}

	acss, ok := usrAcc["access"].(string)
	if !ok {
		return acc, errInvalidUser
	}
	secret, ok := usrAcc["secret"].(string)
	if !ok {
		return acc, errInvalidUser
	}
	role, ok := usrAcc["role"].(string)
	if !ok {
		return acc, errInvalidUser
	}
	userIdJson, ok := usrAcc["userID"].(json.Number)
	if !ok {
		return acc, errInvalidUser
	}
	userId, err := userIdJson.Int64()
	if err != nil {
		return acc, errInvalidUser
	}
	groupIdJson, ok := usrAcc["groupID"].(json.Number)
	if !ok {
		return acc, errInvalidUser
	}
	groupId, err := groupIdJson.Int64()
	if err != nil {
		return acc, errInvalidUser
	}

	return Account{
		Access:  acss,
		Secret:  secret,
		Role:    Role(role),
		UserID:  int(userId),
		GroupID: int(groupId),
	}, nil
}
