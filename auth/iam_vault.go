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
	"strings"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type VaultIAMService struct {
	client            *vault.Client
	reqOpts           []vault.RequestOption
	secretStoragePath string
	rootAcc           Account
}

var _ IAMService = &VaultIAMService{}

func NewVaultIAMService(rootAcc Account, endpoint, secretStoragePath, mountPath, rootToken, roleID, roleSecret, serverCert, clientCert, clientCertKey string) (IAMService, error) {
	opts := []vault.ClientOption{
		vault.WithAddress(endpoint),
		// set request timeout to 10 secs
		vault.WithRequestTimeout(10 * time.Second),
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

	reqOpts := []vault.RequestOption{}
	// if mount path is not specified, it defaults to "approle"
	if mountPath != "" {
		reqOpts = append(reqOpts, vault.WithMountPath(mountPath))
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
			RoleId:   roleID,
			SecretId: roleSecret,
		}, reqOpts...)
		cancel()
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
		reqOpts:           reqOpts,
		secretStoragePath: secretStoragePath,
		rootAcc:           rootAcc,
	}, nil
}

func (vt *VaultIAMService) CreateAccount(account Account) error {
	if vt.rootAcc.Access == account.Access {
		return ErrUserExists
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := vt.client.Secrets.KvV2Write(ctx, vt.secretStoragePath+"/"+account.Access, schema.KvV2WriteRequest{
		Data: map[string]any{
			account.Access: account,
		},
		Options: map[string]interface{}{
			"cas": 0,
		},
	}, vt.reqOpts...)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return ErrUserExists
		}
		return err
	}

	return nil
}

func (vt *VaultIAMService) GetUserAccount(access string) (Account, error) {
	if vt.rootAcc.Access == access {
		return vt.rootAcc, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := vt.client.Secrets.KvV2Read(ctx, vt.secretStoragePath+"/"+access, vt.reqOpts...)
	cancel()
	if err != nil {
		return Account{}, err
	}

	acc, err := parseVaultUserAccount(resp.Data.Data, access)
	if err != nil {
		return Account{}, err
	}

	return acc, nil
}

func (vt *VaultIAMService) UpdateUserAccount(access string, props MutableProps) error {
	//TODO: We need something like a transaction here ?
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := vt.client.Secrets.KvV2DeleteMetadataAndAllVersions(ctx, vt.secretStoragePath+"/"+access, vt.reqOpts...)
	cancel()
	if err != nil {
		return err
	}
	return nil
}

func (vt *VaultIAMService) ListUserAccounts() ([]Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := vt.client.Secrets.KvV2List(ctx, vt.secretStoragePath, vt.reqOpts...)
	cancel()
	if err != nil {
		if vault.IsErrorStatus(err, 404) {
			return []Account{}, nil
		}
		return nil, err
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

func parseVaultUserAccount(data map[string]interface{}, access string) (acc Account, err error) {
	usrAcc, ok := data[access].(map[string]interface{})
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
