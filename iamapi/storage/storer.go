// Copyright 2026 Versity Software
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

package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

// MaxAccessKeysPerUser is the maximum number of access keys a single IAM
// user may hold at once, matching the AWS IAM quota.
const MaxAccessKeysPerUser = 2

var (
	ErrUserIDAlreadyExists      = errors.New("iamapi: user id already exists")
	ErrAccessKeyIDAlreadyExists = errors.New("iamapi: access key id already exists")
)

type ListUsersInput struct {
	PathPrefix string
	Marker     string
	MaxItems   int32
}

type ListUsersOutput struct {
	Users       []types.User
	IsTruncated bool
	Marker      string
}

type UpdateUserInput struct {
	UserName    string
	NewPath     string
	NewUserName string
	NewArn      string
}

type CreateAccessKeyInput struct {
	UserName        string
	AccessKeyID     string
	SecretAccessKey string
	Status          string
	CreateDate      time.Time
}

type UpdateAccessKeyInput struct {
	UserName    string
	AccessKeyID string
	Status      string
}

type ListAccessKeysInput struct {
	UserName string
	Marker   string
	MaxItems int32
}

type ListAccessKeysOutput struct {
	AccessKeys  []types.AccessKeyMetadata
	IsTruncated bool
	Marker      string
}

type GetAccessKeyLastUsedOutput struct {
	UserName     string
	LastUsedDate time.Time
	ServiceName  string
	Region       string
}

// Storer is the IAM API storage backend contract.
type Storer interface {
	CreateUser(ctx context.Context, user types.User) (*types.User, error)
	DeleteUser(ctx context.Context, username string) error
	GetUser(ctx context.Context, username string) (*types.User, error)
	ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersOutput, error)
	UpdateUser(ctx context.Context, input UpdateUserInput) (*types.User, error)

	CreateAccessKey(ctx context.Context, input CreateAccessKeyInput) (*types.AccessKey, error)
	UpdateAccessKey(ctx context.Context, input UpdateAccessKeyInput) error
	DeleteAccessKey(ctx context.Context, username, accessKeyID string) error
	GetAccessKeyLastUsed(ctx context.Context, accessKeyID string) (*GetAccessKeyLastUsedOutput, error)
	ListAccessKeys(ctx context.Context, input ListAccessKeysInput) (*ListAccessKeysOutput, error)
}

func unwrapAPIError(err error) error {
	var apiErr iamerr.APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}

	return err
}

type Config struct {
	Dir   string
	Vault VaultConfig
}

func New(cfg Config) (Storer, error) {
	dir := strings.TrimSpace(cfg.Dir)
	vaultEndpoint := strings.TrimSpace(cfg.Vault.EndpointURL)

	selected := make([]string, 0, 2)
	if dir != "" {
		selected = append(selected, "dir")
	}
	if vaultEndpoint != "" {
		selected = append(selected, "vault")
	}

	switch len(selected) {
	case 0:
		return nil, fmt.Errorf("no IAM storer config specified")
	case 1:
	default:
		return nil, fmt.Errorf("multiple IAM storer configs specified: %s", strings.Join(selected, ", "))
	}

	switch {
	case dir != "":
		store, err := NewInternal(dir)
		if err != nil {
			return nil, fmt.Errorf("init internal IAM storer: %w", err)
		}
		return store, nil
	case vaultEndpoint != "":
		store, err := NewVault(cfg.Vault)
		if err != nil {
			return nil, fmt.Errorf("init vault IAM storer: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("no IAM storer config specified")
	}
}
