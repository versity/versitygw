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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/versity/versitygw/internal/azblobclient"
)

// IAMServiceAzure stores user accounts in an Azure blob.
// The storage account, credentials and container are provided
// from cli configuration, with the same rules as the azure backend.
// The blob format and name is the same as the internal IAM service:
// coming from iAMConfig and iamFile in iam_internal.
//
// Updates are conditional on the blob ETag, so concurrent updates from
// multiple load balanced gateway instances do not overwrite each other.
type IAMServiceAzure struct {
	// This mutex serializes updates from multiple requests to this
	// gateway instance, avoiding needless ETag conflicts between them.
	sync.Mutex

	container  string
	rootAcc    Account
	client     *azblob.Client
	retryDelay time.Duration
}

var _ IAMService = &IAMServiceAzure{}

// errNoChange is returned by a storeIAM update to report that the
// accounts already are as requested, so there is nothing to store.
var errNoChange = errors.New("no change")

const (
	// azureIAMMaxAttempts is how many times an update is attempted with
	// fresh data after losing a race with another gateway instance.
	azureIAMMaxAttempts = 10
	// azureIAMRetryDelay is the upper bound of the random wait before
	// the first retry, doubled at each further retry.
	azureIAMRetryDelay = 10 * time.Millisecond
	// azureIAMTimeout bounds each request to Azure, including the SDK
	// retries, so that an unresponsive service does not hang the gateway.
	azureIAMTimeout = 30 * time.Second
)

func NewAzure(rootAcc Account, accountName, accountKey, serviceURL, sasToken, container string) (*IAMServiceAzure, error) {
	if container == "" {
		return nil, fmt.Errorf("must provide azure IAM service container")
	}

	if accountName == "" && serviceURL == "" {
		return nil, fmt.Errorf("must provide azure IAM storage account or service URL")
	}

	if accountKey != "" && accountName == "" {
		return nil, fmt.Errorf("azure IAM access key requires a storage account name")
	}

	client, _, err := azblobclient.New(accountName, accountKey, serviceURL, sasToken)
	if err != nil {
		return nil, fmt.Errorf("init azure IAM: %w", err)
	}

	s := &IAMServiceAzure{
		container:  container,
		rootAcc:    rootAcc,
		client:     client,
		retryDelay: azureIAMRetryDelay,
	}

	_, _, err = s.getAccounts()
	if err != nil {
		return nil, fmt.Errorf("azure IAM: read accounts from container %q: %w", container, err)
	}

	return s, nil
}

func (s *IAMServiceAzure) CreateAccount(account Account) error {
	if s.rootAcc.Access == account.Access {
		return ErrUserExists
	}

	return s.storeIAM(func(conf *iAMConfig) error {
		_, ok := conf.AccessAccounts[account.Access]
		if ok {
			return ErrUserExists
		}
		conf.AccessAccounts[account.Access] = account
		return nil
	})
}

func (s *IAMServiceAzure) GetUserAccount(access string) (Account, error) {
	if access == s.rootAcc.Access {
		return s.rootAcc, nil
	}

	conf, _, err := s.getAccounts()
	if err != nil {
		return Account{}, err
	}

	acct, ok := conf.AccessAccounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}

	return acct, nil
}

// ResolveAccounts returns the subset of accessKeyIDs that do not exist.
func (s *IAMServiceAzure) ResolveAccounts(accessKeyIDs []string) ([]string, error) {
	return resolveAccountsByLookup(accessKeyIDs, s.GetUserAccount)
}

func (s *IAMServiceAzure) UpdateUserAccount(access string, props MutableProps) error {
	return s.storeIAM(func(conf *iAMConfig) error {
		acc, ok := conf.AccessAccounts[access]
		if !ok {
			return ErrNoSuchUser
		}

		updateAcc(&acc, props)
		conf.AccessAccounts[access] = acc
		return nil
	})
}

// DeleteUserAccount deletes the specified user account. Deleting a
// missing account is not an error, like the internal IAM service.
func (s *IAMServiceAzure) DeleteUserAccount(access string) error {
	return s.storeIAM(func(conf *iAMConfig) error {
		_, ok := conf.AccessAccounts[access]
		if !ok {
			return errNoChange
		}
		delete(conf.AccessAccounts, access)
		return nil
	})
}

func (s *IAMServiceAzure) ListUserAccounts() ([]Account, error) {
	conf, _, err := s.getAccounts()
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(conf.AccessAccounts))
	for k := range conf.AccessAccounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var accs []Account
	for _, k := range keys {
		accs = append(accs, Account{
			Access:    k,
			Secret:    conf.AccessAccounts[k].Secret,
			Role:      conf.AccessAccounts[k].Role,
			UserID:    conf.AccessAccounts[k].UserID,
			GroupID:   conf.AccessAccounts[k].GroupID,
			ProjectID: conf.AccessAccounts[k].ProjectID,
		})
	}

	return accs, nil
}

func (s *IAMServiceAzure) Shutdown() error {
	return nil
}

// storeIAM reads the accounts, applies update and writes them back only
// if the blob has not changed in between. When another gateway instance
// updated it first, the update is applied again to the fresh data.
func (s *IAMServiceAzure) storeIAM(update func(conf *iAMConfig) error) error {
	s.Lock()
	defer s.Unlock()

	for attempt := range azureIAMMaxAttempts {
		if attempt > 0 {
			// wait a random, growing time so that instances racing
			// for the blob stop colliding at every attempt
			time.Sleep(rand.N(s.retryDelay << (attempt - 1)))
		}

		conf, etag, err := s.getAccounts()
		if err != nil {
			return err
		}

		err = update(&conf)
		if errors.Is(err, errNoChange) {
			return nil
		}
		if err != nil {
			return err
		}

		err = s.storeAccts(conf, etag)
		if bloberror.HasCode(err, bloberror.ConditionNotMet, bloberror.BlobAlreadyExists) {
			continue
		}
		return err
	}

	return fmt.Errorf("store accounts in %v: too many concurrent updates", iamFile)
}

// getAccounts returns the stored accounts and the ETag of the blob they
// were read from, or a nil ETag if the blob does not exist yet.
func (s *IAMServiceAzure) getAccounts() (iAMConfig, *azcore.ETag, error) {
	ctx, cancel := context.WithTimeout(context.Background(), azureIAMTimeout)
	defer cancel()

	resp, err := s.client.DownloadStream(ctx, s.container, iamFile, nil)
	if err != nil {
		// if the blob does not exist yet,
		// init empty accounts struct and return that
		if bloberror.HasCode(err, bloberror.BlobNotFound) {
			return defaultIAMConfig(), nil, nil
		}

		// all other errors, return the error
		return iAMConfig{}, nil, fmt.Errorf("get %v: %w", iamFile, err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return iAMConfig{}, nil, fmt.Errorf("read %v: %w", iamFile, err)
	}

	conf, err := parseIAM(b)
	if err != nil {
		return iAMConfig{}, nil, fmt.Errorf("parse iam data: %w", err)
	}

	return conf, resp.ETag, nil
}

// storeAccts writes the accounts over the blob version identified by
// etag, or creates the blob if etag is nil. The write fails with
// ConditionNotMet or BlobAlreadyExists if the blob changed meanwhile.
func (s *IAMServiceAzure) storeAccts(conf iAMConfig, etag *azcore.ETag) error {
	b, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to serialize iam: %w", err)
	}

	cond := &blob.ModifiedAccessConditions{IfMatch: etag}
	if etag == nil {
		cond = &blob.ModifiedAccessConditions{IfNoneMatch: to.Ptr(azcore.ETagAny)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), azureIAMTimeout)
	defer cancel()

	_, err = s.client.UploadBuffer(ctx, s.container, iamFile, b,
		&azblob.UploadBufferOptions{
			AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: cond},
		})
	if err != nil {
		return fmt.Errorf("store accounts in %v: %w", iamFile, err)
	}

	return nil
}
