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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	iamFile       = "users.json"
	iamBackupFile = "users.json.backup"
)

// IAMServiceInternal manages the internal IAM service
type IAMServiceInternal struct {
	// This mutex will help with racing updates to the IAM data
	// from multiple requests to this gateway instance, but
	// will not help with racing updates to multiple load balanced
	// gateway instances. This is a limitation of the internal
	// IAM service. All account updates should be sent to a single
	// gateway instance if possible.
	sync.RWMutex
	dir     string
	rootAcc Account
}

// UpdateAcctFunc accepts the current data and returns the new data to be stored
type UpdateAcctFunc func([]byte) ([]byte, error)

// iAMConfig stores all internal IAM accounts
type iAMConfig struct {
	AccessAccounts map[string]Account `json:"accessAccounts"`
}

var _ IAMService = &IAMServiceInternal{}

// NewInternal creates a new instance for the Internal IAM service
func NewInternal(rootAcc Account, dir string) (*IAMServiceInternal, error) {
	i := &IAMServiceInternal{
		dir:     dir,
		rootAcc: rootAcc,
	}

	err := i.initIAM()
	if err != nil {
		return nil, fmt.Errorf("init iam: %w", err)
	}

	return i, nil
}

// CreateAccount creates a new IAM account. Returns an error if the account
// already exists.
func (s *IAMServiceInternal) CreateAccount(account Account) error {
	if account.Access == s.rootAcc.Access {
		return ErrUserExists
	}

	s.Lock()
	defer s.Unlock()

	return s.storeIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		_, ok := conf.AccessAccounts[account.Access]
		if ok {
			return nil, ErrUserExists
		}
		conf.AccessAccounts[account.Access] = account

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// GetUserAccount retrieves account info for the requested user. Returns
// ErrNoSuchUser if the account does not exist.
func (s *IAMServiceInternal) GetUserAccount(access string) (Account, error) {
	if access == s.rootAcc.Access {
		return s.rootAcc, nil
	}

	s.RLock()
	defer s.RUnlock()

	conf, err := s.getIAM()
	if err != nil {
		return Account{}, fmt.Errorf("get iam data: %w", err)
	}

	acct, ok := conf.AccessAccounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}

	return acct, nil
}

// UpdateUserAccount updates the specified user account fields. Returns
// ErrNoSuchUser if the account does not exist.
func (s *IAMServiceInternal) UpdateUserAccount(access string, props MutableProps) error {
	s.Lock()
	defer s.Unlock()

	return s.storeIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		acc, found := conf.AccessAccounts[access]
		if !found {
			return nil, ErrNoSuchUser
		}

		updateAcc(&acc, props)
		conf.AccessAccounts[access] = acc

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// DeleteUserAccount deletes the specified user account. Does not check if
// account exists.
func (s *IAMServiceInternal) DeleteUserAccount(access string) error {
	s.Lock()
	defer s.Unlock()

	return s.storeIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		delete(conf.AccessAccounts, access)

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		return b, nil
	})
}

// ListUserAccounts lists all the user accounts stored.
func (s *IAMServiceInternal) ListUserAccounts() ([]Account, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.getIAM()
	if err != nil {
		return []Account{}, fmt.Errorf("get iam data: %w", err)
	}

	keys := make([]string, 0, len(conf.AccessAccounts))
	for k := range conf.AccessAccounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var accs []Account
	for _, k := range keys {
		accs = append(accs, Account{
			Access:  k,
			Secret:  conf.AccessAccounts[k].Secret,
			Role:    conf.AccessAccounts[k].Role,
			UserID:  conf.AccessAccounts[k].UserID,
			GroupID: conf.AccessAccounts[k].GroupID,
		})
	}

	return accs, nil
}

// Shutdown graceful termination of service
func (s *IAMServiceInternal) Shutdown() error {
	return nil
}

const (
	iamMode = 0600
)

func (s *IAMServiceInternal) initIAM() error {
	fname := filepath.Join(s.dir, iamFile)

	_, err := os.ReadFile(fname)
	if errors.Is(err, fs.ErrNotExist) {
		b, err := json.Marshal(iAMConfig{AccessAccounts: map[string]Account{}})
		if err != nil {
			return fmt.Errorf("marshal default iam: %w", err)
		}
		err = os.WriteFile(fname, b, iamMode)
		if err != nil {
			return fmt.Errorf("write default iam: %w", err)
		}
	}

	return nil
}

func (s *IAMServiceInternal) getIAM() (iAMConfig, error) {
	b, err := s.readIAMData()
	if err != nil {
		return iAMConfig{}, err
	}

	return parseIAM(b)
}

func parseIAM(b []byte) (iAMConfig, error) {
	var conf iAMConfig
	if err := json.Unmarshal(b, &conf); err != nil {
		return iAMConfig{}, fmt.Errorf("failed to parse the config file: %w", err)
	}

	if conf.AccessAccounts == nil {
		conf.AccessAccounts = make(map[string]Account)
	}

	return conf, nil
}

const (
	backoff  = 100 * time.Millisecond
	maxretry = 300
)

func (s *IAMServiceInternal) readIAMData() ([]byte, error) {
	// We are going to be racing with other running gateways without any
	// coordination. So we might find the file does not exist at times.
	// For this case we need to retry for a while assuming the other gateway
	// will eventually write the file. If it doesn't after the max retries,
	// then we will return the error.

	retries := 0

	for {
		b, err := os.ReadFile(filepath.Join(s.dir, iamFile))
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}
			return nil, fmt.Errorf("read iam file: %w", err)
		}
		if err != nil {
			return nil, err
		}

		return b, nil
	}
}

func (s *IAMServiceInternal) storeIAM(update UpdateAcctFunc) error {
	// We are going to be racing with other running gateways without any
	// coordination. So the strategy here is to read the current file data,
	// update the data, write back out to a temp file, then rename the
	// temp file to the original file. This rename will replace the
	// original file with the new file. This is atomic and should always
	// allow for a consistent view of the data. There is a small
	// window where the file could be read and then updated by
	// another process. In this case any updates the other process did
	// will be lost. This is a limitation of the internal IAM service.
	// This should be rare, and even when it does happen should result
	// in a valid IAM file, just without the other process's updates.

	iamFname := filepath.Join(s.dir, iamFile)
	backupFname := filepath.Join(s.dir, iamBackupFile)

	b, err := os.ReadFile(iamFname)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read iam file: %w", err)
	}

	// save copy of data
	datacopy := make([]byte, len(b))
	copy(datacopy, b)

	// make a backup copy in case something happens
	err = s.writeUsingTempFile(b, backupFname)
	if err != nil {
		return fmt.Errorf("write backup iam file: %w", err)
	}

	b, err = update(b)
	if err != nil {
		return fmt.Errorf("update iam data: %w", err)
	}

	err = s.writeUsingTempFile(b, iamFname)
	if err != nil {
		return fmt.Errorf("write iam file: %w", err)
	}

	return nil
}

func (s *IAMServiceInternal) writeUsingTempFile(b []byte, fname string) error {
	f, err := os.CreateTemp(s.dir, iamFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	_, err = f.Write(b)
	f.Close()
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	err = os.Rename(f.Name(), fname)
	if err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}
