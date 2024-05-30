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
	"time"
)

const (
	iamFile       = "users.json"
	iamBackupFile = "users.json.backup"
)

// IAMServiceInternal manages the internal IAM service
type IAMServiceInternal struct {
	dir string
}

// UpdateAcctFunc accepts the current data and returns the new data to be stored
type UpdateAcctFunc func([]byte) ([]byte, error)

// iAMConfig stores all internal IAM accounts
type iAMConfig struct {
	AccessAccounts map[string]Account `json:"accessAccounts"`
}

var _ IAMService = &IAMServiceInternal{}

// NewInternal creates a new instance for the Internal IAM service
func NewInternal(dir string) (*IAMServiceInternal, error) {
	i := &IAMServiceInternal{
		dir: dir,
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
	return s.storeIAM(func(data []byte) ([]byte, error) {
		conf, err := parseIAM(data)
		if err != nil {
			return nil, fmt.Errorf("get iam data: %w", err)
		}

		_, ok := conf.AccessAccounts[account.Access]
		if ok {
			return nil, fmt.Errorf("account already exists")
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

// DeleteUserAccount deletes the specified user account. Does not check if
// account exists.
func (s *IAMServiceInternal) DeleteUserAccount(access string) error {
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
	// coordination. So the strategy here is to read the current file data.
	// If the file doesn't exist, then we assume someone else is currently
	// updating the file. So we just need to keep retrying. We also need
	// to make sure the data is consistent within a single update. So racing
	// writes to a file would possibly leave this in some invalid state.
	// We can get atomic updates with rename. If we read the data, update
	// the data, write to a temp file, then rename the tempfile back to the
	// data file. This should always result in a complete data image.

	// There is at least one unsolved failure mode here.
	// If a gateway removes the data file and then crashes, all other
	// gateways will retry forever thinking that the original will eventually
	// write the file.

	retries := 0
	fname := filepath.Join(s.dir, iamFile)

	for {
		b, err := os.ReadFile(fname)
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}

			// we have been unsuccessful trying to read the iam file
			// so this must be the case where something happened and
			// the file did not get updated successfully, and probably
			// isn't going to be. The recovery procedure would be to
			// copy the backup file into place of the original.
			return fmt.Errorf("no iam file, needs backup recovery")
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read iam file: %w", err)
		}

		// reset retries on successful read
		retries = 0

		err = os.Remove(fname)
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			time.Sleep(backoff)
			continue
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove old iam file: %w", err)
		}

		// save copy of data
		datacopy := make([]byte, len(b))
		copy(datacopy, b)

		// make a backup copy in case we crash before update
		// this is after remove, so there is a small window something
		// can go wrong, but the remove should barrier other gateways
		// from trying to write backup at the same time. Only one
		// gateway will successfully remove the file.
		os.WriteFile(filepath.Join(s.dir, iamBackupFile), b, iamMode)

		b, err = update(b)
		if err != nil {
			// update failed, try to write old data back out
			os.WriteFile(fname, datacopy, iamMode)
			return fmt.Errorf("update iam data: %w", err)
		}

		err = s.writeTempFile(b)
		if err != nil {
			// update failed, try to write old data back out
			os.WriteFile(fname, datacopy, iamMode)
			return err
		}

		break
	}

	return nil
}

func (s *IAMServiceInternal) writeTempFile(b []byte) error {
	fname := filepath.Join(s.dir, iamFile)

	f, err := os.CreateTemp(s.dir, iamFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	err = os.Rename(f.Name(), fname)
	if err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}
