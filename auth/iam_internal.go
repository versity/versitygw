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
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	iamFile       = "users.json"
	iamBackupFile = "users.json.backup"
)

var (
	cacheDuration = 5 * time.Minute
)

// IAMServiceInternal manages the internal IAM service
type IAMServiceInternal struct {
	path string

	mu        sync.RWMutex
	accts     iAMConfig
	serial    uint32
	iamcache  []byte
	iamvalid  bool
	iamexpire time.Time
}

// UpdateAcctFunc accepts the current data and returns the new data to be stored
type UpdateAcctFunc func([]byte) ([]byte, error)

// iAMConfig stores all internal IAM accounts
type iAMConfig struct {
	AccessAccounts map[string]Account `json:"accessAccounts"`
}

var _ IAMService = &IAMServiceInternal{}

// NewInternal creates a new instance for the Internal IAM service
func NewInternal(path string) (*IAMServiceInternal, error) {
	i := &IAMServiceInternal{
		path: path,
	}

	err := i.initIAM()
	if err != nil {
		return nil, fmt.Errorf("init iam: %w", err)
	}

	err = i.updateCache()
	if err != nil {
		return nil, fmt.Errorf("refresh iam cache: %w", err)
	}

	return i, nil
}

// CreateAccount creates a new IAM account. Returns an error if the account
// already exists.
func (s *IAMServiceInternal) CreateAccount(account Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storeIAM(func(data []byte) ([]byte, error) {
		var conf iAMConfig

		if len(data) > 0 {
			if err := json.Unmarshal(data, &conf); err != nil {
				return nil, fmt.Errorf("failed to parse iam: %w", err)
			}
		} else {
			conf = iAMConfig{AccessAccounts: map[string]Account{}}
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
		s.accts = conf

		return b, nil
	})
}

// GetUserAccount retrieves account info for the requested user. Returns
// ErrNoSuchUser if the account does not exist.
func (s *IAMServiceInternal) GetUserAccount(access string) (Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.getIAM()
	if err != nil {
		return Account{}, fmt.Errorf("get iam data: %w", err)
	}

	serial := crc32.ChecksumIEEE(data)
	if serial != s.serial {
		s.mu.RUnlock()
		err := s.updateCache()
		s.mu.RLock()
		if err != nil {
			return Account{}, fmt.Errorf("refresh iam cache: %w", err)
		}
	}

	acct, ok := s.accts.AccessAccounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}

	return acct, nil
}

// updateCache must be called with no locks held
func (s *IAMServiceInternal) updateCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.getIAM()
	if err != nil {
		return fmt.Errorf("get iam data: %w", err)
	}

	serial := crc32.ChecksumIEEE(data)

	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.accts); err != nil {
			return fmt.Errorf("failed to parse the config file: %w", err)
		}
	} else {
		s.accts.AccessAccounts = make(map[string]Account)
	}

	s.serial = serial

	return nil
}

// DeleteUserAccount deletes the specified user account. Does not check if
// account exists.
func (s *IAMServiceInternal) DeleteUserAccount(access string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storeIAM(func(data []byte) ([]byte, error) {
		if len(data) == 0 {
			// empty config, do nothing
			return data, nil
		}

		var conf iAMConfig

		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, fmt.Errorf("failed to parse iam: %w", err)
		}

		delete(conf.AccessAccounts, access)

		b, err := json.Marshal(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize iam: %w", err)
		}

		s.accts = conf

		return b, nil
	})
}

// ListUserAccounts lists all the user accounts stored.
func (s *IAMServiceInternal) ListUserAccounts() (accs []Account, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.getIAM()
	if err != nil {
		return []Account{}, fmt.Errorf("get iam data: %w", err)
	}

	serial := crc32.ChecksumIEEE(data)
	if serial != s.serial {
		s.mu.RUnlock()
		err := s.updateCache()
		s.mu.RLock()
		if err != nil {
			return []Account{}, fmt.Errorf("refresh iam cache: %w", err)
		}
	}

	for access, usr := range s.accts.AccessAccounts {
		accs = append(accs, Account{
			Access: access,
			Secret: usr.Secret,
			Role:   usr.Role,
		})
	}

	return accs, nil
}

const (
	iamMode = 0600
)

func (s *IAMServiceInternal) initIAM() error {
	fname := filepath.Join(s.path, iamFile)

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

func (s *IAMServiceInternal) getIAM() ([]byte, error) {
	if !s.iamvalid || !s.iamexpire.After(time.Now()) {
		err := s.refreshIAM()
		if err != nil {
			return nil, err
		}
	}

	return s.iamcache, nil
}

const (
	backoff  = 100 * time.Millisecond
	maxretry = 300
)

func (s *IAMServiceInternal) refreshIAM() error {
	// We are going to be racing with other running gateways without any
	// coordination. So we might find the file does not exist at times.
	// For this case we need to retry for a while assuming the other gateway
	// will eventually write the file. If it doesn't after the max retries,
	// then we will return the error.

	retries := 0

	for {
		b, err := os.ReadFile(filepath.Join(s.path, iamFile))
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}
			return fmt.Errorf("read iam file: %w", err)
		}
		if err != nil {
			return err
		}

		s.iamcache = b
		s.iamvalid = true
		s.iamexpire = time.Now().Add(cacheDuration)
		break
	}

	return nil
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
	fname := filepath.Join(s.path, iamFile)

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

		err = os.Remove(iamFile)
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
		os.WriteFile(filepath.Join(s.path, iamBackupFile), b, iamMode)

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

		s.iamcache = b
		s.iamvalid = true
		s.iamexpire = time.Now().Add(cacheDuration)
		break
	}

	return nil
}

func (s *IAMServiceInternal) writeTempFile(b []byte) error {
	fname := filepath.Join(s.path, iamFile)

	f, err := os.CreateTemp(s.path, iamFile)
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
