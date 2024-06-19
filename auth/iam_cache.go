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
	"strings"
	"sync"
	"time"
)

// IAMCache is an in memory cache of the IAM accounts
// with expiration. This helps to alleviate the load on
// the real IAM service if the gateway is handling
// many requests. This forwards account updates to the
// underlying service, and returns cached results while
// the in memory account is not expired.
type IAMCache struct {
	service  IAMService
	iamcache *icache
	cancel   context.CancelFunc
}

var _ IAMService = &IAMCache{}

type item struct {
	value Account
	exp   time.Time
}

type icache struct {
	sync.RWMutex
	expire time.Duration
	items  map[string]item
}

func (i *icache) set(k string, v Account) {
	cpy := v
	i.Lock()
	i.items[k] = item{
		exp:   time.Now().Add(i.expire),
		value: cpy,
	}
	i.Unlock()
}

func (i *icache) get(k string) (Account, bool) {
	i.RLock()
	v, ok := i.items[k]
	i.RUnlock()
	if !ok || !v.exp.After(time.Now()) {
		return Account{}, false
	}
	return v.value, true
}

func (i *icache) update(k string, props MutableProps) {
	i.Lock()
	defer i.Unlock()

	item, found := i.items[k]
	if found {
		updateAcc(&item.value, props)

		// refresh the expiration date
		item.exp = time.Now().Add(i.expire)

		i.items[k] = item
	}
}

func (i *icache) Delete(k string) {
	i.Lock()
	delete(i.items, k)
	i.Unlock()
}

func (i *icache) gcCache(ctx context.Context, interval time.Duration) {
	for {
		if ctx.Err() != nil {
			break
		}

		now := time.Now()

		i.Lock()
		// prune expired entries
		for k, v := range i.items {
			if now.After(v.exp) {
				delete(i.items, k)
			}
		}
		i.Unlock()

		// sleep for the clean interval or context cancelation,
		// whichever comes first
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}

// NewCache initializes an IAM cache for the provided service. The expireTime
// is the duration a cache entry can be valid, and the cleanupInterval is
// how often to scan cache and cleanup expired entries.
func NewCache(service IAMService, expireTime, cleanupInterval time.Duration) *IAMCache {
	i := &IAMCache{
		service: service,
		iamcache: &icache{
			items:  make(map[string]item),
			expire: expireTime,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go i.iamcache.gcCache(ctx, cleanupInterval)
	i.cancel = cancel

	return i
}

// CreateAccount send create to IAM service and creates an account cache entry
func (c *IAMCache) CreateAccount(account Account) error {
	err := c.service.CreateAccount(account)
	if err != nil {
		return err
	}

	// we need a copy of account to be able to store beyond the
	// lifetime of the request, otherwise Fiber will reuse and corrupt
	// these entries
	acct := Account{
		Access: strings.Clone(account.Access),
		Secret: strings.Clone(account.Secret),
		Role:   Role(strings.Clone(string(account.Role))),
	}

	c.iamcache.set(acct.Access, acct)
	return nil
}

// GetUserAccount retrieves the cache account if it is in the cache and not
// expired. Otherwise retrieves from underlying IAM service and caches
// result for the expire duration.
func (c *IAMCache) GetUserAccount(access string) (Account, error) {
	acct, found := c.iamcache.get(access)
	if found {
		return acct, nil
	}

	a, err := c.service.GetUserAccount(access)
	if err != nil {
		return Account{}, err
	}

	c.iamcache.set(access, a)
	return a, nil
}

// DeleteUserAccount deletes account from IAM service and cache
func (c *IAMCache) DeleteUserAccount(access string) error {
	err := c.service.DeleteUserAccount(access)
	if err != nil {
		return err
	}

	c.iamcache.Delete(access)
	return nil
}

func (c *IAMCache) UpdateUserAccount(access string, props MutableProps) error {
	err := c.service.UpdateUserAccount(access, props)
	if err != nil {
		return err
	}

	c.iamcache.update(access, props)
	return nil
}

// ListUserAccounts is a passthrough to the underlying service and
// does not make use of the cache
func (c *IAMCache) ListUserAccounts() ([]Account, error) {
	return c.service.ListUserAccounts()
}

// Shutdown graceful termination of service
func (c *IAMCache) Shutdown() error {
	c.cancel()
	return nil
}
