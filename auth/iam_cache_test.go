package auth

import (
	"errors"
	"testing"
	"time"
	"unsafe"
)

type freshTestService struct {
	IAMService
	accounts  map[string]Account
	fetches   int
	updateErr error
}

func (s *freshTestService) CreateAccount(account Account) error {
	s.accounts[account.Access] = account
	return nil
}

func (s *freshTestService) UpdateUserAccount(access string, props MutableProps) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	a, ok := s.accounts[access]
	if !ok {
		return ErrNoSuchUser
	}
	updateAcc(&a, props)
	s.accounts[access] = a
	return nil
}

func (s *freshTestService) GetUserAccount(access string) (Account, error) {
	s.fetches++
	a, ok := s.accounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}
	a.Access = access
	return a, nil
}

func TestIAMCacheCreateAccountInvalidates(t *testing.T) {
	svc := &freshTestService{accounts: map[string]Account{
		"acct": {Access: "acct", Secret: "stale", Role: RoleAdmin},
	}}
	c := NewCache(svc, time.Minute, time.Hour)
	defer c.Shutdown()

	// Simulate a stale entry left behind by a user deleted elsewhere.
	if _, err := c.GetUserAccount("acct"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	delete(svc.accounts, "acct")

	account := Account{
		Access: "acct", Secret: "secret", Role: RoleUser,
		UserID: 1001, GroupID: 1002, ProjectID: 1003,
	}
	if err := c.CreateAccount(account); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := c.GetUserAccount(account.Access)
	if err != nil {
		t.Fatalf("read after create: %v", err)
	}
	if got != account {
		t.Fatalf("read after create = %+v, want %+v", got, account)
	}
	if svc.fetches != 2 {
		t.Fatalf("create did not invalidate cache: %d backing fetches", svc.fetches)
	}

	if _, err := c.GetUserAccount(account.Access); err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if svc.fetches != 2 {
		t.Fatalf("read after create was not cached: %d backing fetches", svc.fetches)
	}
}

func TestIAMCacheUpdateUserAccountInvalidates(t *testing.T) {
	svc := &freshTestService{accounts: map[string]Account{
		"acct": {Access: "acct", Secret: "old", Role: RoleUser, UserID: 1001},
	}}
	c := NewCache(svc, time.Minute, time.Hour)
	defer c.Shutdown()

	if _, err := c.GetUserAccount("acct"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	svc.accounts["acct"] = Account{Access: "acct", Secret: "old", Role: RoleUser, UserID: 2002}

	failure := errors.New("update failed")
	svc.updateErr = failure
	if err := c.UpdateUserAccount("acct", MutableProps{Role: RoleAdmin}); !errors.Is(err, failure) {
		t.Fatalf("failed update = %v, want %v", err, failure)
	}
	if _, err := c.GetUserAccount("acct"); err != nil {
		t.Fatalf("read after failed update: %v", err)
	}
	if svc.fetches != 1 {
		t.Fatalf("failed update invalidated cache: %d backing fetches", svc.fetches)
	}

	svc.updateErr = nil
	if err := c.UpdateUserAccount("acct", MutableProps{Role: RoleAdmin}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := c.GetUserAccount("acct")
	if err != nil {
		t.Fatalf("read after update: %v", err)
	}
	if got.Role != RoleAdmin || got.UserID != 2002 {
		t.Fatalf("read after update = %+v, want role admin and user ID 2002", got)
	}
	if svc.fetches != 2 {
		t.Fatalf("successful update did not invalidate cache: %d backing fetches", svc.fetches)
	}
}

// The access key passed to GetUserAccount can alias a Fiber request buffer
// that is reused after the request. Neither the cache key nor the cached
// account's Access may change with it.
func TestIAMCacheKeyDoesNotAliasRequestBuffer(t *testing.T) {
	svc := &freshTestService{accounts: map[string]Account{
		"AKIAUSERAAAA": {Access: "AKIAUSERAAAA", Secret: "secret", Role: RoleUser},
	}}
	c := NewCache(svc, time.Minute, time.Hour)
	defer c.Shutdown()

	// unsafe.String stands in for Fiber's zero-copy byte-to-string conversion.
	buf := []byte("AKIAUSERAAAA")
	if _, err := c.GetUserAccount(unsafe.String(&buf[0], len(buf))); err != nil {
		t.Fatalf("prime: %v", err)
	}
	copy(buf, "AKIAUSERBBBB")

	got, err := c.GetUserAccount("AKIAUSERAAAA")
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if got.Access != "AKIAUSERAAAA" {
		t.Fatalf("cached account Access = %q, want %q", got.Access, "AKIAUSERAAAA")
	}
	if svc.fetches != 1 {
		t.Fatalf("cache key was corrupted by buffer reuse: %d backing fetches", svc.fetches)
	}
}

// GetUserAccountFresh must bypass a cached-but-stale entry and
// reflect the backing service state, refreshing the cache.
func TestIAMCacheGetUserAccountFresh(t *testing.T) {
	svc := &freshTestService{accounts: map[string]Account{
		"acct": {Access: "acct", Secret: "old", Role: RoleUser},
	}}
	c := NewCache(svc, time.Minute, time.Hour)
	defer c.Shutdown()

	// Prime the cache with the old secret.
	if _, err := c.GetUserAccount("acct"); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Change the backing store behind the cache.
	svc.accounts["acct"] = Account{Access: "acct", Secret: "new", Role: RoleAdmin}

	// Cached read still serves the stale entry.
	got, err := c.GetUserAccount("acct")
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if got.Secret != "old" {
		t.Fatalf("cached read: expected stale secret, got %q", got.Secret)
	}

	// Fresh read must observe the update.
	got, err = c.GetUserAccountFresh("acct")
	if err != nil {
		t.Fatalf("fresh read: %v", err)
	}
	if got.Secret != "new" || got.Role != RoleAdmin {
		t.Fatalf("fresh read: got %+v", got)
	}

	// And the cache is refreshed as a side effect.
	got, err = c.GetUserAccount("acct")
	if err != nil {
		t.Fatalf("post-fresh cached read: %v", err)
	}
	if got.Secret != "new" {
		t.Fatalf("post-fresh cached read: cache not refreshed, got %q", got.Secret)
	}

	if svc.fetches != 2 {
		t.Fatalf("expected 2 backing fetches (prime + fresh), got %d", svc.fetches)
	}
}
