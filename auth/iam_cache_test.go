package auth

import (
	"testing"
	"time"
)

type freshTestService struct {
	IAMService
	accounts map[string]Account
	fetches  int
}

func (s *freshTestService) GetUserAccount(access string) (Account, error) {
	s.fetches++
	a, ok := s.accounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}
	return a, nil
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
