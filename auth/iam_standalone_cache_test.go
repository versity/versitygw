// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/versity/versitygw/iamapi/private"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/internal/sigv4auth"
)

const (
	cacheTestDate   = "20261030"
	cacheTestRegion = "us-east-1"
)

func TestStandaloneSigningKeyCacheReusesKey(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")
	client, calls, _ := newCachingStandaloneTestClient(t, sock, time.Minute, 0)

	uncached := newStandaloneTestClient(t, sock)
	_, wantAcc, err := uncached.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
	if err != nil {
		t.Fatalf("uncached DeriveSigningKey: %v", err)
	}
	wantKey := sigv4auth.DeriveKey("alicesecret", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)

	for i := range 5 {
		key, acc, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
		if err != nil {
			t.Fatalf("DeriveSigningKey #%d: %v", i, err)
		}
		if !bytes.Equal(key, wantKey) {
			t.Fatalf("DeriveSigningKey #%d key = %x, want %x", i, key, wantKey)
		}
		if acc != wantAcc {
			t.Fatalf("DeriveSigningKey #%d account = %+v, want %+v", i, acc, wantAcc)
		}
	}
	calls.expect(t, private.DerivePath, 1)

	// Every part of the credential scope is its own entry.
	scopes := [][3]string{
		{"20261031", cacheTestRegion, sigv4auth.ServiceS3},
		{cacheTestDate, "eu-west-1", sigv4auth.ServiceS3},
		{cacheTestDate, cacheTestRegion, sigv4auth.ServiceIAM},
	}
	for _, scope := range scopes {
		key, _, err := client.DeriveSigningKey("AKIAALICE", "", scope[0], scope[1], scope[2])
		if err != nil {
			t.Fatalf("DeriveSigningKey %v: %v", scope, err)
		}
		if want := sigv4auth.DeriveKey("alicesecret", scope[0], scope[1], scope[2]); !bytes.Equal(key, want) {
			t.Fatalf("DeriveSigningKey %v key = %x, want %x", scope, key, want)
		}
	}
	calls.expect(t, private.DerivePath, 1+len(scopes))
}

// TestStandaloneSigningKeyCacheExpires covers the cost of the cache: a key
// deactivated on the IAM service keeps working here until its entry expires,
// and no longer.
func TestStandaloneSigningKeyCacheExpires(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")
	client, calls, clock := newCachingStandaloneTestClient(t, sock, time.Minute, 0)

	derive := func() error {
		_, _, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
		return err
	}
	if err := derive(); err != nil {
		t.Fatalf("DeriveSigningKey: %v", err)
	}

	if err := store.UpdateAccessKey(context.Background(), storage.UpdateAccessKeyInput{
		UserName:    "alice",
		AccessKeyID: "AKIAALICE",
		Status:      "Inactive",
	}); err != nil {
		t.Fatalf("UpdateAccessKey: %v", err)
	}

	clock.advance(time.Minute - time.Second)
	if err := derive(); err != nil {
		t.Fatalf("DeriveSigningKey within the TTL: %v", err)
	}
	calls.expect(t, private.DerivePath, 1)

	clock.advance(time.Second)
	if err := derive(); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("DeriveSigningKey after the TTL = %v, want ErrNoSuchUser", err)
	}
	calls.expect(t, private.DerivePath, 2)
}

// TestStandaloneSigningKeyCacheForgetsGoneCredential covers a deactivated
// key that is still cached when a policy evaluation finds it gone: its
// cached signing keys are dropped then, so its next request is refused at
// authentication instead of when the entry expires, while other credentials
// keep theirs.
func TestStandaloneSigningKeyCacheForgetsGoneCredential(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")
	session := createStandaloneTestSession(t, store, "reader", "ASIASESSION", "sesssecret", "tok")
	client, calls, _ := newCachingStandaloneTestClient(t, sock, time.Hour, time.Minute)

	derive := func(access, token string) error {
		_, _, err := client.DeriveSigningKey(access, token, cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
		return err
	}
	if err := derive("AKIAALICE", ""); err != nil {
		t.Fatalf("DeriveSigningKey(AKIAALICE): %v", err)
	}
	if err := derive(session.AccessKeyId, session.SessionToken); err != nil {
		t.Fatalf("DeriveSigningKey(%s): %v", session.AccessKeyId, err)
	}

	if err := store.UpdateAccessKey(context.Background(), storage.UpdateAccessKeyInput{
		UserName:    "alice",
		AccessKeyID: "AKIAALICE",
		Status:      "Inactive",
	}); err != nil {
		t.Fatalf("UpdateAccessKey: %v", err)
	}
	if err := derive("AKIAALICE", ""); err != nil {
		t.Fatalf("DeriveSigningKey before anything found the key gone: %v", err)
	}
	calls.expect(t, private.DerivePath, 2)

	_, err := client.EvaluatePolicy("AKIAALICE", "", []Action{"s3:GetObject"}, []string{"arn:aws:s3:::b/k"}, cacheTestConditionContext(time.Now()))
	if !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("EvaluatePolicy = %v, want ErrNoSuchUser", err)
	}

	if err := derive("AKIAALICE", ""); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("DeriveSigningKey after the evaluation = %v, want ErrNoSuchUser", err)
	}
	if err := derive(session.AccessKeyId, session.SessionToken); err != nil {
		t.Fatalf("DeriveSigningKey(%s): %v", session.AccessKeyId, err)
	}
	calls.expect(t, private.DerivePath, 3)
}

// TestStandaloneSigningKeyCacheSkipsFailures covers an access key that does
// not exist yet: every attempt asks the IAM service again, so the key works
// as soon as it is created.
func TestStandaloneSigningKeyCacheSkipsFailures(t *testing.T) {
	store, sock := standaloneTestServer(t)
	client, calls, _ := newCachingStandaloneTestClient(t, sock, time.Minute, 0)

	for range 2 {
		_, _, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
		if !errors.Is(err, ErrNoSuchUser) {
			t.Fatalf("DeriveSigningKey = %v, want ErrNoSuchUser", err)
		}
	}
	calls.expect(t, private.DerivePath, 2)

	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")
	if _, _, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3); err != nil {
		t.Fatalf("DeriveSigningKey after creating the key: %v", err)
	}
}

// TestStandaloneSigningKeyCacheSession covers a session's key: it is never
// reused past the session's expiration, and only for the session's own token.
func TestStandaloneSigningKeyCacheSession(t *testing.T) {
	store, sock := standaloneTestServer(t)
	session := createStandaloneTestSession(t, store, "reader", "ASIASESSION", "sesssecret", "tok")
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 2*time.Hour, 0)

	derive := func(token string) error {
		_, _, err := client.DeriveSigningKey(session.AccessKeyId, token, cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
		return err
	}
	if err := derive(session.SessionToken); err != nil {
		t.Fatalf("DeriveSigningKey: %v", err)
	}

	if err := derive("other-token"); !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("DeriveSigningKey with another token = %v, want ErrInvalidSessionToken", err)
	}
	if err := derive(""); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("DeriveSigningKey without a token = %v, want ErrNoSuchUser", err)
	}
	calls.expect(t, private.DerivePath, 3)

	clock.set(session.Expiration.Add(-time.Second))
	if err := derive(session.SessionToken); err != nil {
		t.Fatalf("DeriveSigningKey before the session expires: %v", err)
	}
	calls.expect(t, private.DerivePath, 3)

	// The service's own clock has not moved, so it still answers; what
	// matters is that the entry is not used past the expiration.
	clock.set(session.Expiration)
	if err := derive(session.SessionToken); err != nil {
		t.Fatalf("DeriveSigningKey: %v", err)
	}
	calls.expect(t, private.DerivePath, 4)
}

// TestStandaloneSigningKeyCacheOlderService covers an IAM service that
// reports no session expiration: a session's key is not reused, while a
// user's still is.
func TestStandaloneSigningKeyCacheOlderService(t *testing.T) {
	key := sigv4auth.DeriveKey("secret", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
	sock := serveFakePrivate(t, strconv.Itoa(private.ProtocolVersion), http.StatusOK,
		fmt.Sprintf(`{"derivedKey":%q,"principalArn":"arn:aws:sts::000000000000:assumed-role/r/s"}`, base64.StdEncoding.EncodeToString(key)))
	client, calls, _ := newCachingStandaloneTestClient(t, sock, time.Minute, 0)

	for _, access := range []string{"ASIASESSION", "AKIAUSER"} {
		token := ""
		if sigv4auth.IsTempAccessKeyID(access) {
			token = "tok"
		}
		for range 2 {
			got, _, err := client.DeriveSigningKey(access, token, cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
			if err != nil {
				t.Fatalf("DeriveSigningKey(%s): %v", access, err)
			}
			if !bytes.Equal(got, key) {
				t.Fatalf("DeriveSigningKey(%s) key = %x, want %x", access, got, key)
			}
		}
	}
	calls.expect(t, private.DerivePath, 3)
}

func TestStandaloneSigningKeyCacheReturnsCopies(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")
	client, _, _ := newCachingStandaloneTestClient(t, sock, time.Minute, 0)
	want := sigv4auth.DeriveKey("alicesecret", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)

	for range 2 {
		key, _, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
		if err != nil {
			t.Fatalf("DeriveSigningKey: %v", err)
		}
		if !bytes.Equal(key, want) {
			t.Fatalf("key = %x, want %x", key, want)
		}
		clear(key)
	}
}

// TestStandaloneSigningKeyCacheSharesConcurrentMisses covers a burst of
// requests arriving for a credential nobody has used yet: they wait for a
// single call to the IAM service rather than each making their own.
func TestStandaloneSigningKeyCacheSharesConcurrentMisses(t *testing.T) {
	cache := newSigningKeyCache(time.Minute)
	release := make(chan struct{})
	var fetches atomic.Int32

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			resp, err := cache.derive("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3, func() (private.DeriveSigningKeyResponse, error) {
				fetches.Add(1)
				<-release
				return private.DeriveSigningKeyResponse{DerivedKey: []byte("key")}, nil
			})
			if err == nil && string(resp.DerivedKey) != "key" {
				err = fmt.Errorf("DerivedKey = %q", resp.DerivedKey)
			}
			errs <- err
		})
	}
	// Give every caller time to reach the cache before the fetch returns.
	// One that arrives afterwards finds the entry instead, so the count
	// below holds either way.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestStandalonePolicyCacheReusesDecision(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

	// The policy reads no condition key, so requests differing in all of
	// them, the time included, share one decision.
	for i := range 5 {
		clock.advance(time.Second)
		condCtx := cacheTestConditionContext(clock.now())
		condCtx["aws:SourceIp"] = []string{fmt.Sprintf("10.0.0.%d", i)}
		condCtx["aws:UserAgent"] = []string{fmt.Sprintf("agent/%d", i)}
		expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", condCtx, policyDecisionAllow)
	}
	calls.expect(t, private.EvaluatePath, 1)

	condCtx := cacheTestConditionContext(clock.now())
	expectDecision(t, client, "AKIAALICE", "", "s3:DeleteObject", "arn:aws:s3:::b/k", condCtx, policyDecisionDeny)
	expectDecision(t, client, "AKIAALICE", "", "s3:PutObject", "arn:aws:s3:::b/k", condCtx, policyDecisionNoMatch)
	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/other", condCtx, policyDecisionAllow)
	calls.expect(t, private.EvaluatePath, 4)

	expectDecision(t, client, "AKIAALICE", "", "s3:DeleteObject", "arn:aws:s3:::b/k", condCtx, policyDecisionDeny)
	expectDecision(t, client, "AKIAALICE", "", "s3:PutObject", "arn:aws:s3:::b/k", condCtx, policyDecisionNoMatch)
	calls.expect(t, private.EvaluatePath, 4)
}

// TestStandalonePolicyCacheConditionKeys covers decisions that depend on the
// request: each is reused only for requests agreeing on every condition key
// the policy reads, however the policy spells the key and wherever it reads
// it, and requests differing only in other keys share it.
func TestStandalonePolicyCacheConditionKeys(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		// requests are evaluated in order, twice over; the second round
		// must be answered entirely from the cache.
		requests []map[string][]string
		want     []policyDecision
	}{
		{
			name:   "condition key",
			policy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}}`,
			requests: []map[string][]string{
				{"aws:SourceIp": {"10.1.1.1"}},
				{"aws:SourceIp": {"192.0.2.1"}},
			},
			want: []policyDecision{policyDecisionAllow, policyDecisionNoMatch},
		},
		{
			name:   "condition key spelled in another case",
			policy: `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"NotIpAddress":{"AWS:SOURCEIP":"10.0.0.0/8"}}}}`,
			requests: []map[string][]string{
				{"aws:SourceIp": {"10.1.1.1"}},
				{"aws:SourceIp": {"192.0.2.1"}},
			},
			want: []policyDecision{policyDecisionNoMatch, policyDecisionDeny},
		},
		{
			name:   "policy variable in a condition value",
			policy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:Referer":"${aws:UserAgent}"}}}}`,
			requests: []map[string][]string{
				{"aws:Referer": {"agent"}, "aws:UserAgent": {"agent"}},
				{"aws:Referer": {"agent"}, "aws:UserAgent": {"other"}},
			},
			want: []policyDecision{policyDecisionAllow, policyDecisionNoMatch},
		},
		{
			name:   "policy variable in a resource",
			policy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${s3:prefix}"}}`,
			requests: []map[string][]string{
				{"s3:prefix": {"k"}},
				{"s3:prefix": {"j"}},
			},
			want: []policyDecision{policyDecisionAllow, policyDecisionNoMatch},
		},
		{
			name:   "absent key versus key with a value",
			policy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Null":{"aws:Referer":"true"}}}}`,
			requests: []map[string][]string{
				{},
				{"aws:Referer": {}},
			},
			want: []policyDecision{policyDecisionAllow, policyDecisionNoMatch},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, sock := standaloneTestServer(t)
			createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", tt.policy)
			client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

			for round := range 2 {
				for i, req := range tt.requests {
					clock.advance(time.Second)
					condCtx := cacheTestConditionContext(clock.now())
					for k, v := range req {
						condCtx[k] = v
					}
					expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", condCtx, tt.want[i])
					if round == 0 {
						calls.expect(t, private.EvaluatePath, i+1)
					}
				}
			}
			calls.expect(t, private.EvaluatePath, len(tt.requests))
		})
	}
}

// TestStandalonePolicyCacheConditionKeysChange covers a policy change that
// swaps the key a decision depends on. A decision reached under the old key
// must not answer a request that only happens to have the same value under
// the new one: neither policy would decide that request the same way.
func TestStandalonePolicyCacheConditionKeysChange(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:Referer":"a"}}}}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

	request := func(referer, userAgent string) map[string][]string {
		condCtx := cacheTestConditionContext(clock.now())
		condCtx["aws:Referer"] = []string{referer}
		condCtx["aws:UserAgent"] = []string{userAgent}
		return condCtx
	}
	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", request("a", "b"), policyDecisionAllow)

	if err := store.PutUserPolicy(context.Background(), storage.PutUserPolicyInput{
		UserName:       "alice",
		PolicyName:     "P",
		PolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:UserAgent":"z"}}}}`,
	}); err != nil {
		t.Fatalf("PutUserPolicy: %v", err)
	}
	// Another resource misses, and learns the key the policy reads now.
	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/other", request("a", "b"), policyDecisionNoMatch)

	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", request("b", "a"), policyDecisionNoMatch)
	calls.expect(t, private.EvaluatePath, 3)
}

// TestStandalonePolicyCacheSkipsClockConditions covers a policy that reads
// the time: no two requests share a decision, so none is stored.
func TestStandalonePolicyCacheSkipsClockConditions(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2100-01-01T00:00:00Z"}}}}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

	condCtx := cacheTestConditionContext(clock.now())
	for range 3 {
		expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", condCtx, policyDecisionAllow)
	}
	calls.expect(t, private.EvaluatePath, 3)
}

// TestStandalonePolicyCacheExpires covers the cost of the cache: a policy
// changed on the IAM service applies here once the decision expires.
func TestStandalonePolicyCacheExpires(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, 5*time.Second)

	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", cacheTestConditionContext(clock.now()), policyDecisionAllow)

	if err := store.PutUserPolicy(context.Background(), storage.PutUserPolicyInput{
		UserName:       "alice",
		PolicyName:     "P",
		PolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`,
	}); err != nil {
		t.Fatalf("PutUserPolicy: %v", err)
	}

	clock.advance(5*time.Second - time.Millisecond)
	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", cacheTestConditionContext(clock.now()), policyDecisionAllow)
	calls.expect(t, private.EvaluatePath, 1)

	clock.advance(time.Millisecond)
	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", cacheTestConditionContext(clock.now()), policyDecisionDeny)
	calls.expect(t, private.EvaluatePath, 2)
}

// TestStandalonePolicyCacheIdentity covers what identifies the caller: a
// session's decision is reused only with that session's own token, and one
// identity's decisions are never another's.
func TestStandalonePolicyCacheIdentity(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	session := createStandaloneTestSession(t, store, "reader", "ASIASESSION", "sesssecret", "tok")
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)
	condCtx := cacheTestConditionContext(clock.now())

	expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", condCtx, policyDecisionAllow)
	// The role has no policy at all.
	expectDecision(t, client, session.AccessKeyId, session.SessionToken, "s3:GetObject", "arn:aws:s3:::b/k", condCtx, policyDecisionNoMatch)
	calls.expect(t, private.EvaluatePath, 2)

	_, err := client.EvaluatePolicy(session.AccessKeyId, "other-token", []Action{"s3:GetObject"}, []string{"arn:aws:s3:::b/k"}, condCtx)
	if !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("EvaluatePolicy with another token = %v, want ErrInvalidSessionToken", err)
	}
	// Failures are not cached either.
	_, err = client.EvaluatePolicy(session.AccessKeyId, "other-token", []Action{"s3:GetObject"}, []string{"arn:aws:s3:::b/k"}, condCtx)
	if !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("EvaluatePolicy with another token = %v, want ErrInvalidSessionToken", err)
	}
	calls.expect(t, private.EvaluatePath, 4)
}

// TestStandalonePolicyCacheSkipsBatches covers a DeleteObjects batch, whose
// decisions are not cached.
func TestStandalonePolicyCacheSkipsBatches(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/a"}}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

	for range 2 {
		eval, err := client.EvaluatePolicy("AKIAALICE", "", []Action{"s3:DeleteObject"}, []string{"arn:aws:s3:::b/a", "arn:aws:s3:::b/b"}, cacheTestConditionContext(clock.now()))
		if err != nil {
			t.Fatalf("EvaluatePolicy: %v", err)
		}
		if eval.Decisions[0][0] != policyDecisionAllow || eval.Decisions[1][0] != policyDecisionNoMatch {
			t.Fatalf("Decisions = %v, want [[allow] [no match]]", eval.Decisions)
		}
	}
	calls.expect(t, private.EvaluatePath, 2)
}

// TestStandalonePolicyCacheOlderService covers an IAM service that does not
// say whether a decision can be reused: none is.
func TestStandalonePolicyCacheOlderService(t *testing.T) {
	sock := serveFakePrivate(t, strconv.Itoa(private.ProtocolVersion), http.StatusOK, `{"decisions":[["allow"]]}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

	for range 2 {
		expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", cacheTestConditionContext(clock.now()), policyDecisionAllow)
	}
	calls.expect(t, private.EvaluatePath, 2)
}

func TestStandalonePolicyCacheReturnsCopies(t *testing.T) {
	store, sock := standaloneTestServer(t)
	session := createStandaloneTestSession(t, store, "reader", "ASIASESSION", "sesssecret", "tok")
	if err := store.PutRolePolicy(context.Background(), storage.PutRolePolicyInput{
		RoleName:       "reader",
		PolicyName:     "P",
		PolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
	}); err != nil {
		t.Fatalf("PutRolePolicy: %v", err)
	}
	client, _, clock := newCachingStandaloneTestClient(t, sock, 0, time.Minute)

	for range 2 {
		eval, err := client.EvaluatePolicy(session.AccessKeyId, session.SessionToken, []Action{"s3:GetObject"}, []string{"arn:aws:s3:::b/k"}, cacheTestConditionContext(clock.now()))
		if err != nil {
			t.Fatalf("EvaluatePolicy: %v", err)
		}
		if eval.Decisions[0][0] != policyDecisionAllow {
			t.Fatalf("Decisions = %v, want [[allow]]", eval.Decisions)
		}
		eval.Decisions[0][0] = policyDecisionDeny
	}
}

// TestStandaloneCachesDisabled covers a zero TTL, which caches nothing.
func TestStandaloneCachesDisabled(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	client, calls, clock := newCachingStandaloneTestClient(t, sock, 0, 0)

	for range 3 {
		if _, _, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3); err != nil {
			t.Fatalf("DeriveSigningKey: %v", err)
		}
		expectDecision(t, client, "AKIAALICE", "", "s3:GetObject", "arn:aws:s3:::b/k", cacheTestConditionContext(clock.now()), policyDecisionAllow)
	}
	calls.expect(t, private.DerivePath, 3)
	calls.expect(t, private.EvaluatePath, 3)
}

// TestStandaloneCachesConcurrentUse runs both caches from many goroutines at
// once, for the race detector, over a working set larger than either cache
// would ever hold in one TTL.
func TestStandaloneCachesConcurrentUse(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/even*"}}`)
	client, _, _ := newCachingStandaloneTestClient(t, sock, time.Minute, time.Minute)
	wantKey := sigv4auth.DeriveKey("alicesecret", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for g := range 16 {
		wg.Go(func() {
			for i := range 50 {
				key, _, err := client.DeriveSigningKey("AKIAALICE", "", cacheTestDate, cacheTestRegion, sigv4auth.ServiceS3)
				if err != nil || !bytes.Equal(key, wantKey) {
					errs <- fmt.Errorf("DeriveSigningKey = %x, %v", key, err)
					return
				}

				n := (g + i) % 8
				resource, want := fmt.Sprintf("arn:aws:s3:::b/odd%d", n), policyDecisionNoMatch
				if n%2 == 0 {
					resource, want = fmt.Sprintf("arn:aws:s3:::b/even%d", n), policyDecisionAllow
				}
				eval, err := client.EvaluatePolicy("AKIAALICE", "", []Action{"s3:GetObject"}, []string{resource}, cacheTestConditionContext(time.Now()))
				if err != nil || eval.Decisions[0][0] != want {
					errs <- fmt.Errorf("EvaluatePolicy(%s) = %v, %v", resource, eval.Decisions, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestTTLCacheEviction(t *testing.T) {
	now := time.Now()
	key := func(i int) cacheKey { return newCacheKeyBuilder().add(fmt.Sprint(i)).sum() }

	t.Run("expired entries go first", func(t *testing.T) {
		cache := newTTLCache[int](4)
		cache.set(key(0), 0, now.Add(-time.Second), now)
		cache.set(key(1), 1, now.Add(-time.Second), now)
		cache.set(key(2), 2, now.Add(time.Minute), now)
		cache.set(key(3), 3, now.Add(time.Minute), now)

		cache.set(key(4), 4, now.Add(time.Minute), now)
		if n := len(cache.entries); n != 3 {
			t.Fatalf("entries = %d, want 3", n)
		}
		for i := 2; i <= 4; i++ {
			if v, ok := cache.get(key(i), now); !ok || v != i {
				t.Errorf("get(%d) = %d, %v, want %d, true", i, v, ok, i)
			}
		}
	})

	t.Run("a full cache stays at its bound", func(t *testing.T) {
		cache := newTTLCache[int](4)
		for i := range 100 {
			cache.set(key(i), i, now.Add(time.Minute), now)
			if n := len(cache.entries); n > 4 {
				t.Fatalf("entries = %d after %d stores, want at most 4", n, i+1)
			}
		}
		if v, ok := cache.get(key(99), now); !ok || v != 99 {
			t.Errorf("get(99) = %d, %v, want 99, true", v, ok)
		}
	})

	t.Run("replacing an entry evicts nothing", func(t *testing.T) {
		cache := newTTLCache[int](2)
		cache.set(key(0), 0, now.Add(time.Minute), now)
		cache.set(key(1), 1, now.Add(time.Minute), now)
		cache.set(key(1), 10, now.Add(time.Minute), now)
		if v, ok := cache.get(key(0), now); !ok || v != 0 {
			t.Errorf("get(0) = %d, %v, want 0, true", v, ok)
		}
		if v, ok := cache.get(key(1), now); !ok || v != 10 {
			t.Errorf("get(1) = %d, %v, want 10, true", v, ok)
		}
	})
}

// TestNewStandaloneCacheOptions covers how the gateway's IAM cache options
// configure the standalone backend's caches.
func TestNewStandaloneCacheOptions(t *testing.T) {
	_, sock := standaloneTestServer(t)

	tests := []struct {
		name              string
		opts              Opts
		wantSigningKeyTTL time.Duration
		wantPolicyTTL     time.Duration
	}{
		{name: "both enabled", opts: Opts{CacheTTL: 60, StandalonePolicyCacheTTL: 7}, wantSigningKeyTTL: time.Minute, wantPolicyTTL: 7 * time.Second},
		{name: "policy cache disabled", opts: Opts{CacheTTL: 60}, wantSigningKeyTTL: time.Minute},
		{name: "cache disabled", opts: Opts{CacheDisable: true, CacheTTL: 60, StandalonePolicyCacheTTL: 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.RootAccount = Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
			tt.opts.StandaloneIAMEndpoint = sock
			svc, err := New(&tt.opts)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer svc.Shutdown()

			client, ok := svc.(*IAMServiceStandalone)
			if !ok {
				t.Fatalf("New returned %T, want *IAMServiceStandalone", svc)
			}
			var signingKeyTTL, policyTTL time.Duration
			if client.signingKeys != nil {
				signingKeyTTL = client.signingKeys.ttl
			}
			if client.policies != nil {
				policyTTL = client.policies.ttl
			}
			if signingKeyTTL != tt.wantSigningKeyTTL || policyTTL != tt.wantPolicyTTL {
				t.Errorf("TTLs = %v, %v, want %v, %v", signingKeyTTL, policyTTL, tt.wantSigningKeyTTL, tt.wantPolicyTTL)
			}
		})
	}
}

// newCachingStandaloneTestClient builds a client with the given cache TTLs,
// whose caches read a clock the test moves by hand, and whose calls to the
// IAM service are counted by path.
func newCachingStandaloneTestClient(t *testing.T, sock string, signingKeyTTL, policyTTL time.Duration) (*IAMServiceStandalone, *privateCallCounter, *testClock) {
	t.Helper()

	client, err := NewIAMServiceStandalone(
		Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin},
		IAMServiceStandaloneConfig{Endpoint: sock, SigningKeyCacheTTL: signingKeyTTL, PolicyCacheTTL: policyTTL})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	t.Cleanup(func() { client.Shutdown() })

	clock := &testClock{t: time.Now()}
	if client.signingKeys != nil {
		client.signingKeys.now = clock.now
	}
	if client.policies != nil {
		client.policies.now = clock.now
	}

	httpClient := client.client.Load()
	calls := &privateCallCounter{base: httpClient.Transport, calls: map[string]int{}}
	httpClient.Transport = calls

	return client, calls, clock
}

// cacheTestConditionContext is the shape of context every S3 request sends:
// the time, which differs from one request to the next, among the rest.
func cacheTestConditionContext(now time.Time) map[string][]string {
	return map[string][]string{
		"aws:CurrentTime":     {now.UTC().Format(time.RFC3339)},
		"aws:EpochTime":       {fmt.Sprint(now.Unix())},
		"aws:SecureTransport": {"false"},
	}
}

func expectDecision(t *testing.T, client *IAMServiceStandalone, access, token string, action Action, resource string, condCtx map[string][]string, want policyDecision) {
	t.Helper()

	eval, err := client.EvaluatePolicy(access, token, []Action{action}, []string{resource}, condCtx)
	if err != nil {
		t.Fatalf("EvaluatePolicy(%s, %s): %v", action, resource, err)
	}
	if got := eval.Decisions[0][0]; got != want {
		t.Fatalf("EvaluatePolicy(%s, %s, %v) = %v, want %v", action, resource, condCtx, got, want)
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// privateCallCounter counts the calls a client makes to each private
// endpoint.
type privateCallCounter struct {
	base  http.RoundTripper
	mu    sync.Mutex
	calls map[string]int
}

func (c *privateCallCounter) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls[req.URL.Path]++
	c.mu.Unlock()
	return c.base.RoundTrip(req)
}

func (c *privateCallCounter) expect(t *testing.T, path string, want int) {
	t.Helper()
	c.mu.Lock()
	got := c.calls[path]
	c.mu.Unlock()
	if got != want {
		t.Fatalf("calls to %s = %d, want %d", path, got, want)
	}
}
