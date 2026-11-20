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
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/versity/versitygw/iamapi/private"
	"github.com/versity/versitygw/internal/condition"
	"github.com/versity/versitygw/internal/sigv4auth"
)

// standaloneCacheMaxEntries bounds each of the standalone client's caches,
// so their memory stays bounded however many credentials and resources a
// gateway sees within one TTL.
const standaloneCacheMaxEntries = 1 << 16

// cacheEvictionSample is how many entries a full cache looks at to make room
// for a new one.
const cacheEvictionSample = 8

// signingKeyCache reuses derive-signing-key results, so a client signing
// request after request with one credential costs the IAM service one call
// per TTL rather than one per request. An entry is keyed on everything the
// derived key depends on: the access key, the session token and the
// credential scope.
//
// An entry lives for ttl, and never past its session's expiration. A
// deactivated or deleted access key therefore keeps working for up to ttl,
// or until a policy evaluation finds it gone and forgets its entries.
// Failures are not cached, so an access key created a moment after a request
// was refused works on the next one.
type signingKeyCache struct {
	ttl     time.Duration
	now     func() time.Time
	entries *ttlCache[cachedSigningKey]
	flights singleflight.Group
}

// cachedSigningKey is one derive-signing-key result, with the identity it
// belongs to so that forget can find it.
type cachedSigningKey struct {
	resp     private.DeriveSigningKeyResponse
	identity cacheKey
}

// newSigningKeyCache returns nil, which caches nothing, for a ttl that isn't
// positive.
func newSigningKeyCache(ttl time.Duration) *signingKeyCache {
	if ttl <= 0 {
		return nil
	}
	return &signingKeyCache{
		ttl:     ttl,
		now:     time.Now,
		entries: newTTLCache[cachedSigningKey](standaloneCacheMaxEntries),
	}
}

// derive returns the derive-signing-key result for the credential and scope,
// calling fetch when none is cached. Concurrent misses for one entry share a
// single fetch. Every caller is handed the same DerivedKey slice, so none may
// modify it. A nil cache calls fetch every time.
func (c *signingKeyCache) derive(access, sessionToken, date, region, service string, fetch func() (private.DeriveSigningKeyResponse, error)) (private.DeriveSigningKeyResponse, error) {
	if c == nil {
		return fetch()
	}

	identity := identityCacheKey(access, sessionToken)
	key := newCacheKeyBuilder().addKey(identity).add(date).add(region).add(service).sum()
	if cached, ok := c.entries.get(key, c.now()); ok {
		return cached.resp, nil
	}

	v, err, _ := c.flights.Do(string(key[:]), func() (any, error) {
		resp, err := fetch()
		if err != nil {
			return nil, err
		}

		now := c.now()
		expires := now.Add(c.ttl)
		// A session stops authenticating at its expiration, so its key is
		// not reused past it. An IAM service too old to report the
		// expiration leaves it zero, which caches nothing.
		if sigv4auth.IsTempAccessKeyID(access) && resp.Expiration.Before(expires) {
			expires = resp.Expiration
		}
		if expires.After(now) {
			c.entries.set(key, cachedSigningKey{resp: resp, identity: identity}, expires, now)
		}
		return resp, nil
	})
	if err != nil {
		return private.DeriveSigningKeyResponse{}, err
	}
	return v.(private.DeriveSigningKeyResponse), nil
}

// forget drops every cached key of the credential, for when the IAM service
// reports it gone, so that its next request asks the service again and is
// refused. A nil cache has nothing to forget.
func (c *signingKeyCache) forget(access, sessionToken string) {
	if c == nil {
		return
	}
	identity := identityCacheKey(access, sessionToken)
	c.entries.deleteFunc(func(cached cachedSigningKey) bool {
		return cached.identity == identity
	})
}

// standaloneEvaluation is one evaluate-policy result, with what the IAM
// service reported about reusing it.
type standaloneEvaluation struct {
	PolicyEvaluation
	cacheable     bool
	conditionKeys []string
}

// policyCache reuses evaluate-policy decisions for the same identity,
// actions and resource. Every request's condition context differs from the
// last one's, since it carries the time, so a decision is keyed only on the
// condition keys the IAM service reports the identity's policies read. A
// request is answered from the cache only when it agrees with the one that
// was evaluated on every one of those keys, and so would have been decided
// the same way.
//
// An entry lives for ttl, which is therefore also how long a policy change
// can take to apply. A cache hit records no use of the credential, since the
// IAM service records last-used on evaluate-policy.
type policyCache struct {
	ttl time.Duration
	now func() time.Time
	// conditionKeys holds, for each identity, the condition keys its
	// policies were last reported to read. They pick which of a request's
	// condition values its decision is keyed on, so a lookup needs them
	// before it can look for a decision.
	conditionKeys *ttlCache[[]string]
	decisions     *ttlCache[PolicyEvaluation]
	flights       singleflight.Group
}

// newPolicyCache returns nil, which caches nothing, for a ttl that isn't
// positive.
func newPolicyCache(ttl time.Duration) *policyCache {
	if ttl <= 0 {
		return nil
	}
	return &policyCache{
		ttl:           ttl,
		now:           time.Now,
		conditionKeys: newTTLCache[[]string](standaloneCacheMaxEntries),
		decisions:     newTTLCache[PolicyEvaluation](standaloneCacheMaxEntries),
	}
}

// evaluate returns the decisions for the identity, actions, resources and
// condition context, calling fetch when none is cached. Concurrent misses
// share a single fetch when their whole condition context matches. Every
// caller gets its own copy of the decision matrices. A nil cache calls fetch
// every time.
func (c *policyCache) evaluate(access, sessionToken string, actions []Action, resources []string, condition map[string][]string, fetch func() (standaloneEvaluation, error)) (PolicyEvaluation, error) {
	// Several resources are a DeleteObjects batch, one ARN per key. The same
	// batch seldom comes twice, and caching it would only crowd out
	// decisions that do get reused.
	if c == nil || len(resources) != 1 {
		eval, err := fetch()
		return eval.PolicyEvaluation, err
	}
	resource := resources[0]

	identity := identityCacheKey(access, sessionToken)
	now := c.now()
	if keys, ok := c.conditionKeys.get(identity, now); ok {
		if eval, ok := c.decisions.get(decisionKey(identity, actions, resource, keys, condition), now); ok {
			return eval.clone(), nil
		}
	}

	// Which keys the decision depends on is unknown until the IAM service
	// answers, so only requests agreeing on every key share a fetch.
	flight := decisionKey(identity, actions, resource, slices.Sorted(maps.Keys(condition)), condition)
	v, err, _ := c.flights.Do(string(flight[:]), func() (any, error) {
		eval, err := fetch()
		if err != nil {
			return nil, err
		}

		// A decision that depends on the clock would never be looked up
		// again, so storing it would only evict one that might.
		if eval.cacheable && !slices.ContainsFunc(eval.conditionKeys, isClockConditionKey) {
			now := c.now()
			expires := now.Add(c.ttl)
			c.conditionKeys.set(identity, eval.conditionKeys, expires, now)
			c.decisions.set(decisionKey(identity, actions, resource, eval.conditionKeys, condition), eval.PolicyEvaluation, expires, now)
		}
		return eval.PolicyEvaluation, nil
	})
	if err != nil {
		return PolicyEvaluation{}, err
	}
	return v.(PolicyEvaluation).clone(), nil
}

// decisionKey identifies one evaluation of an identity's policies: the
// actions, the resource, and the request's values for keys, the condition
// keys the decision depends on. The keys are hashed along with their values,
// so a decision reached while the policies read other keys is never taken
// for this one.
func decisionKey(identity cacheKey, actions []Action, resource string, keys []string, condCtx map[string][]string) cacheKey {
	b := newCacheKeyBuilder().addKey(identity)
	b.addCount(len(actions))
	for _, action := range actions {
		b.add(string(action))
	}
	b.add(resource)
	b.addCount(len(keys))
	for _, key := range keys {
		b.add(key)
		// The same case-insensitive lookup the IAM service evaluates with,
		// and a key that is absent hashes differently from one with no
		// values: the Null operator and IfExists tell the two apart.
		values, present := condition.LookupContextValues(condCtx, key)
		b.addFlag(present)
		b.addCount(len(values))
		for _, value := range values {
			b.add(value)
		}
	}
	return b.sum()
}

// identityCacheKey identifies the caller a credential names: an access key,
// and the session token that goes with a temporary one.
func identityCacheKey(access, sessionToken string) cacheKey {
	return newCacheKeyBuilder().add(access).add(sessionToken).sum()
}

// isClockConditionKey reports whether key is one of the condition keys that
// carry the time of the request.
func isClockConditionKey(key string) bool {
	return strings.EqualFold(key, "aws:CurrentTime") || strings.EqualFold(key, "aws:EpochTime")
}

// clone returns a copy of e that shares no decision matrix with it.
func (e PolicyEvaluation) clone() PolicyEvaluation {
	e.Decisions = cloneDecisionMatrix(e.Decisions)
	e.SessionDecisions = cloneDecisionMatrix(e.SessionDecisions)
	return e
}

func cloneDecisionMatrix(matrix [][]policyDecision) [][]policyDecision {
	if matrix == nil {
		return nil
	}
	out := make([][]policyDecision, len(matrix))
	for i, row := range matrix {
		out[i] = slices.Clone(row)
	}
	return out
}

// cacheKey identifies a cache entry by a SHA-256 hash of everything the
// cached result depends on, so an entry's size is fixed however long its
// inputs are: a session token or an object ARN can run to kilobytes.
type cacheKey [sha256.Size]byte

// cacheKeyBuilder hashes a fixed sequence of fields into a cacheKey. Strings
// are written length first and lists count first, so no two different
// inputs hash the same bytes.
type cacheKeyBuilder struct {
	h hash.Hash
}

func newCacheKeyBuilder() *cacheKeyBuilder {
	return &cacheKeyBuilder{h: sha256.New()}
}

func (b *cacheKeyBuilder) add(s string) *cacheKeyBuilder {
	b.addCount(len(s))
	io.WriteString(b.h, s)
	return b
}

func (b *cacheKeyBuilder) addKey(key cacheKey) *cacheKeyBuilder {
	b.h.Write(key[:])
	return b
}

func (b *cacheKeyBuilder) addCount(n int) {
	var buf [binary.MaxVarintLen64]byte
	b.h.Write(buf[:binary.PutUvarint(buf[:], uint64(n))])
}

func (b *cacheKeyBuilder) addFlag(v bool) {
	if v {
		b.h.Write([]byte{1})
		return
	}
	b.h.Write([]byte{0})
}

func (b *cacheKeyBuilder) sum() cacheKey {
	var key cacheKey
	b.h.Sum(key[:0])
	return key
}

// ttlCache maps cacheKeys to values that expire, holding at most max of
// them. A full cache evicts to make room for a new entry, preferring ones
// that have expired. Expired entries are otherwise left until they are
// evicted or overwritten, since a lookup ignores them anyway.
type ttlCache[V any] struct {
	mu      sync.RWMutex
	entries map[cacheKey]ttlEntry[V]
	max     int
}

type ttlEntry[V any] struct {
	value   V
	expires time.Time
}

func newTTLCache[V any](max int) *ttlCache[V] {
	return &ttlCache[V]{
		entries: make(map[cacheKey]ttlEntry[V]),
		max:     max,
	}
}

func (c *ttlCache[V]) get(key cacheKey, now time.Time) (V, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || !now.Before(entry.expires) {
		var zero V
		return zero, false
	}
	return entry.value, true
}

func (c *ttlCache[V]) set(key cacheKey, value V, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[key] = ttlEntry[V]{value: value, expires: expires}
}

// deleteFunc removes every entry whose value del reports true for.
func (c *ttlCache[V]) deleteFunc(del func(V) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	maps.DeleteFunc(c.entries, func(_ cacheKey, entry ttlEntry[V]) bool {
		return del(entry.value)
	})
}

// evictLocked removes at least one entry. Map iteration starts at a random
// entry, so the first few it visits are a random sample: every expired entry
// among them is removed, and the first of them if none has expired.
func (c *ttlCache[V]) evictLocked(now time.Time) {
	var first cacheKey
	visited, removed := 0, false
	for key, entry := range c.entries {
		if visited == 0 {
			first = key
		}
		if !now.Before(entry.expires) {
			delete(c.entries, key)
			removed = true
		}
		visited++
		if visited == cacheEvictionSample {
			break
		}
	}
	if !removed {
		delete(c.entries, first)
	}
}
