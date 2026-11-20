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

package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

// Access key lookups are on the hot path of every S3 request the gateway
// sends through the standalone IAM service, but Vault's KV store has no
// secondary indexes: the only way to find the user that owns an access key id
// from the key alone is to list every user and read them one by one, a cost
// that grows with the number of users. InternalStore avoids that with its
// AccessKeyIndex; this file gives VaultStore the same thing, as one small KV
// entry per access key at <secretStoragePath>/access-keys/<access key id>
// holding the case-folded key of the user that owns it.
//
// The entry is only a hint. The user record stays the source of truth: a
// lookup reads the entry, then the user it names, and trusts the result only
// if that user really holds the key. Anything else — no entry, an entry for a
// user that was renamed or deleted, an entry for a key that user no longer
// has — falls back to scanning every user and repairs the entry from what the
// scan finds. That is what makes the index safe to be wrong: Vault has no
// multi-key transaction, so the user record and its index entries cannot be
// updated atomically, and a crash, a lost connection or an older gateway
// version that does not know about the index can leave them disagreeing. A
// disagreement therefore costs one scan, never a wrong answer, and existing
// deployments need no migration step to start using it.

// accessKeyIndexUserField is the one field of an access key's index entry.
const accessKeyIndexUserField = "user"

// accessKeyBackfillTimeout bounds the startup backfill pass as a whole;
// every Vault request in it is additionally bounded by vaultRequestTimeout.
// A pass that runs out of time leaves the rest to the lookup path's own
// repair, so this only has to be generous, not exact.
const accessKeyBackfillTimeout = 5 * time.Minute

// errAccessKeyIndexDenied is returned by the index helpers once Vault has
// refused them access to the index path, so a caller looping over many keys
// can stop instead of failing every one of them the same way.
var errAccessKeyIndexDenied = errors.New("iamapi: vault access key index not accessible")

// accessKeysPath is the KV prefix under which the access key index is stored,
// kept distinct from usersPath so listing users never picks it up.
func (s *VaultStore) accessKeysPath() string {
	return s.secretStoragePath + "/access-keys"
}

// reAuthFailure is the error withReAuth and indexCall return when
// re-authenticating failed. It deliberately does not unwrap: the HTTP status
// inside is the login's, and a caller checking the outcome of its own call —
// a 404 taken as "no such entry", say — must not mistake the one for the
// other.
type reAuthFailure struct{ err error }

func (e reAuthFailure) Error() string { return e.err.Error() }

// withReAuth runs call, and if Vault rejected it as forbidden — an expired
// AppRole token — re-authenticates and runs it once more: the retry shape
// every user-path call in this store shares.
func (s *VaultStore) withReAuth(call func() error) error {
	err := call()
	if !vault.IsErrorStatus(err, http.StatusForbidden) {
		return err
	}
	if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
		return reAuthFailure{reauthErr}
	}
	return call()
}

// indexCall runs call against the index path. It differs from withReAuth in
// how it reads a 403, because the index path is the one path an existing
// deployment's Vault policy may not cover: it was added after those policies
// were written. A 403 is then a policy denial rather than an expired token,
// and the index is switched off for the life of the process instead of being
// retried — and re-authenticated against — on every lookup. Everything keeps
// working through the scan, exactly as it did before the index existed, and
// extending the policy to the path plus a restart brings the index back.
//
// With AppRole credentials, a 403 is first treated as an expired token: only
// a retry that is still refused after re-authenticating counts as a denial,
// and a failed re-authentication is returned as the store-wide failure it
// is. A static token cannot be renewed, so its 403 is a denial at once —
// reAuthIfNeeded would only attempt an AppRole login with no credentials.
func (s *VaultStore) indexCall(call func() error) error {
	if s.indexDenied.Load() {
		return errAccessKeyIndexDenied
	}
	err := call()
	if !vault.IsErrorStatus(err, http.StatusForbidden) {
		return err
	}
	if s.creds.RoleId != "" {
		if reauthErr := s.reAuthIfNeeded(err); reauthErr != nil {
			return reAuthFailure{reauthErr}
		}
		if err = call(); !vault.IsErrorStatus(err, http.StatusForbidden) {
			return err
		}
	}
	// Logged unconditionally, once: this is a deployment that silently runs
	// with the cost the index exists to remove until someone acts on it.
	if s.indexDenied.CompareAndSwap(false, true) {
		log.Printf("WARNING: vault denied access to %q: the access key index is disabled and access key lookups will scan every user; "+
			"grant the IAM policy access to this path and restart to enable it: %v", s.accessKeysPath(), err)
	}
	return errAccessKeyIndexDenied
}

// readAccessKeyIndex returns the case-folded user key accessKeyID is indexed
// under, and the KV version the entry was read at (0 when there is none).
// userKey is empty when there is no usable entry: none was ever written, it
// is malformed (version is then still set, so it can be overwritten), or the
// index is switched off. A non-nil error is a Vault failure that says
// nothing about whether the entry exists.
func (s *VaultStore) readAccessKeyIndex(ctx context.Context, accessKeyID string) (userKey string, version int32, err error) {
	path := s.accessKeysPath() + "/" + accessKeyID
	var resp *vault.Response[schema.KvV2ReadResponse]
	err = s.indexCall(func() (err error) {
		resp, err = s.client.Secrets.KvV2Read(ctx, path, s.kvReqOpts...)
		return err
	})
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) || errors.Is(err, errAccessKeyIndexDenied) {
			return "", 0, nil
		}
		return "", 0, err
	}

	userKey, _ = resp.Data.Data[accessKeyIndexUserField].(string)
	return userKey, kvVersion(resp.Data.Metadata), nil
}

// writeAccessKeyIndex writes accessKeyID's entry as a check-and-set against
// version (0: the entry must not exist). Every write in this store carries a
// cas option, which is what lets it run on a KV mount configured with
// cas_required; the index must not be the exception.
func (s *VaultStore) writeAccessKeyIndex(ctx context.Context, accessKeyID, userKey string, version int32) error {
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{accessKeyIndexUserField: userKey},
		Options: map[string]any{"cas": version},
	}
	path := s.accessKeysPath() + "/" + accessKeyID
	return s.indexCall(func() error {
		_, err := s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
		return err
	})
}

// putAccessKeyIndex points accessKeyID's entry at userKey. version is the KV
// version the caller last saw the entry at, 0 for none. If the entry has moved
// on since, it is re-read once and overwritten, unless it already points at
// userKey; a second conflict means another writer got there in between, and
// whichever entry wins is checked by the lookup that reads it anyway. With
// createOnly an existing entry is always left alone, which is what a bulk
// backfill needs so that it cannot overwrite a newer entry written while it
// was running.
func (s *VaultStore) putAccessKeyIndex(ctx context.Context, accessKeyID, userKey string, version int32, createOnly bool) error {
	err := s.writeAccessKeyIndex(ctx, accessKeyID, userKey, version)
	if err == nil || !strings.Contains(err.Error(), "check-and-set") {
		return err
	}
	if createOnly {
		return nil
	}

	current, currentVersion, err := s.readAccessKeyIndex(ctx, accessKeyID)
	if err != nil {
		return err
	}
	if current == userKey {
		return nil
	}
	if err := s.writeAccessKeyIndex(ctx, accessKeyID, userKey, currentVersion); err != nil {
		if strings.Contains(err.Error(), "check-and-set") {
			return errConcurrentModification
		}
		return err
	}
	return nil
}

// deleteAccessKeyIndex removes accessKeyID's index entry. A missing entry is
// not an error.
func (s *VaultStore) deleteAccessKeyIndex(accessKeyID string) error {
	path := s.accessKeysPath() + "/" + accessKeyID
	err := s.indexCall(func() error {
		_, err := s.client.Secrets.KvV2DeleteMetadataAndAllVersions(context.Background(), path, s.kvReqOpts...)
		return err
	})
	if vault.IsErrorStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// logIndexFailure logs a failed best-effort index write or delete. Nothing is
// logged once the index is switched off: indexCall has said why, once.
func logIndexFailure(action, accessKeyID string, err error) {
	if errors.Is(err, errAccessKeyIndexDenied) {
		return
	}
	debuglogger.Logf("failed to %s Vault access key index entry for %q: %v", action, accessKeyID, err)
}

// userHasAccessKey reports whether user holds accessKeyID.
func userHasAccessKey(user *types.User, accessKeyID string) bool {
	for _, key := range user.AccessKeys {
		if key.AccessKeyId == accessKeyID {
			return true
		}
	}
	return false
}

// findAccessKeyOwner resolves accessKeyID to the user holding it, with the KV
// version that user record was read at (see readUserVersion). The common case
// costs two Vault reads however many users exist: the index entry, then the
// user. See the comment at the top of this file for why a stale or missing
// entry only costs a scan.
func (s *VaultStore) findAccessKeyOwner(ctx context.Context, accessKeyID string) (*types.User, int32, error) {
	// Access key ids from the private API are whatever the gateway received
	// in an Authorization header, and this one is about to become part of a
	// Vault path. Every key this service issues satisfies the same check, so
	// failing it also means no scan could find the key.
	if err := iamutil.ValidateAccessKeyID(accessKeyID); err != nil {
		return nil, 0, iamerr.NoSuchEntityAccessKey(accessKeyID)
	}

	userKey, entryVersion, err := s.readAccessKeyIndex(ctx, accessKeyID)
	if err != nil {
		return nil, 0, err
	}
	if userKey != "" {
		user, version, err := s.readUserVersion(userKey)
		switch {
		case err == nil && userHasAccessKey(user, accessKeyID):
			return user, version, nil
		case err != nil && !iamerr.IsNoSuchEntity(err):
			return nil, 0, err
		}
		// The entry is stale: its user is gone, or no longer holds the key.
	}

	user, version, err := s.scanForAccessKey(ctx, accessKeyID)
	switch {
	case err == nil:
		if putErr := s.putAccessKeyIndex(ctx, accessKeyID, caseFoldKey(user.UserName), entryVersion, false); putErr != nil {
			logIndexFailure("repair", accessKeyID, putErr)
		}
	case entryVersion != 0 && iamerr.IsNoSuchEntity(err):
		// Nobody holds the key, so the entry that claimed otherwise (or
		// could not be parsed) is garbage left behind by a failed cleanup;
		// drop it so this key's lookups stop paying for a stale read on top
		// of the scan.
		if delErr := s.deleteAccessKeyIndex(accessKeyID); delErr != nil {
			logIndexFailure("delete stale", accessKeyID, delErr)
		}
	}
	return user, version, err
}

// scanForAccessKey finds the user holding accessKeyID by reading every user
// in turn. It is the lookup of last resort, for keys the index does not (yet)
// know about, and costs one list plus up to one read per user.
func (s *VaultStore) scanForAccessKey(ctx context.Context, accessKeyID string) (*types.User, int32, error) {
	usernames, err := s.listUsernames(ctx)
	if err != nil {
		return nil, 0, err
	}

	for _, username := range usernames {
		user, version, err := s.readUserVersion(username)
		if err != nil {
			// Deleted between the listing and the read: it no longer holds
			// anything, which is not a reason to fail the whole lookup.
			if iamerr.IsNoSuchEntity(err) {
				continue
			}
			return nil, 0, err
		}
		if userHasAccessKey(user, accessKeyID) {
			return user, version, nil
		}
	}

	return nil, 0, iamerr.NoSuchEntityAccessKey(accessKeyID)
}

// listUsernames returns the KV key of every stored user, empty when none has
// ever been created.
func (s *VaultStore) listUsernames(ctx context.Context) ([]string, error) {
	var resp *vault.Response[schema.StandardListResponse]
	err := s.withReAuth(func() (err error) {
		resp, err = s.client.Secrets.KvV2List(ctx, s.usersPath(), s.kvReqOpts...)
		return err
	})
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return resp.Data.Keys, nil
}

// listIndexedAccessKeys returns the set of access key ids that have an index
// entry.
func (s *VaultStore) listIndexedAccessKeys(ctx context.Context) (map[string]struct{}, error) {
	var resp *vault.Response[schema.StandardListResponse]
	err := s.indexCall(func() (err error) {
		resp, err = s.client.Secrets.KvV2List(ctx, s.accessKeysPath(), s.kvReqOpts...)
		return err
	})
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			return map[string]struct{}{}, nil
		}
		return nil, err
	}

	indexed := make(map[string]struct{}, len(resp.Data.Keys))
	for _, id := range resp.Data.Keys {
		indexed[id] = struct{}{}
	}
	return indexed, nil
}

// indexUserAccessKeys points the index entry of each of user's access keys at
// user. It is how a rename keeps the index in step with the record that now
// holds the keys. Best-effort, like every index write that follows a user
// write: whatever it misses is repaired by the lookup that trips over it.
func (s *VaultStore) indexUserAccessKeys(ctx context.Context, user types.User) {
	userKey := caseFoldKey(user.UserName)
	for _, key := range user.AccessKeys {
		if err := s.putAccessKeyIndex(ctx, key.AccessKeyId, userKey, 0, false); err != nil {
			logIndexFailure("update", key.AccessKeyId, err)
		}
	}
}

// backfillAccessKeyIndex writes an index entry for every access key that does
// not have one yet, so users created before the index existed get its benefit
// right after an upgrade instead of each paying for a scan on first use. It
// never overwrites an entry, and what it misses (keys created while it runs,
// say) is repaired by the lookup path, so running it is optional for
// correctness and safe to repeat or run from several instances at once.
func (s *VaultStore) backfillAccessKeyIndex(ctx context.Context) error {
	indexed, err := s.listIndexedAccessKeys(ctx)
	if err != nil {
		return err
	}
	usernames, err := s.listUsernames(ctx)
	if err != nil {
		return err
	}

	skipped := 0
	for _, username := range usernames {
		if err := ctx.Err(); err != nil {
			return err
		}
		user, _, err := s.readUserVersion(username)
		if err != nil {
			// One user that cannot be read (deleted since the listing, or a
			// record that does not parse) must not leave every user after it
			// unindexed: whatever this pass misses, lookups repair.
			if !iamerr.IsNoSuchEntity(err) {
				debuglogger.Logf("Vault access key index backfill skipped user %q: %v", username, err)
				skipped++
			}
			continue
		}
		for _, key := range user.AccessKeys {
			if _, ok := indexed[key.AccessKeyId]; ok {
				continue
			}
			if err := s.putAccessKeyIndex(ctx, key.AccessKeyId, caseFoldKey(user.UserName), 0, true); err != nil {
				return err
			}
		}
	}
	if skipped > 0 {
		return fmt.Errorf("skipped %d unreadable users", skipped)
	}
	return nil
}

// backfillAccessKeyIndexInBackground runs backfillAccessKeyIndex once, off
// the caller's goroutine: the service must come up whether or not the backfill
// can run, and a failure only means lookups repair the index lazily instead.
func (s *VaultStore) backfillAccessKeyIndexInBackground() {
	ctx, cancel := context.WithTimeout(context.Background(), accessKeyBackfillTimeout)
	defer cancel()
	if err := s.backfillAccessKeyIndex(ctx); err != nil {
		debuglogger.Logf("Vault access key index backfill did not complete: %v", err)
	}
}

// usageRecord is the last-used data a recordAccessKeyUsage call left stored
// for an access key.
type usageRecord struct {
	when    time.Time
	service string
	region  string
}

// usageFlightKey identifies one recording in flight: the same key used for
// the same service and region.
type usageFlightKey struct {
	accessKeyID string
	service     string
	region      string
}

// usageTrackerTrust is how long accessKeyUsageTracker believes its memory of a
// key's last-used record without looking at Vault again. It is deliberately
// far shorter than UsageRecordCoalesceWindow: the tracker cannot see what
// other instances sharing the same Vault write, so past this horizon the next
// use goes back to the stored record, which can then be seen to have moved on.
// It still collapses a busy key's thousands of requests into one lookup per
// horizon.
const usageTrackerTrust = 5 * time.Second

// trackedUsage is the tracker's memory of one key: the record this process
// last saw stored, and when it last confirmed it against Vault.
type trackedUsage struct {
	usageRecord
	checkedAt time.Time
}

// accessKeyUsageTracker is VaultStore's in-process memory of last-used
// recording, which exists to spare Vault the reads that deciding "nothing to
// record" otherwise costs. shouldRecordUsage already keeps the *writes* to one
// per key per UsageRecordCoalesceWindow, but it can only be asked after the
// key's user has been fetched, so without this every request still paid for
// that fetch — in a goroutine, off the request's own latency, but against the
// same Vault. Remembering what this process last saw stored lets the answer
// be "nothing to do" without touching Vault at all.
//
// It never answers a read: only the decision to *skip* recording a use goes
// through it, and nothing that authenticates or authorizes a request does.
//
// Several instances may share one Vault, and the tracker cannot see what the
// others write. That is why an entry is believed only for usageTrackerTrust:
// if another instance records a different service or region for the key, this
// one notices on the first use after the horizon and records its own, instead
// of going on to skip the use until the coalescing window runs out. Within the
// horizon, the stored service or region can be briefly out of date for a key
// whose uses are spread across instances and services; the coalesced date
// already is out of date by up to a whole window, by design. Beyond that an
// entry that is wrong or missing — after a restart, or because another
// instance wrote a newer record — costs a redundant read or write at worst.
//
// It holds one small entry per access key that has been used.
// DeleteAccessKey drops the entry with the key on the instance that serves
// the delete; on any other instance it simply goes stale and is never
// consulted again, since a deleted key no longer authenticates.
type accessKeyUsageTracker struct {
	mu       sync.Mutex
	recorded map[string]trackedUsage
	inflight map[usageFlightKey]struct{}
}

func newAccessKeyUsageTracker() *accessKeyUsageTracker {
	return &accessKeyUsageTracker{
		recorded: make(map[string]trackedUsage),
		inflight: make(map[usageFlightKey]struct{}),
	}
}

// begin reports whether a use of accessKeyID at when needs recording, and if
// so marks it in flight until finish. It says no when this process confirmed,
// within usageTrackerTrust, a stored record recent enough that
// shouldRecordUsage would skip this use, and when the very same recording
// (key, service and region) is already under way — which is what keeps a
// burst of concurrent requests for one key from racing each other to write
// the same thing. A different service or region is never held back by one in
// flight: that is the part of the record that has to be able to change the
// moment the answer does.
func (t *accessKeyUsageTracker) begin(accessKeyID, service, region string, when time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if prev, ok := t.recorded[accessKeyID]; ok &&
		when.Sub(prev.checkedAt) < usageTrackerTrust &&
		!shouldRecordUsage(prev.when, prev.service, prev.region, service, region, when) {
		return false
	}
	flight := usageFlightKey{accessKeyID, service, region}
	if _, ok := t.inflight[flight]; ok {
		return false
	}
	t.inflight[flight] = struct{}{}
	return true
}

// finish ends the recording begin started, for a use at when. rec is what is
// now stored for the key, or nil if that is unknown (the recording failed).
func (t *accessKeyUsageTracker) finish(accessKeyID, service, region string, rec *usageRecord, when time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.inflight, usageFlightKey{accessKeyID, service, region})
	if rec != nil {
		t.recorded[accessKeyID] = trackedUsage{usageRecord: *rec, checkedAt: when}
	}
}

// forget drops what is remembered about accessKeyID.
func (t *accessKeyUsageTracker) forget(accessKeyID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.recorded, accessKeyID)
}
