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
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

// Every AssumeRole and AssumeRoleWithWebIdentity call counts the role's
// active sessions before minting another, to enforce
// MaxActiveSessionsPerRole. Sessions are stored by access key id, and the
// role a session belongs to is only inside its record, so counting from the
// records alone means listing every session of every role and reading each
// one: a cost that grows with the whole session store, paid by every mint.
// InternalStore counts in memory; this file gives VaultStore an index of
// sessions by role, the way vault_access_keys.go gives it one of access keys
// by user, as one small KV entry — a marker — per session at
//
//	<secretStoragePath>/sessions-by-role/<role>/<access key id>.<expiry>
//
// <role> is the session's role ARN, base64url-encoded so that the "/" of a
// role path cannot split it, and <expiry> is the session's expiration in
// Unix seconds. A KV LIST returns names only, so putting the expiration in
// the name is what lets one LIST of a role's directory count its active
// sessions without reading a single session or marker: a marker whose
// expiry has passed is skipped, as GetSession would skip its session.
//
// The count trusts the index, so the index must not miss sessions. A marker
// is written before its session, and a mint whose marker cannot be written
// fails. A mint whose session write fails removes its marker only once it
// has read back that the session is not stored (see
// settleFailedSessionWrite). A marker without a session, left by a failed
// write or a crash in between, holds one of the role's slots until it
// expires, which errs on the side of the limit.
//
// Sessions stored before the index existed have no marker, so a process
// counts through the index only once it has reconciled the index with the
// stored sessions (see reconcileSessionIndex). It starts doing that in the
// background as soon as it comes up, and until a reconcile succeeds, counts
// read every session, as they did before the index; no mint waits for a
// reconcile or fails because of one (see maintainSessionIndex). An instance
// of an older version sharing the same Vault writes sessions without
// markers, and those are not counted until the next sweep indexes them. If
// Vault's policy does not cover the index path, the count reads every
// session, as it did before.
//
// Expired sessions are removed together with their markers, a few at a time
// by the counts that come across them, and all of them by a sweep of every
// role's directory that reconciles the index again every
// sessionIndexSweepInterval, which reaches the roles no one assumes any more
// and so no count visits. That keeps doing what the old count did as a side
// effect of reading every session: Vault's delete_version_after only
// soft-deletes an expired session's data and leaves its metadata behind, and
// without that scan nothing would remove the metadata of a session nobody
// looks up again.

// sessionMarkerRoleField is the one field of a session marker: the role ARN
// its directory encodes, for an operator browsing Vault. Nothing reads it.
const sessionMarkerRoleField = "roleArn"

// maxSessionPurgesPerCount bounds how many expired sessions one count
// removes, so that the first mint after many of a role's sessions expired
// together does not pay for removing all of them. A role's sessions expire
// at the rate they are minted, so any bound above one per mint keeps up, and
// what is left over is skipped as expired until a later count removes it.
const maxSessionPurgesPerCount = 4

// sessionIndexReconcileTimeout bounds one reconcile as a whole; every Vault
// request in it is additionally bounded by vaultRequestTimeout. A reconcile
// that runs out of time is tried again, and the markers it did write are
// not written again.
const sessionIndexReconcileTimeout = 5 * time.Minute

// sessionIndexRetryInterval is how long maintainSessionIndex waits before
// trying again after a reconcile failed, as long as none has succeeded yet:
// meanwhile every count reads every session.
const sessionIndexRetryInterval = time.Minute

// sessionIndexSweepInterval is how often maintainSessionIndex reconciles the
// index again once a reconcile has succeeded: to remove the expired sessions
// of roles no count visits, and to index the sessions an instance of an
// older version stored without a marker.
const sessionIndexSweepInterval = 15 * time.Minute

// errSessionIndexDenied is errAccessKeyIndexDenied's counterpart for the
// session index: Vault has refused access to its path, and counts read every
// session instead.
var errSessionIndexDenied = errors.New("iamapi: vault session index not accessible")

// sessionsByRolePath is the KV prefix under which the session index is
// stored, kept distinct from sessionsPath so listing sessions never picks it
// up.
func (s *VaultStore) sessionsByRolePath() string {
	return s.secretStoragePath + "/sessions-by-role"
}

// sessionRolePath is the directory of roleArn's markers. A role ARN carries
// the role's path, which may hold any number of "/", so — like an OIDC
// provider url, see oidcProviderPathSegment — it is base64url-encoded into a
// single path segment rather than used as it is.
func (s *VaultStore) sessionRolePath(roleArn string) string {
	return s.sessionsByRolePath() + "/" + base64.RawURLEncoding.EncodeToString([]byte(roleArn))
}

// sessionMarkerName is the name of the marker of the session with
// accessKeyID that expires at expiration. The expiry is rounded up to the
// second, so a marker never says its session has expired before GetSession
// would.
func sessionMarkerName(accessKeyID string, expiration time.Time) string {
	expiry := expiration.Unix()
	if expiration.Nanosecond() != 0 {
		expiry++
	}
	return accessKeyID + "." + strconv.FormatInt(expiry, 10)
}

// parseSessionMarkerName reverses sessionMarkerName. ok is false for any
// name sessionMarkerName cannot have produced, such as the "<dir>/" entries
// Vault lists for subdirectories; the access key id it returns is safe to
// make part of a Vault path.
func parseSessionMarkerName(name string) (accessKeyID string, expiration time.Time, ok bool) {
	accessKeyID, expiry, found := strings.Cut(name, ".")
	if !found || iamutil.ValidateAccessKeyID(accessKeyID) != nil {
		return "", time.Time{}, false
	}
	unix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return accessKeyID, time.Unix(unix, 0).UTC(), true
}

// splitSessionMarkers sorts the marker names in a role's directory listing
// into the access key ids of the sessions still active at now and the names
// of the markers that have expired. Anything else is left out of both.
func splitSessionMarkers(names []string, now time.Time) (active, expired []string) {
	for _, name := range names {
		accessKeyID, expiration, ok := parseSessionMarkerName(name)
		switch {
		case !ok:
		case expiration.After(now):
			active = append(active, accessKeyID)
		default:
			expired = append(expired, name)
		}
	}
	return active, expired
}

// sessionIndexCall runs call against the session index path (see
// secondaryIndexCall).
func (s *VaultStore) sessionIndexCall(call func() error) error {
	return s.secondaryIndexCall(&s.sessionIndexDenied, errSessionIndexDenied, s.sessionsByRolePath(),
		"the session index is disabled and every AssumeRole call will read every stored session to count the role's sessions", call)
}

// listSessionIndex lists path, a directory of the session index: the role
// directories ("<segment>/") at its root, or the markers in one role's
// directory. It is empty when the directory does not exist.
func (s *VaultStore) listSessionIndex(ctx context.Context, path string) ([]string, error) {
	var resp *vault.Response[schema.StandardListResponse]
	err := s.sessionIndexCall(func() (err error) {
		resp, err = s.client.Secrets.KvV2List(ctx, path, s.kvReqOpts...)
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

// writeSessionMarker writes session's marker. The write is create-only —
// a check-and-set against version 0, which also lets it run on a KV mount
// configured with cas_required — and a marker that already exists is not an
// error: its name alone says everything the new one would.
func (s *VaultStore) writeSessionMarker(ctx context.Context, session types.Session) error {
	path := s.sessionRolePath(session.RoleArn) + "/" + sessionMarkerName(session.AccessKeyId, session.Expiration)
	req := schema.KvV2WriteRequest{
		Data:    map[string]any{sessionMarkerRoleField: session.RoleArn},
		Options: map[string]any{"cas": 0},
	}
	err := s.sessionIndexCall(func() error {
		_, err := s.client.Secrets.KvV2Write(ctx, path, req, s.kvReqOpts...)
		return err
	})
	if err != nil && strings.Contains(err.Error(), "check-and-set") {
		return nil
	}
	return err
}

// deleteSessionMarker removes the marker name from the role directory
// rolePath. A missing marker is not an error.
func (s *VaultStore) deleteSessionMarker(ctx context.Context, rolePath, name string) error {
	path := rolePath + "/" + name
	err := s.sessionIndexCall(func() error {
		_, err := s.client.Secrets.KvV2DeleteMetadataAndAllVersions(ctx, path, s.kvReqOpts...)
		return err
	})
	if vault.IsErrorStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// removeSessionMarker removes the marker CreateSession wrote for a session
// it then failed to store. Best-effort: a marker left behind only holds one
// of the role's slots until it expires.
func (s *VaultStore) removeSessionMarker(session types.Session) {
	rolePath := s.sessionRolePath(session.RoleArn)
	name := sessionMarkerName(session.AccessKeyId, session.Expiration)
	if err := s.deleteSessionMarker(context.Background(), rolePath, name); err != nil && !errors.Is(err, errSessionIndexDenied) {
		debuglogger.Logf("failed to delete Vault session index marker of unstored session %q: %v", session.AccessKeyId, err)
	}
}

// settleFailedSessionWrite is the outcome of a CreateSession whose session
// write failed with writeErr. The failure does not prove that Vault did not
// store the session: the client retries a 5xx or a dropped connection, so a
// write Vault committed but whose reply was lost is sent again, and the
// check-and-set refuses the retry. So the session is read back before
// anything is undone:
//
//   - Not stored: its marker is removed, so that it does not hold one of the
//     role's slots until it expires, and GetSession has removed the metadata
//     setSessionTTL created. writeErr is returned.
//   - Stored, and it is this session: the write did land, and the mint
//     succeeds after all.
//   - Anything else, a failed read included: the marker stays, which errs on
//     the side of the limit, and writeErr is returned.
//
// A write still in progress at Vault when the read finds nothing can land
// after the marker is gone; that session is not counted until the next
// sweep indexes it.
func (s *VaultStore) settleFailedSessionWrite(ctx context.Context, session types.Session, writeErr error) (*types.Session, error) {
	stored, err := s.GetSession(ctx, session.AccessKeyId)
	switch {
	case errors.Is(err, iamutil.ErrSessionNotFound):
		s.removeSessionMarker(session)
	case err != nil:
		debuglogger.Logf("failed to read back Vault session %q after its write failed, keeping its index marker: %v", session.AccessKeyId, err)
	case stored.SessionToken == session.SessionToken && stored.SecretAccessKey == session.SecretAccessKey:
		cloned := session
		return &cloned, nil
	}
	return nil, writeErr
}

// purgeExpiredSessions removes the expired sessions that the markers names
// in the role directory rolePath stand for, each followed by its marker. The
// marker goes last so that a session that could not be removed is tried
// again by the next purge that lists it. Best-effort: an expired marker is
// not counted whether it has been removed or not.
func (s *VaultStore) purgeExpiredSessions(ctx context.Context, rolePath string, names []string) {
	for _, name := range names {
		accessKeyID, _, ok := parseSessionMarkerName(name)
		if !ok {
			continue
		}
		if err := s.deleteByPath("sessions/" + accessKeyID); err != nil && !vault.IsErrorStatus(err, http.StatusNotFound) {
			debuglogger.Logf("failed to delete expired Vault session for access key %q: %v", accessKeyID, err)
			continue
		}
		if err := s.deleteSessionMarker(ctx, rolePath, name); err != nil {
			if errors.Is(err, errSessionIndexDenied) {
				return
			}
			debuglogger.Logf("failed to delete Vault session index marker %q: %v", name, err)
		}
	}
}

// activeSessionCountForRole counts roleArn's sessions that are active at
// now, so CreateSession can enforce MaxActiveSessionsPerRole: through the
// index once this process has reconciled it, and otherwise — until then, or
// if Vault denies the index — by reading every session, as before the index.
func (s *VaultStore) activeSessionCountForRole(ctx context.Context, roleArn string, now time.Time) (int, error) {
	if s.sessionIndexReconciled.Load() {
		count, err := s.indexedSessionCount(ctx, roleArn, now)
		if !errors.Is(err, errSessionIndexDenied) {
			return count, err
		}
	}
	return s.scanActiveSessionCount(ctx, roleArn)
}

// indexedSessionCount counts roleArn's sessions that are active at now from
// the role's directory in the index: one LIST, however many sessions are
// stored for this role or any other. It also removes a few of the expired
// sessions the listing turns up (see maxSessionPurgesPerCount).
func (s *VaultStore) indexedSessionCount(ctx context.Context, roleArn string, now time.Time) (int, error) {
	rolePath := s.sessionRolePath(roleArn)
	names, err := s.listSessionIndex(ctx, rolePath)
	if err != nil {
		return 0, err
	}

	active, expired := splitSessionMarkers(names, now)
	if len(expired) > maxSessionPurgesPerCount {
		expired = expired[:maxSessionPurgesPerCount]
	}
	s.purgeExpiredSessions(ctx, rolePath, expired)
	return len(active), nil
}

// scanActiveSessionCount is the count without the index: it lists every
// session and reads each one, at a cost that grows with the number stored
// for every role. GetSession removes an expired session it reads, so one is
// neither counted nor left to slow down the next scan.
func (s *VaultStore) scanActiveSessionCount(ctx context.Context, roleArn string) (int, error) {
	accessKeyIDs, err := s.listSessionIDs(ctx)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, accessKeyID := range accessKeyIDs {
		session, err := s.GetSession(ctx, accessKeyID)
		if err != nil {
			if errors.Is(err, iamutil.ErrSessionNotFound) {
				continue
			}
			return 0, err
		}
		if session.RoleArn == roleArn {
			count++
		}
	}
	return count, nil
}

// listSessionIDs returns the access key id of every stored session, empty
// when none has ever been stored.
func (s *VaultStore) listSessionIDs(ctx context.Context) ([]string, error) {
	var resp *vault.Response[schema.StandardListResponse]
	err := s.withReAuth(func() (err error) {
		resp, err = s.client.Secrets.KvV2List(ctx, s.sessionsPath(), s.kvReqOpts...)
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

// maintainSessionIndex reconciles the session index as soon as the process
// comes up, which is what lets counts go through it, and again every
// sweepInterval after that, until ctx is done. A reconcile that fails before
// any has succeeded is tried again after retryInterval, while counts keep
// reading every session; one that fails later only leaves its work to the
// next sweep. It stops for good once Vault denies the index, which is then
// switched off for the life of the process.
//
// It is what runs reconcileSessionIndex, off every request's path: no mint
// waits for a reconcile, is bounded by its deadline, or fails because of it,
// and reconciles do not overlap within a process.
func (s *VaultStore) maintainSessionIndex(ctx context.Context, retryInterval, sweepInterval time.Duration) {
	for {
		wait := sweepInterval
		if err := s.sweepSessionIndex(ctx); err != nil {
			if errors.Is(err, errSessionIndexDenied) || ctx.Err() != nil {
				return
			}
			debuglogger.Logf("Vault session index reconcile did not complete: %v", err)
			if !s.sessionIndexReconciled.Load() {
				wait = retryInterval
			}
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// sweepSessionIndex runs one reconcile, within sessionIndexReconcileTimeout,
// and lets counts trust the index once one has succeeded.
func (s *VaultStore) sweepSessionIndex(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, sessionIndexReconcileTimeout)
	defer cancel()
	if err := s.reconcileSessionIndex(ctx); err != nil {
		return err
	}
	s.sessionIndexReconciled.Store(true)
	return nil
}

// reconcileSessionIndex writes a marker for every active session that has
// none: one stored by a version of this service that predates the index,
// while Vault denied the index, or by a mint whose marker was lost. It also
// removes every expired session it comes across, with its marker, in every
// role's directory — including those of roles no one assumes any more, which
// no count visits — and the metadata left by a session write that failed.
//
// A session that already has a marker is not read, so once the sessions
// stored before an upgrade are indexed, a reconcile costs a LIST per role
// directory plus one of the sessions. Markers are create-only, so it is safe
// to run alongside CreateSession, and from several instances at once.
func (s *VaultStore) reconcileSessionIndex(ctx context.Context) error {
	now := time.Now().UTC()

	roleDirs, err := s.listSessionIndex(ctx, s.sessionsByRolePath())
	if err != nil {
		return err
	}
	indexed := make(map[string]struct{})
	for _, dir := range roleDirs {
		segment, ok := strings.CutSuffix(dir, "/")
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rolePath := s.sessionsByRolePath() + "/" + segment
		names, err := s.listSessionIndex(ctx, rolePath)
		if err != nil {
			return err
		}
		active, expired := splitSessionMarkers(names, now)
		for _, accessKeyID := range active {
			indexed[accessKeyID] = struct{}{}
		}
		s.purgeExpiredSessions(ctx, rolePath, expired)
	}

	accessKeyIDs, err := s.listSessionIDs(ctx)
	if err != nil {
		return err
	}
	for _, accessKeyID := range accessKeyIDs {
		if _, ok := indexed[accessKeyID]; ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// GetSession also removes the session if it has expired, or if
		// Vault has already soft-deleted it.
		session, err := s.GetSession(ctx, accessKeyID)
		if errors.Is(err, iamutil.ErrSessionNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err := s.writeSessionMarker(ctx, *session); err != nil {
			return err
		}
	}
	return nil
}
