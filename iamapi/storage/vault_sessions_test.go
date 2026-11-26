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
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

const (
	// readerRoleArn has a path, so its "/" must not split the role's
	// directory in the session index.
	readerRoleArn = "arn:aws:iam::123456789012:role/team/data/reader"
	writerRoleArn = "arn:aws:iam::123456789012:role/writer"
)

// lowerSessionCap lowers MaxActiveSessionsPerRole for the duration of the
// test, so reaching it does not take 1000 sessions.
func lowerSessionCap(t *testing.T, n int) {
	t.Helper()
	orig := MaxActiveSessionsPerRole
	MaxActiveSessionsPerRole = n
	t.Cleanup(func() { MaxActiveSessionsPerRole = orig })
}

// newReconciledFakeVaultStore is newFakeVaultStore for a store whose session
// index has been reconciled, as the background maintenance does at startup,
// so that counts go through the index.
func newReconciledFakeVaultStore(t *testing.T) (*VaultStore, *fakeVault) {
	t.Helper()
	s, fv := newFakeVaultStore(t)
	if err := s.reconcileSessionIndex(context.Background()); err != nil {
		t.Fatalf("reconcileSessionIndex: %v", err)
	}
	s.sessionIndexReconciled.Store(true)
	return s, fv
}

func newTestSession(t *testing.T, roleArn string, expiration time.Time) types.Session {
	t.Helper()
	accessKeyID, err := iamutil.GenerateTempAccessKeyID()
	if err != nil {
		t.Fatalf("GenerateTempAccessKeyID: %v", err)
	}
	return types.Session{
		AccessKeyId:     accessKeyID,
		SecretAccessKey: "secret-" + accessKeyID,
		SessionToken:    "token-" + accessKeyID,
		RoleArn:         roleArn,
		RoleName:        roleArn[strings.LastIndex(roleArn, "/")+1:],
		RoleID:          "AROA" + strings.ToUpper(roleArn[strings.LastIndex(roleArn, "/")+1:]),
		RoleSessionName: "session",
		CreateDate:      time.Now().UTC().Truncate(time.Second),
		Expiration:      expiration,
	}
}

// mintSession stores a new session for roleArn through CreateSession.
func mintSession(t *testing.T, s *VaultStore, roleArn string, expiration time.Time) types.Session {
	t.Helper()
	session := newTestSession(t, roleArn, expiration)
	if _, err := s.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession for %s: %v", roleArn, err)
	}
	return session
}

// storeSession writes session behind the store's back, with or without its
// marker: without, it is what a version of the service that predates the
// session index leaves behind.
func storeSession(t *testing.T, s *VaultStore, fv *fakeVault, session types.Session, withMarker bool) {
	t.Helper()
	record, err := sessionToVaultMap(session)
	if err != nil {
		t.Fatalf("sessionToVaultMap: %v", err)
	}
	fv.put("iam/sessions/"+session.AccessKeyId, map[string]any{session.AccessKeyId: record})
	if withMarker {
		fv.put(markerPath(s, session), map[string]any{sessionMarkerRoleField: session.RoleArn})
	}
}

func markerPath(s *VaultStore, session types.Session) string {
	return s.sessionRolePath(session.RoleArn) + "/" + sessionMarkerName(session.AccessKeyId, session.Expiration)
}

// names returns the stored secrets whose path starts with prefix.
func (fv *fakeVault) names(prefix string) []string {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	var out []string
	for name := range fv.secrets {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func markersOf(s *VaultStore, fv *fakeVault, roleArn string) []string {
	return fv.names(s.sessionRolePath(roleArn) + "/")
}

// requireGone checks that session has neither a record nor a marker left.
func requireGone(t *testing.T, s *VaultStore, fv *fakeVault, session types.Session) {
	t.Helper()
	if _, ok := fv.secret("iam/sessions/" + session.AccessKeyId); ok {
		t.Errorf("expired session %s is still stored", session.AccessKeyId)
	}
	if _, ok := fv.secret(markerPath(s, session)); ok {
		t.Errorf("marker of expired session %s is still stored", session.AccessKeyId)
	}
}

func requireThrottling(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, iamerr.GetAPIError(iamerr.ErrThrottling)) {
		t.Fatalf("CreateSession error = %v, want Throttling", err)
	}
}

func isWrite(method string) bool {
	return method == http.MethodPost || method == http.MethodPut
}

// TestVaultCreateSessionCostIsIndependentOfSessionCount is the regression
// test for the count reading every stored session: however many sessions
// this role or any other has, minting one takes the same four requests (the
// count's LIST, the marker, the session's TTL and the session) and reads no
// session at all.
func TestVaultCreateSessionCostIsIndependentOfSessionCount(t *testing.T) {
	s, fv := newReconciledFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)

	for range 40 {
		mintSession(t, s, writerRoleArn, later)
	}
	for range 10 {
		mintSession(t, s, readerRoleArn, later)
	}

	for _, roleArn := range []string{readerRoleArn, writerRoleArn, "arn:aws:iam::123456789012:role/fresh"} {
		fv.resetLog()
		session := mintSession(t, s, roleArn, later)
		if got := fv.total(); got != 4 {
			t.Errorf("minting for %s took %d Vault requests, want 4 (log: %v)", roleArn, got, fv.log)
		}
		if got := fv.count("LIST", "iam/sessions/") + fv.count("GET", "iam/sessions/"); got != 0 {
			t.Errorf("minting for %s listed or read sessions %d times, want 0", roleArn, got)
		}

		got, err := s.GetSession(ctx, session.AccessKeyId)
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.SessionToken != session.SessionToken || got.RoleArn != roleArn {
			t.Errorf("GetSession = %+v, want the session just minted", got)
		}
	}

	if got, want := len(markersOf(s, fv, writerRoleArn)), 41; got != want {
		t.Errorf("%s has %d markers, want %d", writerRoleArn, got, want)
	}
}

func TestVaultSessionCapPerRole(t *testing.T) {
	lowerSessionCap(t, 3)
	s, fv := newReconciledFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)

	for range 3 {
		mintSession(t, s, readerRoleArn, later)
	}

	fv.resetLog()
	refused := newTestSession(t, readerRoleArn, later)
	_, err := s.CreateSession(ctx, refused)
	requireThrottling(t, err)
	if got := fv.total(); got != 1 {
		t.Errorf("a refused mint took %d Vault requests, want 1 (log: %v)", got, fv.log)
	}
	if _, ok := fv.secret("iam/sessions/" + refused.AccessKeyId); ok {
		t.Error("a refused session was stored")
	}

	// Another role is unaffected by the first one's limit.
	mintSession(t, s, writerRoleArn, later)
}

// TestVaultSessionCountSkipsAndPurgesExpiredSessions checks that a session
// past its expiry does not count against its role, and that the counts that
// find one remove it, record and marker, a bounded number at a time.
func TestVaultSessionCountSkipsAndPurgesExpiredSessions(t *testing.T) {
	lowerSessionCap(t, 2)
	s, fv := newReconciledFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Minute)

	var expired []types.Session
	for range maxSessionPurgesPerCount + 2 {
		session := newTestSession(t, readerRoleArn, past)
		storeSession(t, s, fv, session, true)
		expired = append(expired, session)
	}

	fv.resetLog()
	mintSession(t, s, readerRoleArn, later)
	if got := fv.count("DELETE", "iam/sessions/"); got != maxSessionPurgesPerCount {
		t.Errorf("one count removed %d expired sessions, want %d", got, maxSessionPurgesPerCount)
	}
	if got := fv.count("DELETE", "iam/sessions-by-role/"); got != maxSessionPurgesPerCount {
		t.Errorf("one count removed %d expired markers, want %d", got, maxSessionPurgesPerCount)
	}

	// The second mint still fits under the limit of 2 — no expired session
	// counts — and removes the rest.
	mintSession(t, s, readerRoleArn, later)
	for _, session := range expired {
		requireGone(t, s, fv, session)
	}

	_, err := s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
	requireThrottling(t, err)
}

// TestVaultSessionCountsUntilItExpires checks that a session counts against
// its role for as long as GetSession returns it, and stops counting within a
// second of that: its marker's expiry is rounded up to the second, never down.
func TestVaultSessionCountsUntilItExpires(t *testing.T) {
	lowerSessionCap(t, 1)
	s, _ := newReconciledFakeVaultStore(t)
	ctx := context.Background()

	// Not on a second boundary, so the marker's expiry has to round up.
	expiration := time.Now().Truncate(time.Second).Add(1500 * time.Millisecond)
	session := mintSession(t, s, readerRoleArn, expiration)
	_, markerExpiry, _ := parseSessionMarkerName(sessionMarkerName(session.AccessKeyId, expiration))
	if markerExpiry.Before(expiration) || markerExpiry.Sub(expiration) >= time.Second {
		t.Fatalf("marker expiry %v for a session expiring at %v, want within the second after", markerExpiry, expiration)
	}

	for {
		_, getErr := s.GetSession(ctx, session.AccessKeyId)
		alive := getErr == nil
		markerExpired := time.Now().After(markerExpiry)

		_, err := s.CreateSession(ctx, newTestSession(t, readerRoleArn, time.Now().Add(time.Hour)))
		switch {
		case alive:
			// Still a session, so still counted.
			requireThrottling(t, err)
		case err == nil:
			return
		case markerExpired:
			t.Fatalf("CreateSession after the session and its marker expired: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestVaultSessionIndexCountsSessionsStoredBeforeIt covers sessions stored
// by a version that predates the index: they have no marker, and are counted
// anyway — by reading every session until the index has been reconciled, and
// through the index once it has.
func TestVaultSessionIndexCountsSessionsStoredBeforeIt(t *testing.T) {
	lowerSessionCap(t, 3)
	s, fv := newFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)

	for range 2 {
		storeSession(t, s, fv, newTestSession(t, readerRoleArn, later), false)
	}
	gone := newTestSession(t, readerRoleArn, time.Now().Add(-time.Minute))
	storeSession(t, s, fv, gone, false)
	storeSession(t, s, fv, newTestSession(t, writerRoleArn, later), false)

	// Not reconciled yet: the count reads every session, and neither
	// waits for a reconcile nor runs one.
	mintSession(t, s, readerRoleArn, later)
	fv.resetLog()
	_, err := s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
	requireThrottling(t, err)
	if got := fv.count("GET", "iam/sessions/"); got != 4 {
		t.Errorf("a count before reconciling read %d sessions, want all 4", got)
	}
	if got := fv.count("LIST", "sessions-by-role") + fv.count(http.MethodPost, "sessions-by-role"); got != 0 {
		t.Errorf("a count before reconciling made %d requests to the index, want 0", got)
	}

	if err := s.sweepSessionIndex(ctx); err != nil {
		t.Fatalf("sweepSessionIndex: %v", err)
	}
	if got := len(markersOf(s, fv, readerRoleArn)); got != 3 {
		t.Errorf("%s has %d markers after reconciling, want 3", readerRoleArn, got)
	}
	if got := len(markersOf(s, fv, writerRoleArn)); got != 1 {
		t.Errorf("%s has %d markers after reconciling, want 1", writerRoleArn, got)
	}
	requireGone(t, s, fv, gone)

	// Reconciled once, counting no longer reads any session.
	fv.resetLog()
	_, err = s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
	requireThrottling(t, err)
	if got := fv.total(); got != 1 {
		t.Errorf("a count after reconciling took %d Vault requests, want 1 (log: %v)", got, fv.log)
	}
}

// TestVaultSessionIndexReconcile checks that a reconcile reads none of the
// sessions that already have a marker, and that it clears expired sessions
// out of the directory of a role nobody assumes any more, which no count
// would visit.
func TestVaultSessionIndexReconcile(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)

	for range 5 {
		mintSession(t, s, readerRoleArn, later)
	}
	abandoned := newTestSession(t, "arn:aws:iam::123456789012:role/deleted", time.Now().Add(-time.Minute))
	storeSession(t, s, fv, abandoned, true)

	fv.resetLog()
	if err := s.reconcileSessionIndex(ctx); err != nil {
		t.Fatalf("reconcileSessionIndex: %v", err)
	}
	if got := fv.count("GET", "iam/sessions/"); got != 0 {
		t.Errorf("reconcile read %d sessions, want 0: all of them have markers", got)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		if got := fv.count(method, ""); got != 0 {
			t.Errorf("reconcile made %d %s requests, want 0", got, method)
		}
	}
	requireGone(t, s, fv, abandoned)
	if got := len(markersOf(s, fv, readerRoleArn)); got != 5 {
		t.Errorf("%s has %d markers after reconciling, want 5", readerRoleArn, got)
	}
}

// TestVaultSessionIndexDeniedByPolicy covers a Vault policy written before
// the session index existed, which does not cover its path: sessions must
// still be minted and the limit still enforced, by reading every session as
// before, and the index must be given up on rather than retried on every
// mint.
func TestVaultSessionIndexDeniedByPolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		appRole    bool
		wantLogins int
	}{
		{name: "static token", appRole: false, wantLogins: 0},
		{name: "approle", appRole: true, wantLogins: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lowerSessionCap(t, 2)
			s, fv := newFakeVaultStore(t)
			ctx := context.Background()
			later := time.Now().Add(time.Hour)
			if tc.appRole {
				s.creds = schema.AppRoleLoginRequest{RoleId: "role", SecretId: "secret"}
			} else {
				fv.loginStatus = http.StatusBadRequest
			}
			fv.fail = func(_, path string) int {
				if strings.HasPrefix(path, "iam/sessions-by-role") {
					return http.StatusForbidden
				}
				return 0
			}

			for range 2 {
				mintSession(t, s, readerRoleArn, later)
			}
			_, err := s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
			requireThrottling(t, err)
			mintSession(t, s, writerRoleArn, later)

			if !s.sessionIndexDenied.Load() {
				t.Fatal("session index was not disabled after Vault denied access to it")
			}
			if fv.logins != tc.wantLogins {
				t.Errorf("concluding the index is denied took %d AppRole logins, want %d", fv.logins, tc.wantLogins)
			}
			logins := fv.logins

			fv.resetLog()
			_, err = s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
			requireThrottling(t, err)
			if got := fv.count("LIST", "sessions-by-role") + fv.count(http.MethodPost, "sessions-by-role") + fv.count(http.MethodDelete, "sessions-by-role"); got != 0 {
				t.Errorf("%d requests still went to the disabled index", got)
			}
			if got := fv.count("GET", "iam/sessions/"); got != 3 {
				t.Errorf("the count read %d sessions, want all 3", got)
			}
			if fv.logins != logins {
				t.Errorf("mints re-authenticated %d times after the index was disabled", fv.logins-logins)
			}
		})
	}
}

// TestVaultCreateSessionReportsIndexFailures checks that Vault failing on
// the index fails the mint: the count must not be taken as zero, and a
// session must not be stored without the marker that counts it. The
// injected status is a 400 for the reason TestVaultAccessKeyLookupReportsVaultFailures
// gives.
func TestVaultCreateSessionReportsIndexFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failOn func(method string) bool
	}{
		{"count", func(method string) bool { return method == "LIST" }},
		{"marker write", isWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fv := newReconciledFakeVaultStore(t)
			ctx := context.Background()
			later := time.Now().Add(time.Hour)
			mintSession(t, s, readerRoleArn, later)

			fv.fail = func(method, path string) int {
				if tc.failOn(method) && strings.HasPrefix(path, "iam/sessions-by-role") {
					return http.StatusBadRequest
				}
				return 0
			}
			session := newTestSession(t, readerRoleArn, later)
			_, err := s.CreateSession(ctx, session)
			if err == nil || errors.Is(err, iamerr.GetAPIError(iamerr.ErrThrottling)) {
				t.Fatalf("CreateSession error = %v, want the Vault failure", err)
			}
			if _, ok := fv.secret("iam/sessions/" + session.AccessKeyId); ok {
				t.Error("the session was stored although its marker was not")
			}
			if s.sessionIndexDenied.Load() {
				t.Error("a Vault failure switched the session index off")
			}

			fv.fail = nil
			mintSession(t, s, readerRoleArn, later)
		})
	}
}

// TestVaultCreateSessionRemovesMarkerOfUnstoredSession checks that a mint
// that fails to store its session gives back the slot its marker took, and
// leaves no metadata behind at the session's path.
func TestVaultCreateSessionRemovesMarkerOfUnstoredSession(t *testing.T) {
	lowerSessionCap(t, 1)
	s, fv := newReconciledFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)

	fv.fail = func(method, path string) int {
		if isWrite(method) && strings.HasPrefix(path, "iam/sessions/") {
			return http.StatusBadRequest
		}
		return 0
	}
	failed := newTestSession(t, readerRoleArn, later)
	if _, err := s.CreateSession(ctx, failed); err == nil {
		t.Fatal("CreateSession succeeded although the session could not be stored")
	}
	if got := markersOf(s, fv, readerRoleArn); len(got) != 0 {
		t.Errorf("markers left behind by a failed mint: %v", got)
	}
	if _, ok := fv.secret("iam/sessions/" + failed.AccessKeyId); ok {
		t.Error("the metadata of a session that was not stored was left behind")
	}

	fv.fail = nil
	mintSession(t, s, readerRoleArn, later)
}

// maintainInBackground runs s's session index maintenance with the given
// intervals until the test ends.
func maintainInBackground(t *testing.T, s *VaultStore, retryInterval, sweepInterval time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.maintainSessionIndex(ctx, retryInterval, sweepInterval)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestVaultSessionIndexMaintenanceRetriesReconcile checks that a reconcile
// that fails leaves the index untrusted, does not fail the mints made
// meanwhile — they read every session instead — and is tried again in the
// background until it succeeds.
func TestVaultSessionIndexMaintenanceRetriesReconcile(t *testing.T) {
	lowerSessionCap(t, 3)
	s, fv := newFakeVaultStore(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	storeSession(t, s, fv, newTestSession(t, readerRoleArn, later), false)

	failures := 0
	fv.setFail(func(method, path string) int {
		// The reconcile's first request, which no count makes.
		if method == "LIST" && strings.TrimSuffix(path, "/") == "iam/sessions-by-role" {
			failures++
			return http.StatusBadRequest
		}
		return 0
	})
	maintainInBackground(t, s, 10*time.Millisecond, time.Hour)
	waitFor(t, "a failed reconcile to be retried", func() bool {
		fv.mu.Lock()
		defer fv.mu.Unlock()
		return failures >= 2
	})
	if s.sessionIndexReconciled.Load() {
		t.Fatal("the index was trusted after a failed reconcile")
	}

	mintSession(t, s, readerRoleArn, later)
	mintSession(t, s, readerRoleArn, later)
	_, err := s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
	requireThrottling(t, err)

	fv.setFail(nil)
	waitFor(t, "the reconcile to succeed", s.sessionIndexReconciled.Load)
	if got := len(markersOf(s, fv, readerRoleArn)); got != 3 {
		t.Errorf("%s has %d markers after reconciling, want 3", readerRoleArn, got)
	}
	fv.resetLog()
	_, err = s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
	requireThrottling(t, err)
	if got := fv.total(); got != 1 {
		t.Errorf("a count after reconciling took %d Vault requests, want 1 (log: %v)", got, fv.log)
	}
}

// TestVaultSessionIndexMaintenanceSweepsAbandonedRoles checks that the
// expired sessions of a role nobody assumes any more, which no count visits,
// are removed by the periodic sweep, and not only by a restart.
func TestVaultSessionIndexMaintenanceSweepsAbandonedRoles(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	maintainInBackground(t, s, time.Hour, 10*time.Millisecond)
	waitFor(t, "the startup reconcile", s.sessionIndexReconciled.Load)

	abandoned := newTestSession(t, "arn:aws:iam::123456789012:role/deleted", time.Now().Add(-time.Minute))
	storeSession(t, s, fv, abandoned, true)
	// What a session write that failed for good leaves behind: metadata
	// with no session in it, and no marker.
	leftover := "iam/sessions/" + newTestSession(t, readerRoleArn, time.Now().Add(time.Hour)).AccessKeyId
	fv.mu.Lock()
	fv.secrets[leftover] = &fakeSecret{}
	fv.mu.Unlock()

	waitFor(t, "the sweep to remove the abandoned role's expired session", func() bool {
		_, sessionLeft := fv.secret("iam/sessions/" + abandoned.AccessKeyId)
		_, markerLeft := fv.secret(markerPath(s, abandoned))
		_, metadataLeft := fv.secret(leftover)
		return !sessionLeft && !markerLeft && !metadataLeft
	})
}

// TestVaultSessionIndexMaintenanceStopsWhenDenied checks that a Vault
// policy that does not cover the index stops the maintenance for good
// rather than having it retried forever.
func TestVaultSessionIndexMaintenanceStopsWhenDenied(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	fv.loginStatus = http.StatusBadRequest
	fv.fail = func(_, path string) int {
		if strings.HasPrefix(path, "iam/sessions-by-role") {
			return http.StatusForbidden
		}
		return 0
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.maintainSessionIndex(context.Background(), time.Millisecond, time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session index maintenance kept running after Vault denied the index")
	}
	if !s.sessionIndexDenied.Load() || s.sessionIndexReconciled.Load() {
		t.Errorf("denied = %v, reconciled = %v; want the index denied and untrusted",
			s.sessionIndexDenied.Load(), s.sessionIndexReconciled.Load())
	}
}

func TestNewVaultReconcilesSessionIndexInBackground(t *testing.T) {
	seed, fv := newFakeVaultStore(t)
	before := newTestSession(t, readerRoleArn, time.Now().Add(time.Hour))
	storeSession(t, seed, fv, before, false)

	store, err := NewVault(VaultConfig{
		EndpointURL:       fv.URL,
		RootToken:         "root",
		MountPath:         "secret",
		SecretStoragePath: "iam",
	})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	vs := store.(*VaultStore)
	waitFor(t, "startup reconcile", vs.sessionIndexReconciled.Load)
	if _, ok := fv.secret(markerPath(vs, before)); !ok {
		t.Error("startup reconcile did not index a session stored before the index")
	}
}

func TestSessionMarkerName(t *testing.T) {
	const id = "ASIA0000000000000001"
	expiration := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	name := sessionMarkerName(id, expiration)
	if want := id + "." + strconv.FormatInt(expiration.Unix(), 10); name != want {
		t.Fatalf("sessionMarkerName = %q, want %q", name, want)
	}
	gotID, gotExpiration, ok := parseSessionMarkerName(name)
	if !ok || gotID != id || !gotExpiration.Equal(expiration) {
		t.Errorf("parseSessionMarkerName(%q) = %q, %v, %v; want %q, %v, true", name, gotID, gotExpiration, ok, id, expiration)
	}

	// A fraction of a second rounds up, never down.
	_, gotExpiration, _ = parseSessionMarkerName(sessionMarkerName(id, expiration.Add(time.Millisecond)))
	if want := expiration.Add(time.Second); !gotExpiration.Equal(want) {
		t.Errorf("expiry of a marker for %v = %v, want %v", expiration.Add(time.Millisecond), gotExpiration, want)
	}

	// The access key id of a marker becomes part of a Vault path when its
	// expired session is removed.
	for _, bad := range []string{"", id, id + ".", id + ".soon", "short.1", "../users/alice.1", "ASIA/../../users/alice.1", "subdir/"} {
		if _, _, ok := parseSessionMarkerName(bad); ok {
			t.Errorf("parseSessionMarkerName(%q) accepted a name sessionMarkerName cannot produce", bad)
		}
	}

	s := newVaultStoreAt(t, "http://127.0.0.1:0")
	segment := strings.TrimPrefix(s.sessionRolePath(readerRoleArn), s.sessionsByRolePath()+"/")
	if segment == "" || strings.Contains(segment, "/") {
		t.Errorf("role directory segment %q for %s is not a single path segment", segment, readerRoleArn)
	}
}

// withFastRetries replaces s's Vault client with one that retries as the
// default client does, but without waiting a second between tries.
func withFastRetries(t *testing.T, s *VaultStore, fv *fakeVault) {
	t.Helper()
	client, err := vault.New(vault.WithAddress(fv.URL), vault.WithRequestTimeout(5*time.Second),
		vault.WithRetryConfiguration(vault.RetryConfiguration{RetryWaitMin: time.Millisecond, RetryWaitMax: 5 * time.Millisecond, RetryMax: 2}))
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	if err := client.SetToken("root"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	s.client = client
}

// TestVaultCreateSessionWriteFailureAfterCommit covers a session write that
// Vault committed although its reply was lost: the client retries it, and
// the retry is refused by the check-and-set. The session is stored, so its
// marker must stay and count it.
func TestVaultCreateSessionWriteFailureAfterCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		// readFails makes reading the session back fail too, so whether
		// it was stored cannot be told.
		readFails bool
	}{
		{name: "stored session is read back"},
		{name: "read back fails", readFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lowerSessionCap(t, 1)
			s, fv := newReconciledFakeVaultStore(t)
			withFastRetries(t, s, fv)
			ctx := context.Background()
			later := time.Now().Add(time.Hour)

			session := newTestSession(t, readerRoleArn, later)
			sessionPath := "iam/sessions/" + session.AccessKeyId
			lost := false
			fv.failAfterCommit = func(method, path string) int {
				if path == sessionPath && !lost {
					lost = true
					return http.StatusBadGateway
				}
				return 0
			}
			if tc.readFails {
				fv.fail = func(method, path string) int {
					if method == http.MethodGet && path == sessionPath {
						return http.StatusBadRequest
					}
					return 0
				}
			}

			got, err := s.CreateSession(ctx, session)
			if tc.readFails {
				if err == nil {
					t.Fatal("CreateSession succeeded although the session could not be read back")
				}
			} else {
				if err != nil {
					t.Fatalf("CreateSession for a session Vault stored: %v", err)
				}
				if got.SessionToken != session.SessionToken {
					t.Errorf("CreateSession = %+v, want the session minted", got)
				}
			}
			if !lost {
				t.Fatal("the session write was not retried")
			}
			fv.failAfterCommit, fv.fail = nil, nil

			if _, err := s.GetSession(ctx, session.AccessKeyId); err != nil {
				t.Fatalf("GetSession of the stored session: %v", err)
			}
			if _, ok := fv.secret(markerPath(s, session)); !ok {
				t.Error("the marker of a stored session was removed")
			}
			_, err = s.CreateSession(ctx, newTestSession(t, readerRoleArn, later))
			requireThrottling(t, err)
		})
	}
}
