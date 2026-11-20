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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go/schema"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

// fakeVault is just enough of Vault's KV v2 HTTP API for VaultStore: reads,
// writes with check-and-set, listing, metadata deletion and AppRole login.
// Every request is logged so tests can assert how many Vault calls an
// operation costs, which is the whole point of the access key index.
//
// It behaves like a KV mount configured with cas_required: a write without a
// cas option is refused. Every write VaultStore makes carries one, which is
// what lets it run on such a mount, so every test here also checks that.
type fakeVault struct {
	*httptest.Server

	mu      sync.Mutex
	secrets map[string]*fakeSecret
	log     []string
	logins  int
	// loginStatus, when non-zero, is the status AppRole logins fail with.
	loginStatus int
	// fail, when set, may answer a request with an error status instead of
	// serving it; it returns 0 to let the request through.
	fail func(method, path string) int
}

type fakeSecret struct {
	version int
	data    map[string]any
}

const fakeMount = "secret/"

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	fv := &fakeVault{secrets: map[string]*fakeSecret{}}
	fv.Server = httptest.NewServer(http.HandlerFunc(fv.serve))
	t.Cleanup(fv.Close)
	return fv
}

func (fv *fakeVault) reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (fv *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	fv.mu.Lock()
	defer fv.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/v1/")

	if strings.HasPrefix(path, "auth/approle/login") {
		fv.logins++
		if fv.loginStatus != 0 {
			fv.reply(w, fv.loginStatus, map[string]any{"errors": []string{"injected login failure"}})
			return
		}
		// Like Vault's own login reply, this carries an (empty) "data"
		// element: without one the client does not treat the body as a
		// structured response and leaves Auth unset.
		fv.reply(w, http.StatusOK, map[string]any{
			"data": map[string]any{},
			"auth": map[string]any{"client_token": "token"},
		})
		return
	}

	method := r.Method
	if method == http.MethodGet && r.URL.Query().Get("list") == "true" {
		method = "LIST"
	}
	rest, ok := strings.CutPrefix(path, fakeMount)
	if !ok {
		fv.reply(w, http.StatusNotFound, map[string]any{"errors": []string{"unsupported path"}})
		return
	}
	kind, name, _ := strings.Cut(rest, "/")
	fv.log = append(fv.log, method+" "+name)

	if fv.fail != nil {
		if status := fv.fail(method, name); status != 0 {
			fv.reply(w, status, map[string]any{"errors": []string{"injected failure"}})
			return
		}
	}

	notFound := func() { fv.reply(w, http.StatusNotFound, map[string]any{"errors": []string{}}) }

	switch {
	case kind == "data" && method == http.MethodGet:
		sec, ok := fv.secrets[name]
		if !ok {
			notFound()
			return
		}
		fv.reply(w, http.StatusOK, map[string]any{"data": map[string]any{
			"data":     sec.data,
			"metadata": map[string]any{"version": sec.version},
		}})

	case kind == "data" && (method == http.MethodPost || method == http.MethodPut):
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Data    map[string]any `json:"data"`
			Options map[string]any `json:"options"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			fv.reply(w, http.StatusBadRequest, map[string]any{"errors": []string{err.Error()}})
			return
		}
		cur := 0
		if sec, ok := fv.secrets[name]; ok {
			cur = sec.version
		}
		cas, ok := req.Options["cas"]
		if !ok {
			fv.reply(w, http.StatusBadRequest, map[string]any{"errors": []string{"check-and-set parameter required for this call"}})
			return
		}
		if want, _ := cas.(float64); int(want) != cur {
			fv.reply(w, http.StatusBadRequest, map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
			return
		}
		fv.secrets[name] = &fakeSecret{version: cur + 1, data: req.Data}
		fv.reply(w, http.StatusOK, map[string]any{"data": map[string]any{"version": cur + 1}})

	case kind == "metadata" && method == "LIST":
		prefix := strings.TrimSuffix(name, "/") + "/"
		var keys []string
		for p := range fv.secrets {
			if after, ok := strings.CutPrefix(p, prefix); ok && !strings.Contains(after, "/") {
				keys = append(keys, after)
			}
		}
		if len(keys) == 0 {
			notFound()
			return
		}
		sort.Strings(keys)
		fv.reply(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})

	case kind == "metadata" && method == http.MethodDelete:
		delete(fv.secrets, name)
		w.WriteHeader(http.StatusNoContent)

	case kind == "metadata" && method == http.MethodPost:
		w.WriteHeader(http.StatusNoContent)

	default:
		fv.reply(w, http.StatusMethodNotAllowed, nil)
	}
}

// resetLog forgets the requests seen so far, so a test can measure just the
// operation it is about to run.
func (fv *fakeVault) resetLog() {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.log = nil
}

// count returns how many logged requests are for method on a path containing
// substr.
func (fv *fakeVault) count(method, substr string) int {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	n := 0
	for _, line := range fv.log {
		m, p, _ := strings.Cut(line, " ")
		if m == method && strings.Contains(p, substr) {
			n++
		}
	}
	return n
}

// total returns how many requests were logged since the last resetLog.
func (fv *fakeVault) total() int {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	return len(fv.log)
}

func (fv *fakeVault) secret(name string) (map[string]any, bool) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	sec, ok := fv.secrets[name]
	if !ok {
		return nil, false
	}
	return sec.data, true
}

// remove drops a secret behind the store's back, the way an older version of
// the service, or a failed cleanup, would leave things.
func (fv *fakeVault) remove(name string) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	delete(fv.secrets, name)
}

// put writes a secret behind the store's back.
func (fv *fakeVault) put(name string, data map[string]any) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.secrets[name] = &fakeSecret{version: 1, data: data}
}

func (fv *fakeVault) indexedOwner(accessKeyID string) (string, bool) {
	data, ok := fv.secret("iam/access-keys/" + accessKeyID)
	if !ok {
		return "", false
	}
	owner, _ := data[accessKeyIndexUserField].(string)
	return owner, true
}

func newFakeVaultStore(t *testing.T) (*VaultStore, *fakeVault) {
	t.Helper()
	fv := newFakeVault(t)
	return newStoreOn(t, fv), fv
}

// newStoreOn returns a store backed by fv. Calling it twice for the same fv
// gives two service instances sharing one Vault, each with its own in-process
// state.
func newStoreOn(t *testing.T, fv *fakeVault) *VaultStore {
	t.Helper()
	return newVaultStoreAt(t, fv.URL)
}

// addUserWithKey creates a user holding one access key and returns the key's
// id.
func addUserWithKey(t *testing.T, s *VaultStore, name string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, types.User{UserName: name, UserID: "AIDA" + name, Arn: "arn:aws:iam::123456789012:user/" + name}); err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	id := fmt.Sprintf("AKIA%016s", strings.ToUpper(name))
	if _, err := s.CreateAccessKey(ctx, CreateAccessKeyInput{
		UserName:        name,
		AccessKeyID:     id,
		SecretAccessKey: "secret-" + name,
		Status:          "Active",
		CreateDate:      time.Now().UTC().Truncate(time.Second),
	}); err != nil {
		t.Fatalf("CreateAccessKey(%s): %v", name, err)
	}
	return id
}

func requireOwner(t *testing.T, s *VaultStore, accessKeyID, wantUser string) {
	t.Helper()
	user, err := s.GetUserByAccessKeyID(context.Background(), accessKeyID)
	if err != nil {
		t.Fatalf("GetUserByAccessKeyID(%s): %v", accessKeyID, err)
	}
	if user.UserName != wantUser {
		t.Fatalf("GetUserByAccessKeyID(%s) = user %q, want %q", accessKeyID, user.UserName, wantUser)
	}
}

func requireNoSuchAccessKey(t *testing.T, s *VaultStore, accessKeyID string) {
	t.Helper()
	_, err := s.GetUserByAccessKeyID(context.Background(), accessKeyID)
	if !errors.Is(err, iamerr.NoSuchEntityAccessKey(accessKeyID)) {
		t.Fatalf("GetUserByAccessKeyID(%s) error = %v, want NoSuchEntityAccessKey", accessKeyID, err)
	}
}

// TestVaultAccessKeyLookupCostIsIndependentOfUserCount is the regression test
// for the lookup cost growing with the number of users: whichever user owns
// the key, resolving it takes the same two reads and never lists users.
func TestVaultAccessKeyLookupCostIsIndependentOfUserCount(t *testing.T) {
	s, fv := newFakeVaultStore(t)

	const users = 60
	ids := make([]string, users)
	for i := range ids {
		ids[i] = addUserWithKey(t, s, fmt.Sprintf("user%03d", i))
	}

	for _, idx := range []int{0, users / 2, users - 1} {
		fv.resetLog()
		requireOwner(t, s, ids[idx], fmt.Sprintf("user%03d", idx))
		if got := fv.total(); got != 2 {
			t.Errorf("lookup of user %d took %d Vault requests, want 2 (log: %v)", idx, got, fv.log)
		}
		if got := fv.count("LIST", ""); got != 0 {
			t.Errorf("lookup of user %d listed %d times, want 0", idx, got)
		}
	}
}

// TestVaultAccessKeyLookupRepairsMissingIndexEntry covers data written before
// the index existed: the first lookup scans and writes the entry back, every
// later one is cheap, and nothing needed migrating.
func TestVaultAccessKeyLookupRepairsMissingIndexEntry(t *testing.T) {
	s, fv := newFakeVaultStore(t)

	var ids []string
	for i := range 10 {
		ids = append(ids, addUserWithKey(t, s, fmt.Sprintf("user%02d", i)))
	}
	last := ids[len(ids)-1]
	fv.remove("iam/access-keys/" + last)

	fv.resetLog()
	requireOwner(t, s, last, "user09")
	if got := fv.count("LIST", "users"); got != 1 {
		t.Errorf("first lookup listed users %d times, want 1 (scan)", got)
	}
	if owner, ok := fv.indexedOwner(last); !ok || owner != "user09" {
		t.Fatalf("index entry after first lookup = %q, %v; want it repaired to user09", owner, ok)
	}

	fv.resetLog()
	requireOwner(t, s, last, "user09")
	if got := fv.total(); got != 2 {
		t.Errorf("lookup after repair took %d Vault requests, want 2", got)
	}
}

// TestVaultAccessKeyLookupDistrustsStaleIndexEntry checks that the user record
// stays the source of truth: an entry naming a user that does not hold the key
// never authenticates it, and is corrected from the scan.
func TestVaultAccessKeyLookupDistrustsStaleIndexEntry(t *testing.T) {
	s, fv := newFakeVaultStore(t)

	aliceKey := addUserWithKey(t, s, "alice")
	addUserWithKey(t, s, "bob")

	fv.put("iam/access-keys/"+aliceKey, map[string]any{accessKeyIndexUserField: "bob"})
	requireOwner(t, s, aliceKey, "alice")
	if owner, _ := fv.indexedOwner(aliceKey); owner != "alice" {
		t.Errorf("index entry = %q after lookup, want it corrected to alice", owner)
	}

	// An entry naming a user that no longer exists is stale in the same way.
	fv.put("iam/access-keys/"+aliceKey, map[string]any{accessKeyIndexUserField: "ghost"})
	requireOwner(t, s, aliceKey, "alice")
	if owner, _ := fv.indexedOwner(aliceKey); owner != "alice" {
		t.Errorf("index entry = %q after lookup, want it corrected to alice", owner)
	}

	// And a malformed one.
	fv.put("iam/access-keys/"+aliceKey, map[string]any{"unexpected": 1})
	requireOwner(t, s, aliceKey, "alice")
}

func TestVaultDeletedAccessKeyIsRevoked(t *testing.T) {
	s, fv := newFakeVaultStore(t)

	id := addUserWithKey(t, s, "alice")
	requireOwner(t, s, id, "alice")

	if err := s.DeleteAccessKey(context.Background(), "alice", id); err != nil {
		t.Fatalf("DeleteAccessKey: %v", err)
	}
	requireNoSuchAccessKey(t, s, id)
	if _, ok := fv.indexedOwner(id); ok {
		t.Error("index entry survived DeleteAccessKey")
	}

	// The revocation must not depend on the cleanup having worked: if the
	// entry outlives the key, the key still must not resolve, and the lookup
	// removes the leftover.
	fv.put("iam/access-keys/"+id, map[string]any{accessKeyIndexUserField: "alice"})
	requireNoSuchAccessKey(t, s, id)
	if _, ok := fv.indexedOwner(id); ok {
		t.Error("stale index entry for a deleted key was not removed by the lookup")
	}
}

func TestVaultAccessKeyIndexFollowsUserRename(t *testing.T) {
	s, fv := newFakeVaultStore(t)

	id := addUserWithKey(t, s, "alice")
	if _, err := s.UpdateUser(context.Background(), UpdateUserInput{UserName: "alice", NewUserName: "bob"}); err != nil {
		t.Fatalf("UpdateUser rename: %v", err)
	}

	if owner, _ := fv.indexedOwner(id); owner != "bob" {
		t.Errorf("index entry = %q after rename, want bob", owner)
	}
	fv.resetLog()
	requireOwner(t, s, id, "bob")
	if got := fv.count("LIST", ""); got != 0 {
		t.Errorf("lookup after rename scanned (%d lists), want it served from the index", got)
	}
}

func TestVaultAccessKeyLookupOfUnknownKey(t *testing.T) {
	s, _ := newFakeVaultStore(t)
	addUserWithKey(t, s, "alice")

	requireNoSuchAccessKey(t, s, "AKIAUNKNOWNUNKNOWN")
}

// TestVaultAccessKeyLookupRejectsMalformedIDs checks that an id which could
// not be a key this service issued is refused without any Vault request, in
// particular that it never reaches a Vault path.
func TestVaultAccessKeyLookupRejectsMalformedIDs(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	addUserWithKey(t, s, "alice")

	for _, id := range []string{"", "short", "../users/alice", "AKIA/../../users/alice", "AKIA0000000000000000 ", strings.Repeat("A", 200)} {
		fv.resetLog()
		requireNoSuchAccessKey(t, s, id)
		if got := fv.total(); got != 0 {
			t.Errorf("lookup of %q made %d Vault requests, want 0", id, got)
		}
	}
}

// TestVaultAccessKeyLookupReportsVaultFailures checks that a Vault failure is
// reported as one, not mistaken for the key not existing. The injected status
// is a 400 rather than a 5xx only because the Vault client retries 5xx
// responses with a backoff that would make the test slow; the store treats
// every status other than 403 and 404 alike.
func TestVaultAccessKeyLookupReportsVaultFailures(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	id := addUserWithKey(t, s, "alice")

	for _, target := range []string{"access-keys", "users"} {
		fv.fail = func(_, path string) int {
			if strings.Contains(path, target) {
				return http.StatusBadRequest
			}
			return 0
		}
		_, err := s.GetUserByAccessKeyID(context.Background(), id)
		if err == nil || errors.Is(err, iamerr.NoSuchEntityAccessKey(id)) || errors.Is(err, iamerr.NoSuchEntityUser("alice")) {
			t.Errorf("with %s failing, GetUserByAccessKeyID error = %v, want a Vault error", target, err)
		}
	}
	fv.fail = nil
	requireOwner(t, s, id, "alice")
}

// TestVaultAccessKeyIndexDeniedByPolicy covers a Vault policy written before
// the index existed, which does not cover its path: nothing may break, and
// the index must be given up on rather than re-authenticated against and
// retried on every lookup — whether the store holds AppRole credentials or a
// static token, for which an AppRole login is not an option at all.
func TestVaultAccessKeyIndexDeniedByPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		appRole bool
		// wantLogins is how many AppRole logins it may take to conclude
		// that the denial is a policy and not an expired token.
		wantLogins int
	}{
		{name: "static token", appRole: false, wantLogins: 0},
		{name: "approle", appRole: true, wantLogins: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fv := newFakeVaultStore(t)
			if tc.appRole {
				s.creds = schema.AppRoleLoginRequest{RoleId: "role", SecretId: "secret"}
			} else {
				// What a Vault with AppRole mounted answers a login with no
				// credentials: a static-token store must never depend on it.
				fv.loginStatus = http.StatusBadRequest
			}
			fv.fail = func(_, path string) int {
				if strings.HasPrefix(path, "iam/access-keys") {
					return http.StatusForbidden
				}
				return 0
			}

			id := addUserWithKey(t, s, "alice") // creating the key must not fail
			requireOwner(t, s, id, "alice")     // lookups fall back to scanning

			if !s.indexDenied.Load() {
				t.Fatal("index was not disabled after Vault denied access to it")
			}
			if fv.logins != tc.wantLogins {
				t.Errorf("concluding the index is denied took %d AppRole logins, want %d", fv.logins, tc.wantLogins)
			}
			logins := fv.logins

			fv.resetLog()
			for range 5 {
				requireOwner(t, s, id, "alice")
			}
			if got := fv.count("GET", "access-keys") + fv.count("POST", "access-keys") + fv.count("LIST", "access-keys"); got != 0 {
				t.Errorf("%d requests still went to the disabled index", got)
			}
			if fv.logins != logins {
				t.Errorf("lookups re-authenticated %d times after the index was disabled", fv.logins-logins)
			}

			if err := s.DeleteAccessKey(context.Background(), "alice", id); err != nil {
				t.Fatalf("DeleteAccessKey: %v", err)
			}
			requireNoSuchAccessKey(t, s, id)
		})
	}
}

// TestVaultAccessKeyLookupReAuthFailure checks that when a 403 cannot be
// resolved because re-authenticating itself fails, that failure is reported
// as what it is. In particular the login's own status must not be read as the
// outcome of the call that needed it: a login answered with 404 is not "no
// index entry", nor "no users", either of which would turn an authentication
// outage into "no such access key". Nor is it a reason to switch the index
// off for good.
func TestVaultAccessKeyLookupReAuthFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		loginStatus int
		denied      string // path prefix answered with 403
	}{
		{"index denied, login refused", http.StatusBadRequest, "iam/access-keys"},
		{"index denied, login not found", http.StatusNotFound, "iam/access-keys"},
		{"users denied, login not found", http.StatusNotFound, "iam/users"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fv := newFakeVaultStore(t)
			s.creds = schema.AppRoleLoginRequest{RoleId: "role", SecretId: "secret"}
			id := addUserWithKey(t, s, "alice")
			// Send the lookup down the scan, so a denied users path is hit.
			fv.remove("iam/access-keys/" + id)

			fv.loginStatus = tc.loginStatus
			fv.fail = func(_, path string) int {
				if strings.HasPrefix(path, tc.denied) {
					return http.StatusForbidden
				}
				return 0
			}
			_, err := s.GetUserByAccessKeyID(context.Background(), id)
			if err == nil || errors.Is(err, iamerr.NoSuchEntityAccessKey(id)) {
				t.Fatalf("GetUserByAccessKeyID error = %v, want the re-authentication failure", err)
			}
			if s.indexDenied.Load() {
				t.Error("a failed re-authentication switched the index off")
			}

			fv.loginStatus = 0
			fv.fail = nil
			requireOwner(t, s, id, "alice")
		})
	}
}

// TestVaultCreateAccessKeyReplacesStaleIndexEntry covers an entry left behind
// under the id a new key is created with: it has to be overwritten, which
// with check-and-set means re-reading it for its version first.
func TestVaultCreateAccessKeyReplacesStaleIndexEntry(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	id := fmt.Sprintf("AKIA%016s", "ALICE")
	fv.put("iam/access-keys/"+id, map[string]any{accessKeyIndexUserField: "ghost"})

	if got := addUserWithKey(t, s, "alice"); got != id {
		t.Fatalf("addUserWithKey made key %s, want %s", got, id)
	}
	if owner, _ := fv.indexedOwner(id); owner != "alice" {
		t.Errorf("index entry = %q after CreateAccessKey, want alice", owner)
	}
	fv.resetLog()
	requireOwner(t, s, id, "alice")
	if got := fv.total(); got != 2 {
		t.Errorf("lookup took %d Vault requests, want 2", got)
	}
}

func TestVaultGetAccessKeyLastUsedUsesIndex(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	var last string
	for i := range 20 {
		last = addUserWithKey(t, s, fmt.Sprintf("user%02d", i))
	}

	fv.resetLog()
	out, err := s.GetAccessKeyLastUsed(context.Background(), last)
	if err != nil {
		t.Fatalf("GetAccessKeyLastUsed: %v", err)
	}
	if out.UserName != "user19" {
		t.Errorf("UserName = %q, want user19", out.UserName)
	}
	if got := fv.total(); got != 2 {
		t.Errorf("GetAccessKeyLastUsed took %d Vault requests, want 2", got)
	}
}

// waitFor polls cond until it holds, failing the test if it never does.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func lastUsedOf(t *testing.T, s *VaultStore, id string) *GetAccessKeyLastUsedOutput {
	t.Helper()
	out, err := s.GetAccessKeyLastUsed(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAccessKeyLastUsed: %v", err)
	}
	return out
}

// TestVaultRecordAccessKeyUsageSkipsVaultInsideCoalesceWindow checks that the
// coalescing window spares Vault the reads as well as the writes: once a use
// is recorded, further uses of the same key inside the window cost nothing.
func TestVaultRecordAccessKeyUsageSkipsVaultInsideCoalesceWindow(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	id := addUserWithKey(t, s, "alice")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first use to be recorded", func() bool { return lastUsedOf(t, s, id).ServiceName == "s3" })
	if got := lastUsedOf(t, s, id); !got.LastUsedDate.Equal(now) || got.Region != "us-east-1" {
		t.Fatalf("recorded %+v, want s3/us-east-1 at %v", got, now)
	}

	fv.resetLog()
	for i := range 100 {
		if err := s.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", now.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	if got := fv.total(); got != 0 {
		t.Errorf("uses inside the coalescing window made %d Vault requests, want 0", got)
	}

	// A different service is never coalesced, and neither is the next window.
	if err := s.RecordAccessKeyUsage(ctx, id, "iam", "us-east-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "service change to be recorded", func() bool { return lastUsedOf(t, s, id).ServiceName == "iam" })

	later := now.Add(UsageRecordCoalesceWindow + time.Second)
	if err := s.RecordAccessKeyUsage(ctx, id, "iam", "us-east-1", later); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "next window to be recorded", func() bool { return lastUsedOf(t, s, id).LastUsedDate.Equal(later) })
}

// TestVaultRecordAccessKeyUsageRechecksVaultAfterTrustHorizon checks that the
// tracker's memory is only believed for usageTrackerTrust: after that a use
// goes back to the stored record — one lookup, and no write while that record
// is still inside the coalescing window.
func TestVaultRecordAccessKeyUsageRechecksVaultAfterTrustHorizon(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	id := addUserWithKey(t, s, "alice")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first use to be recorded", func() bool { return lastUsedOf(t, s, id).ServiceName == "s3" })

	fv.resetLog()
	if err := s.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", now.Add(usageTrackerTrust-time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := fv.total(); got != 0 {
		t.Errorf("use inside the trust horizon made %d Vault requests, want 0", got)
	}

	beyond := now.Add(usageTrackerTrust + time.Second)
	if err := s.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", beyond); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "use beyond the horizon to be checked against Vault", func() bool { return fv.count("GET", "users/alice") >= 1 })
	// Let the goroutine finish before asserting that it wrote nothing.
	waitFor(t, "recheck to finish", func() bool {
		s.usage.mu.Lock()
		defer s.usage.mu.Unlock()
		return len(s.usage.inflight) == 0
	})
	if got := fv.count("POST", "users/alice"); got != 0 {
		t.Errorf("recheck of a record still inside the coalescing window wrote %d times, want 0", got)
	}
	if got := lastUsedOf(t, s, id); !got.LastUsedDate.Equal(now) {
		t.Errorf("LastUsedDate = %v, want it left at %v (coalesced)", got.LastUsedDate, now)
	}
}

// TestVaultRecordAccessKeyUsageSeesOtherInstancesRecords covers several
// service instances sharing one Vault. Instance B records a different service
// for a key instance A has recorded; A must not go on skipping its own uses
// (as its memory alone would have it) for the whole coalescing window, but
// notice B's record once its memory has aged past the trust horizon and put
// its service back.
func TestVaultRecordAccessKeyUsageSeesOtherInstancesRecords(t *testing.T) {
	a, fv := newFakeVaultStore(t)
	b := newStoreOn(t, fv)
	id := addUserWithKey(t, a, "alice")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := a.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "A's record", func() bool { return lastUsedOf(t, a, id).ServiceName == "s3" })

	if err := b.RecordAccessKeyUsage(ctx, id, "iam", "us-east-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B's record", func() bool { return lastUsedOf(t, a, id).ServiceName == "iam" })

	// Past the horizon but well inside the coalescing window, where A's
	// memory alone would still say there is nothing to record.
	if usageTrackerTrust >= UsageRecordCoalesceWindow/2 {
		t.Fatalf("usageTrackerTrust (%v) must be well below UsageRecordCoalesceWindow (%v)", usageTrackerTrust, UsageRecordCoalesceWindow)
	}
	later := now.Add(UsageRecordCoalesceWindow / 2)
	if err := a.RecordAccessKeyUsage(ctx, id, "s3", "us-east-1", later); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "A to record s3 over B's record", func() bool { return lastUsedOf(t, a, id).ServiceName == "s3" })
}

// TestVaultRecordAccessKeyUsageConcurrentBurst checks that a burst of
// concurrent requests for one key writes its last-used record once.
func TestVaultRecordAccessKeyUsageConcurrentBurst(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	id := addUserWithKey(t, s, "alice")
	now := time.Now().UTC().Truncate(time.Second)

	fv.resetLog()
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.RecordAccessKeyUsage(context.Background(), id, "s3", "us-east-1", now)
		}()
	}
	wg.Wait()
	waitFor(t, "burst to be recorded", func() bool { return lastUsedOf(t, s, id).ServiceName == "s3" })

	// Each GetAccessKeyLastUsed poll above only reads; the writes are the
	// POSTs to the user record.
	if got := fv.count("POST", "users/alice"); got != 1 {
		t.Errorf("burst wrote the user record %d times, want 1", got)
	}
}

func TestVaultRecordAccessKeyUsageForgetsDeletedKey(t *testing.T) {
	s, _ := newFakeVaultStore(t)
	id := addUserWithKey(t, s, "alice")
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.RecordAccessKeyUsage(context.Background(), id, "s3", "us-east-1", now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "use to be recorded", func() bool { return lastUsedOf(t, s, id).ServiceName == "s3" })

	if err := s.DeleteAccessKey(context.Background(), "alice", id); err != nil {
		t.Fatal(err)
	}
	s.usage.mu.Lock()
	_, remembered := s.usage.recorded[id]
	s.usage.mu.Unlock()
	if remembered {
		t.Error("usage tracker still remembers a deleted access key")
	}
}

func TestVaultBackfillAccessKeyIndex(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	ctx := context.Background()

	ids := map[string]string{}
	for i := range 5 {
		name := fmt.Sprintf("user%d", i)
		ids[addUserWithKey(t, s, name)] = name
	}
	// Strip the index, as for data written before it existed...
	var kept string
	for id := range ids {
		fv.remove("iam/access-keys/" + id)
		kept = id
	}
	// ...except for one entry, which the backfill must leave exactly as it is
	// even though it disagrees with the user record.
	fv.put("iam/access-keys/"+kept, map[string]any{accessKeyIndexUserField: "elsewhere"})

	if err := s.backfillAccessKeyIndex(ctx); err != nil {
		t.Fatalf("backfillAccessKeyIndex: %v", err)
	}
	for id, name := range ids {
		want := name
		if id == kept {
			want = "elsewhere"
		}
		if owner, ok := fv.indexedOwner(id); !ok || owner != want {
			t.Errorf("index entry for %s = %q, %v; want %q", id, owner, ok, want)
		}
	}

	fv.resetLog()
	if err := s.backfillAccessKeyIndex(ctx); err != nil {
		t.Fatalf("second backfillAccessKeyIndex: %v", err)
	}
	if got := fv.count("POST", "access-keys"); got != 0 {
		t.Errorf("second backfill wrote %d entries, want 0", got)
	}
}

// TestVaultBackfillAccessKeyIndexSkipsUnreadableUser checks that one user
// record that cannot be parsed does not stop the backfill from indexing the
// users after it.
func TestVaultBackfillAccessKeyIndexSkipsUnreadableUser(t *testing.T) {
	s, fv := newFakeVaultStore(t)
	id := addUserWithKey(t, s, "zed")
	fv.remove("iam/access-keys/" + id)
	// Sorts before "zed", and is not a user record at all.
	fv.put("iam/users/aaa", map[string]any{"aaa": "not a user"})

	if err := s.backfillAccessKeyIndex(context.Background()); err == nil {
		t.Error("backfillAccessKeyIndex reported success despite skipping a user")
	}
	if owner, ok := fv.indexedOwner(id); !ok || owner != "zed" {
		t.Errorf("index entry for %s = %q, %v; want zed", id, owner, ok)
	}
}

func TestNewVaultBackfillsAccessKeyIndexInBackground(t *testing.T) {
	seed, fv := newFakeVaultStore(t)
	ids := map[string]string{}
	for i := range 3 {
		name := fmt.Sprintf("user%d", i)
		ids[addUserWithKey(t, seed, name)] = name
	}
	for id := range ids {
		fv.remove("iam/access-keys/" + id)
	}

	if _, err := NewVault(VaultConfig{
		EndpointURL:       fv.URL,
		RootToken:         "root",
		MountPath:         "secret",
		SecretStoragePath: "iam",
	}); err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	waitFor(t, "startup backfill", func() bool {
		for id, name := range ids {
			if owner, ok := fv.indexedOwner(id); !ok || owner != name {
				return false
			}
		}
		return true
	})
}
