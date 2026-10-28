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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

// newFakeVaultStore returns a VaultStore talking to a Vault whose KV v2
// engine is answered by handler.
func newFakeVaultStore(t *testing.T, handler http.HandlerFunc) Storer {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	store, err := NewVault(VaultConfig{EndpointURL: srv.URL, RootToken: "root", MountPath: "secret"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	return store
}

func writeVaultJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// TestVaultStoreFailureIsNotNotFound pins what the identity resolvers rely
// on: a Vault that cannot answer is never reported with the errors that mean
// an access key or session does not exist. The failure is a rejected token
// because the client retries a sealed Vault's 503 with a backoff that would
// make the test take seconds; the store treats every non-404 alike.
func TestVaultStoreFailureIsNotNotFound(t *testing.T) {
	store := newFakeVaultStore(t, func(w http.ResponseWriter, r *http.Request) {
		writeVaultJSON(t, w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
	})

	t.Run("GetUserByAccessKeyID", func(t *testing.T) {
		_, err := store.GetUserByAccessKeyID(context.Background(), "AKIAALICE")
		if err == nil {
			t.Fatal("GetUserByAccessKeyID succeeded against a sealed Vault")
		}
		if iamerr.IsNoSuchEntity(err) {
			t.Fatalf("GetUserByAccessKeyID reported a sealed Vault as a missing key: %v", err)
		}
	})

	t.Run("GetSession", func(t *testing.T) {
		_, err := store.GetSession(context.Background(), "ASIASESSION")
		if err == nil {
			t.Fatal("GetSession succeeded against a sealed Vault")
		}
		if errors.Is(err, iamutil.ErrSessionNotFound) {
			t.Fatalf("GetSession reported a sealed Vault as a missing session: %v", err)
		}
	})
}

// TestVaultGetUserByAccessKeyIDSkipsUsersDeletedMidScan covers a user deleted
// between the listing and the read of its record: its absence says nothing
// about the key being looked for, which belongs to a later user in the scan.
func TestVaultGetUserByAccessKeyIDSkipsUsersDeletedMidScan(t *testing.T) {
	bob := types.User{
		UserName:   "bob",
		AccessKeys: []types.AccessKeyEntry{{AccessKeyId: "AKIABOB", Status: "Active"}},
	}
	bobRecord, err := json.Marshal(bob)
	if err != nil {
		t.Fatalf("marshal user: %v", err)
	}
	var bobFields map[string]any
	if err := json.Unmarshal(bobRecord, &bobFields); err != nil {
		t.Fatalf("unmarshal user: %v", err)
	}

	store := newFakeVaultStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch path := strings.TrimSuffix(r.URL.Path, "/"); {
		case strings.HasSuffix(path, "/metadata/iam/users"):
			writeVaultJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"keys": []string{"ghost", "bob"}}})
		case strings.HasSuffix(path, "/data/iam/users/ghost"):
			writeVaultJSON(t, w, http.StatusNotFound, map[string]any{"errors": []string{}})
		case strings.HasSuffix(path, "/data/iam/users/bob"):
			writeVaultJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{
				"data":     map[string]any{"bob": bobFields},
				"metadata": map[string]any{"version": 1},
			}})
		default:
			t.Errorf("unexpected Vault request %s %s", r.Method, r.URL.Path)
			writeVaultJSON(t, w, http.StatusNotFound, map[string]any{"errors": []string{}})
		}
	})

	user, err := store.GetUserByAccessKeyID(context.Background(), "AKIABOB")
	if err != nil {
		t.Fatalf("GetUserByAccessKeyID: %v", err)
	}
	if user.UserName != "bob" {
		t.Fatalf("GetUserByAccessKeyID user = %q, want bob", user.UserName)
	}

	_, err = store.GetUserByAccessKeyID(context.Background(), "AKIAUNKNOWN")
	if !iamerr.IsNoSuchEntity(err) {
		t.Fatalf("GetUserByAccessKeyID unknown key err = %v, want a NoSuchEntity error", err)
	}
}

// TestVaultNonPrintableNamesAreNotFound covers names that cannot be part of a
// Vault path: Vault refuses a path holding a non-printable rune with a 400,
// so nothing can be stored under one, and a lookup is answered as not found
// without asking Vault. Reported as Vault failing, an unauthenticated client
// could turn a junk access key id or role ARN into a retried 500.
func TestVaultNonPrintableNamesAreNotFound(t *testing.T) {
	store := newFakeVaultStore(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected Vault request %s %s", r.Method, r.URL.Path)
		writeVaultJSON(t, w, http.StatusBadRequest, map[string]any{"errors": []string{}})
	})

	ctx := context.Background()
	// NUL, a C0 control, DEL, NEL, a no-break space, a line separator and
	// a byte order mark: every class of rune unicode.IsPrint rejects.
	for _, r := range []rune{0x00, 0x1f, 0x7f, 0x85, 0xa0, 0x2028, 0xfeff} {
		name := "name" + string(r)
		if _, err := store.GetUser(ctx, name); !iamerr.IsNoSuchEntity(err) {
			t.Errorf("GetUser(%q) err = %v, want a NoSuchEntity error", name, err)
		}
		if _, err := store.GetRole(ctx, name); !iamerr.IsNoSuchEntity(err) {
			t.Errorf("GetRole(%q) err = %v, want a NoSuchEntity error", name, err)
		}
		if _, err := store.GetSession(ctx, "ASIA"+string(r)); !errors.Is(err, iamutil.ErrSessionNotFound) {
			t.Errorf("GetSession(%q) err = %v, want ErrSessionNotFound", "ASIA"+string(r), err)
		}
	}
}
