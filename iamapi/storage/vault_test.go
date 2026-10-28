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
	"time"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

// newVaultStoreAt returns a VaultStore talking to the Vault at url with a
// static token. It is built directly, not through NewVault, which starts a
// background access key index backfill whose requests would race with what a
// test serves or counts.
func newVaultStoreAt(t *testing.T, url string) *VaultStore {
	t.Helper()

	client, err := vault.New(vault.WithAddress(url), vault.WithRequestTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	if err := client.SetToken("root"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	return &VaultStore{
		client:            client,
		kvReqOpts:         []vault.RequestOption{vault.WithMountPath("secret")},
		secretStoragePath: "iam",
		usage:             newAccessKeyUsageTracker(),
	}
}

// newVaultStoreOnHandler returns a VaultStore talking to a Vault whose KV v2
// engine is answered by handler.
func newVaultStoreOnHandler(t *testing.T, handler http.HandlerFunc) *VaultStore {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return newVaultStoreAt(t, srv.URL)
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
	store := newVaultStoreOnHandler(t, func(w http.ResponseWriter, r *http.Request) {
		writeVaultJSON(t, w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
	})

	t.Run("GetUserByAccessKeyID", func(t *testing.T) {
		_, err := store.GetUserByAccessKeyID(context.Background(), "AKIA00000000000ALICE")
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
// between the listing and the read of its record, in the scan a lookup falls
// back to when the access key index has no entry: its absence says nothing
// about the key being looked for, which belongs to a later user in the scan.
func TestVaultGetUserByAccessKeyIDSkipsUsersDeletedMidScan(t *testing.T) {
	const bobKey = "AKIA0000000000000BOB"
	bob := types.User{
		UserName:   "bob",
		AccessKeys: []types.AccessKeyEntry{{AccessKeyId: bobKey, Status: "Active"}},
	}
	bobRecord, err := json.Marshal(bob)
	if err != nil {
		t.Fatalf("marshal user: %v", err)
	}
	var bobFields map[string]any
	if err := json.Unmarshal(bobRecord, &bobFields); err != nil {
		t.Fatalf("unmarshal user: %v", err)
	}

	// The user the lookup re-points the index entry at, from what the scan
	// found.
	repaired := make(chan string, 1)
	store := newVaultStoreOnHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch path := strings.TrimSuffix(r.URL.Path, "/"); {
		case strings.Contains(path, "/data/iam/access-keys/") && r.Method == http.MethodGet:
			writeVaultJSON(t, w, http.StatusNotFound, map[string]any{"errors": []string{}})
		case strings.HasSuffix(path, "/data/iam/access-keys/"+bobKey) && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			var req struct {
				Data map[string]any `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode index write: %v", err)
			}
			owner, _ := req.Data[accessKeyIndexUserField].(string)
			repaired <- owner
			writeVaultJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"version": 1}})
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

	user, err := store.GetUserByAccessKeyID(context.Background(), bobKey)
	if err != nil {
		t.Fatalf("GetUserByAccessKeyID: %v", err)
	}
	if user.UserName != "bob" {
		t.Fatalf("GetUserByAccessKeyID user = %q, want bob", user.UserName)
	}
	select {
	case owner := <-repaired:
		if owner != "bob" {
			t.Errorf("index entry repaired to %q, want bob", owner)
		}
	default:
		t.Error("the lookup did not repair the missing index entry")
	}

	_, err = store.GetUserByAccessKeyID(context.Background(), "AKIA000000000UNKNOWN")
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
	store := newVaultStoreOnHandler(t, func(w http.ResponseWriter, r *http.Request) {
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
		// Long enough that only the rune can disqualify it, since an access
		// key id becomes part of the index entry's Vault path.
		accessKeyID := "AKIA0000000000000000" + string(r)
		if _, err := store.GetUserByAccessKeyID(ctx, accessKeyID); !iamerr.IsNoSuchEntity(err) {
			t.Errorf("GetUserByAccessKeyID(%q) err = %v, want a NoSuchEntity error", accessKeyID, err)
		}
	}
}
