// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/stretchr/testify/assert"
)

// fakeBlob emulates the Azure Blob Storage operations IAMServiceAzure
// uses on its single blob: Get Blob and Put Blob, with ETags and the
// If-Match and If-None-Match conditions.
type fakeBlob struct {
	mu      sync.Mutex
	data    []byte
	etag    string // empty while the blob does not exist
	version int
	puts    int

	// noContainer makes every request fail as if the container was
	// missing.
	noContainer bool
	// beforePut, when set, runs before each Put Blob condition is
	// checked, emulating another gateway instance writing in between.
	beforePut func(f *fakeBlob)
}

func (f *fakeBlob) set(data []byte) {
	f.version++
	f.data = data
	f.etag = fmt.Sprintf(`"0x%d"`, f.version)
}

// addAccount stores acc as another gateway instance would.
func (f *fakeBlob) addAccount(acc Account) {
	conf := defaultIAMConfig()
	if f.etag != "" {
		conf, _ = parseIAM(f.data)
	}
	conf.AccessAccounts[acc.Access] = acc
	b, _ := json.Marshal(conf)
	f.set(b)
}

func (f *fakeBlob) accounts(t *testing.T) map[string]Account {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	conf, err := parseIAM(f.data)
	assert.NoError(t, err)
	return conf.AccessAccounts
}

func (f *fakeBlob) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

func azError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)
}

func (f *fakeBlob) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path != "/acct/iam/"+iamFile {
		azError(w, http.StatusBadRequest, "InvalidUri")
		return
	}
	if f.noContainer {
		azError(w, http.StatusNotFound, "ContainerNotFound")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if f.etag == "" {
			azError(w, http.StatusNotFound, "BlobNotFound")
			return
		}
		w.Header().Set("ETag", f.etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(f.data)))
		w.WriteHeader(http.StatusOK)
		w.Write(f.data)
	case http.MethodPut:
		f.puts++
		if f.beforePut != nil {
			f.beforePut(f)
		}
		if r.Header.Get("If-None-Match") == "*" && f.etag != "" {
			azError(w, http.StatusConflict, "BlobAlreadyExists")
			return
		}
		ifMatch := r.Header.Get("If-Match")
		if ifMatch != "" && ifMatch != f.etag {
			azError(w, http.StatusPreconditionFailed, "ConditionNotMet")
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			azError(w, http.StatusBadRequest, "InvalidInput")
			return
		}
		f.set(b)
		w.Header().Set("ETag", f.etag)
		w.WriteHeader(http.StatusCreated)
	default:
		azError(w, http.StatusMethodNotAllowed, "UnsupportedHttpVerb")
	}
}

func newTestAzureIAM(t *testing.T, f *fakeBlob) *IAMServiceAzure {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	key := base64.StdEncoding.EncodeToString([]byte("testkey"))
	s, err := NewAzure(Account{Access: "root", Secret: "rootsecret", Role: RoleAdmin},
		"acct", key, srv.URL+"/acct", "", "iam")
	if err != nil {
		t.Fatalf("NewAzure: %v", err)
	}
	s.retryDelay = time.Microsecond
	return s
}

func TestNewAzureValidatesOptions(t *testing.T) {
	tests := []struct {
		name                         string
		account, key, url, container string
		wantErr                      string
	}{
		{
			name:    "missing container",
			account: "acct",
			wantErr: "container",
		},
		{
			name:      "missing account and url",
			container: "iam",
			wantErr:   "storage account or service URL",
		},
		{
			// the url avoids the missing account and url check
			name:      "key without account",
			key:       "secret",
			url:       "http://127.0.0.1:1/acct",
			container: "iam",
			wantErr:   "requires a storage account name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAzure(Account{Access: "root"}, tt.account, tt.key, tt.url, "", tt.container)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestIAMServiceAzureAccounts(t *testing.T) {
	f := &fakeBlob{}
	s := newTestAzureIAM(t, f)

	// nothing stored yet
	_, err := s.GetUserAccount("alice")
	assert.Equal(t, ErrNoSuchUser, err)
	accs, err := s.ListUserAccounts()
	assert.NoError(t, err)
	assert.Empty(t, accs)

	alice := Account{Access: "alice", Secret: "alicesecret", Role: RoleUser, UserID: 1}
	bob := Account{Access: "bob", Secret: "bobsecret", Role: RoleUserPlus}
	assert.NoError(t, s.CreateAccount(bob))
	assert.NoError(t, s.CreateAccount(alice))
	assert.Equal(t, ErrUserExists, s.CreateAccount(alice))
	assert.Equal(t, ErrUserExists, s.CreateAccount(Account{Access: "root"}))

	acc, err := s.GetUserAccount("alice")
	assert.NoError(t, err)
	assert.Equal(t, alice, acc)

	// the root account is never stored
	acc, err = s.GetUserAccount("root")
	assert.NoError(t, err)
	assert.Equal(t, "rootsecret", acc.Secret)
	assert.NotContains(t, f.accounts(t), "root")

	assert.NoError(t, s.UpdateUserAccount("bob", MutableProps{Role: RoleAdmin}))
	assert.Equal(t, ErrNoSuchUser, s.UpdateUserAccount("carol", MutableProps{Role: RoleAdmin}))
	assert.Equal(t, RoleAdmin, f.accounts(t)["bob"].Role)

	accs, err = s.ListUserAccounts()
	assert.NoError(t, err)
	if assert.Len(t, accs, 2) {
		assert.Equal(t, "alice", accs[0].Access)
		assert.Equal(t, "bob", accs[1].Access)
	}

	assert.NoError(t, s.DeleteUserAccount("bob"))
	// deleting a missing account is not an error, like the internal IAM
	assert.NoError(t, s.DeleteUserAccount("bob"))
	_, err = s.GetUserAccount("bob")
	assert.Equal(t, ErrNoSuchUser, err)
	assert.Equal(t, map[string]Account{"alice": alice}, f.accounts(t))
}

func TestIAMServiceAzureDeleteMissingAccountDoesNotStore(t *testing.T) {
	f := &fakeBlob{}
	f.addAccount(Account{Access: "alice", Role: RoleUser})
	s := newTestAzureIAM(t, f)

	assert.NoError(t, s.DeleteUserAccount("bob"))
	assert.Equal(t, 0, f.putCount())
}

func TestIAMServiceAzureRetriesWhenBlobCreatedConcurrently(t *testing.T) {
	f := &fakeBlob{}
	f.beforePut = func(f *fakeBlob) {
		if f.puts == 1 {
			f.addAccount(Account{Access: "other", Role: RoleUser})
		}
	}
	s := newTestAzureIAM(t, f)

	assert.NoError(t, s.CreateAccount(Account{Access: "alice", Role: RoleUser}))
	assert.Equal(t, 2, f.putCount())
	assert.Len(t, f.accounts(t), 2)
}

func TestIAMServiceAzureRetriesOnConflict(t *testing.T) {
	f := &fakeBlob{}
	f.addAccount(Account{Access: "alice", Role: RoleUser})
	f.beforePut = func(f *fakeBlob) {
		if f.puts <= 3 {
			f.addAccount(Account{Access: fmt.Sprintf("other%d", f.puts), Role: RoleUser})
		}
	}
	s := newTestAzureIAM(t, f)

	assert.NoError(t, s.UpdateUserAccount("alice", MutableProps{Role: RoleUserPlus}))
	assert.Equal(t, 4, f.putCount())

	// the update was applied on top of every concurrent write
	accs := f.accounts(t)
	assert.Len(t, accs, 4)
	assert.Equal(t, RoleUserPlus, accs["alice"].Role)
}

func TestIAMServiceAzureCreateWithLostResponse(t *testing.T) {
	alice := Account{Access: "alice", Secret: "alicesecret", Role: RoleUser}
	f := &fakeBlob{}
	f.beforePut = func(f *fakeBlob) {
		// the first Put Blob was stored, but its response was lost, so
		// the one seen here is the SDK retry and fails its condition
		if f.puts == 1 {
			f.addAccount(alice)
		}
	}
	s := newTestAzureIAM(t, f)

	assert.NoError(t, s.CreateAccount(alice))
	assert.Equal(t, 1, f.putCount())
	assert.Equal(t, map[string]Account{"alice": alice}, f.accounts(t))
}

func TestIAMServiceAzureCreateRacingSameAccess(t *testing.T) {
	alice := Account{Access: "alice", Secret: "alicesecret", Role: RoleUser}
	other := Account{Access: "alice", Secret: "othersecret", Role: RoleUser}
	f := &fakeBlob{}
	f.beforePut = func(f *fakeBlob) {
		// another instance creates a different account with the same
		// access key in between
		if f.puts == 1 {
			f.addAccount(other)
		}
	}
	s := newTestAzureIAM(t, f)

	assert.Equal(t, ErrUserExists, s.CreateAccount(alice))
	assert.Equal(t, map[string]Account{"alice": other}, f.accounts(t))
}

func TestIAMServiceAzureGivesUpAfterMaxRetries(t *testing.T) {
	f := &fakeBlob{}
	f.addAccount(Account{Access: "alice", Role: RoleUser})
	f.beforePut = func(f *fakeBlob) {
		f.addAccount(Account{Access: fmt.Sprintf("other%d", f.puts), Role: RoleUser})
	}
	s := newTestAzureIAM(t, f)

	err := s.CreateAccount(Account{Access: "bob", Role: RoleUser})
	assert.True(t, bloberror.HasCode(err, bloberror.ConditionNotMet))
	assert.Equal(t, azureIAMMaxAttempts, f.putCount())
	assert.NotContains(t, f.accounts(t), "bob")
}

func TestNewAzureFailsWhenContainerIsMissing(t *testing.T) {
	srv := httptest.NewServer(&fakeBlob{noContainer: true})
	t.Cleanup(srv.Close)

	key := base64.StdEncoding.EncodeToString([]byte("testkey"))
	_, err := NewAzure(Account{Access: "root"}, "acct", key, srv.URL+"/acct", "", "iam")
	assert.True(t, bloberror.HasCode(err, bloberror.ContainerNotFound))
}

func TestIAMServiceAzureMissingContainerIsNotAMissingUser(t *testing.T) {
	f := &fakeBlob{}
	s := newTestAzureIAM(t, f)
	f.noContainer = true // the container is deleted while the gateway runs

	_, err := s.GetUserAccount("alice")
	assert.Error(t, err)
	assert.NotEqual(t, ErrNoSuchUser, err)
	assert.Error(t, s.CreateAccount(Account{Access: "alice", Role: RoleUser}))
}
