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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Vault answers a KV v2 read of a missing secret with 404 and this body.
func TestVaultIAMServiceGetUserAccountUnknownReturnsErrNoSuchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/kv-v2/data/users/NOSUCHKEYID0000000", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errors":[]}`))
	}))
	defer srv.Close()

	iam, err := NewVaultIAMService(Account{Access: "root"}, srv.URL, "", "users", "", "", "", "", "token", "", "", "", "", "")
	assert.NoError(t, err)

	_, err = iam.GetUserAccount("NOSUCHKEYID0000000")
	assert.Equal(t, ErrNoSuchUser, err)

	missing, err := iam.ResolveAccounts([]string{"NOSUCHKEYID0000000"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"NOSUCHKEYID0000000"}, missing)
}

// Any Vault error other than 404, such as a token whose policy doesn't cover
// the path, must not be mistaken for a missing account.
func TestVaultIAMServiceGetUserAccountPermissionDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()

	iam, err := NewVaultIAMService(Account{Access: "root"}, srv.URL, "", "users", "", "", "", "", "token", "", "", "", "", "")
	assert.NoError(t, err)

	_, err = iam.GetUserAccount("user1")
	assert.Error(t, err)
	assert.NotEqual(t, ErrNoSuchUser, err)
}
