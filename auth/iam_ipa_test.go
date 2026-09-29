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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// FreeIPA JSON-RPC response bodies, as returned by a FreeIPA 4.13 server.
const (
	ipaUserShowNotFound = `{"result": null, "error": {"code": 4001, "message": "nosuchkeyid0000000: user not found", "data": {"reason": "nosuchkeyid0000000: user not found"}, "name": "NotFound"}, "id": 0, "principal": "admin@EXAMPLE.TEST", "version": "4.13.1"}`
	ipaUserShowFound    = `{"result": {"result": {"uid": ["novaultuser"], "uidnumber": ["1828600004"], "gidnumber": ["1828600004"]}, "value": "novaultuser", "summary": null}, "error": null, "id": 0, "principal": "admin@EXAMPLE.TEST", "version": "4.13.1"}`
	ipaVaultNotFound    = `{"result": null, "error": {"code": 4001, "message": "s3secret: vault not found", "data": {"reason": "s3secret: vault not found"}, "name": "NotFound"}, "id": 1, "principal": "admin@EXAMPLE.TEST", "version": "4.13.1"}`
	ipaVersionError     = `{"result": null, "error": {"code": 901, "message": "9.999 client incompatible with 2.257 server at 'https://ipa.example.test/ipa/xml'", "data": {"cver": "9.999", "sver": "2.257", "server": "https://ipa.example.test/ipa/xml"}, "name": "VersionError"}, "id": 0, "principal": "admin@EXAMPLE.TEST", "version": "4.13.1"}`
)

func TestIpaIAMServiceGetUserAccountNotFound(t *testing.T) {
	tests := []struct {
		name       string
		responses  map[string]string
		noSuchUser bool
	}{
		{
			name:       "unknown user",
			responses:  map[string]string{"user_show/1": ipaUserShowNotFound},
			noSuchUser: true,
		},
		{
			name: "user without vault",
			responses: map[string]string{
				"user_show/1":               ipaUserShowFound,
				"vault_retrieve_internal/1": ipaVaultNotFound,
			},
			noSuchUser: true,
		},
		{
			name:      "other rpc error",
			responses: map[string]string{"user_show/1": ipaVersionError},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipa := newFakeIpaIAMService(t, tt.responses)

			_, err := ipa.GetUserAccount("NOSUCHKEYID0000000")
			if tt.noSuchUser {
				assert.Equal(t, ErrNoSuchUser, err)
			} else {
				assert.ErrorIs(t, err, errRpc)
				assert.NotErrorIs(t, err, ErrNoSuchUser)
			}
		})
	}
}

// newFakeIpaIAMService returns an IpaIAMService talking to a fake FreeIPA
// server that answers each JSON-RPC method with the given response body.
func newFakeIpaIAMService(t *testing.T, responses map[string]string) *IpaIAMService {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ipa/session/login_password" {
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		resp, ok := responses[req.Method]
		assert.True(t, ok, "unexpected IPA method %q", req.Method)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	return &IpaIAMService{
		client:          *srv.Client(),
		version:         IpaVersion,
		host:            srv.URL,
		vaultName:       "s3secret",
		kraTransportKey: &key.PublicKey,
		rootAcc:         Account{Access: "root"},
	}
}
