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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
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

func TestIpaIAMServiceLoginRetrySendsBodyAgain(t *testing.T) {
	transport := &retryTransport{}
	ipa := &IpaIAMService{
		client:   http.Client{Transport: transport},
		host:     "https://ipa.example.test",
		username: "admin",
		password: "secret",
	}

	assert.NoError(t, ipa.login())
	assert.Equal(t, 2, transport.calls)
	if assert.Len(t, transport.bodies, 2) {
		assert.Equal(t, "password=secret&user=admin", transport.bodies[1])
	}
}

func TestIpaIAMServiceRPCInternalRetrySendsBodyAgain(t *testing.T) {
	transport := &retryTransport{
		respBody: `{"result": {"result": null, "value": "", "summary": null}, "error": null, "id": 1, "principal": "admin@EXAMPLE.TEST", "version": "4.13.1"}`,
	}
	ipa := &IpaIAMService{
		client: http.Client{Transport: transport},
		host:   "https://ipa.example.test",
	}

	_, err := ipa.rpcInternal(`{"method":"user_show","params":[["admin"],{}]}`)
	assert.NoError(t, err)
	assert.Equal(t, 2, transport.calls)
	if assert.Len(t, transport.bodies, 2) {
		assert.Equal(t, `{"method":"user_show","params":[["admin"],{}]}`, transport.bodies[1])
	}
}

func TestIsRetryable(t *testing.T) {
	wrap := func(err error) error {
		return &url.Error{Op: "Post", URL: "https://ipa.example.test", Err: err}
	}
	reset := wrap(&net.OpError{Op: "read", Net: "tcp",
		Err: os.NewSyscallError("read", syscall.ECONNRESET)})
	refused := wrap(&net.OpError{Op: "dial", Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})

	assert.True(t, isRetryable(wrap(io.EOF)), "EOF")
	assert.True(t, isRetryable(reset), "connection reset")
	assert.False(t, isRetryable(refused), "connection refused")
	assert.False(t, isRetryable(nil), "nil")
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

// retryTransport fails the first attempt with a retryable error and records
// the body of every attempt, so a retry that reuses a spent request shows up
// as an empty body.
type retryTransport struct {
	calls    int
	bodies   []string
	respBody string
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++

	var body string
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(b)
	}
	t.bodies = append(t.bodies, body)

	if t.calls == 1 {
		return nil, io.EOF
	}
	if req.ContentLength > 0 && int64(len(body)) != req.ContentLength {
		return nil, fmt.Errorf("http: ContentLength=%d with Body length %d",
			req.ContentLength, len(body))
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.respBody)),
		Request:    req,
	}, nil
}
