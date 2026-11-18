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

package azblobclient

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("testkey"))

	tests := []struct {
		name                       string
		account, key, url, sas     string
		wantURL                    string
		wantSAS, wantKey, wantDflt bool
	}{
		{
			name:    "sas and account without url",
			account: "acct",
			sas:     "sv=2024-01-01&sig=abc",
			wantURL: "https://acct.blob.core.windows.net/",
			wantSAS: true,
		},
		{
			name:    "question mark only falls back to account and key",
			account: "acct",
			key:     key,
			sas:     "?",
			wantURL: "https://acct.blob.core.windows.net/",
			wantKey: true,
		},
		{
			name:    "account and key",
			account: "acct",
			key:     key,
			wantURL: "https://acct.blob.core.windows.net/",
			wantKey: true,
		},
		{
			name:     "account only",
			account:  "acct",
			wantURL:  "https://acct.blob.core.windows.net/",
			wantDflt: true,
		},
		{
			name:     "key without account",
			key:      key,
			url:      "https://example.com/",
			wantURL:  "https://example.com/",
			wantDflt: true,
		},
		{
			name:    "explicit url wins",
			account: "acct",
			key:     key,
			url:     "http://127.0.0.1:10000/acct",
			wantURL: "http://127.0.0.1:10000/acct",
			wantKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// AZURE_CLIENT_ID must not be taken as the account name
			t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")

			client, creds, err := New(tt.account, tt.key, tt.url, tt.sas)
			if !assert.NoError(t, err) {
				return
			}
			assert.NotNil(t, client)
			assert.Equal(t, tt.wantURL, creds.ServiceURL)
			assert.Equal(t, tt.wantSAS, creds.SASToken != "")
			assert.Equal(t, tt.wantKey, creds.SharedKey != nil)
			assert.Equal(t, tt.wantDflt, creds.Default != nil)
			if tt.wantKey {
				assert.Equal(t, tt.account, creds.SharedKey.AccountName())
			}
		})
	}
}

func TestNewKeepsSASOutOfTransportErrors(t *testing.T) {
	// a port nothing listens on, so the request fails with a transport
	// error carrying its URL
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	endpoint := "http://" + l.Addr().String() + "/acct"
	l.Close()

	client, _, err := New("", "", endpoint, "sv=2024-01-01&sig=SECRETSIGNATURE", noRetries)
	if !assert.NoError(t, err) {
		return
	}

	_, err = client.DownloadStream(context.Background(), "iam", "users.json", nil)
	if assert.Error(t, err) {
		// the URL is still reported, only its query is removed
		assert.Contains(t, err.Error(), "/acct/iam/users.json")
		assert.NotContains(t, err.Error(), "SECRETSIGNATURE")
	}
}

// noRetries disables retries. The clients ignore policy.WithRetryOptions.
func noRetries(o *policy.ClientOptions) { o.Retry.MaxRetries = -1 }

func TestNewRejectsInvalidSASWithoutLeakingToken(t *testing.T) {
	for _, tt := range []struct{ name, token string }{
		{"newline", "sig=SECRET\n"},
		{"carriage return", "sig=SECRET\r"},
		{"nul", "sig=SECRET\x00"},
		{"del", "sig=SECRET\x7f"},
		{"bad escape", "sig=SECRET%zz"},
		{"semicolon", "sig=SECRET;bad"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, creds, err := New("", "", "http://localhost/acct", tt.token)
			assert.Nil(t, client)
			assert.Empty(t, creds)
			if assert.Error(t, err) {
				assert.NotContains(t, err.Error(), "SECRET")
			}
		})
	}
}

func TestNewTrimsLeadingQuestionMarkFromSAS(t *testing.T) {
	client, creds, err := New("", "", "http://localhost/acct", "?sv=2024-01-01&sig=abc")
	if assert.NoError(t, err) {
		assert.NotNil(t, client)
		assert.Equal(t, "sv=2024-01-01&sig=abc", creds.SASToken)
		assert.NotContains(t, client.URL(), "??")
	}
}

type ctxKey struct{}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// The transport of a client from New does not see values of the caller's
// context.
func TestNewHidesContextValuesFromTransport(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("testkey"))
	var got any = "unset"
	client, _, err := New("acct", key, "http://127.0.0.1/acct", "", func(o *policy.ClientOptions) {
		o.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
			got = req.Context().Value(ctxKey{})
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
		})
	})
	if !assert.NoError(t, err) {
		return
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, "v")
	_, err = client.ServiceClient().NewContainerClient("bucket").GetProperties(ctx, nil)
	assert.NoError(t, err)
	assert.Nil(t, got, "transport saw a value of the caller's context")
}

// Cancelling the caller's context still ends an in-flight request.
func TestNewRequestContextCancelReachesTransport(t *testing.T) {
	inflight, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(inflight) })
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(upstream.Close)
	// runs before upstream.Close, which waits for the handler
	t.Cleanup(func() { close(done) })
	key := base64.StdEncoding.EncodeToString([]byte("testkey"))
	client, _, err := New("acct", key, upstream.URL+"/acct", "")
	if !assert.NoError(t, err) {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := client.ServiceClient().NewContainerClient("bucket").GetProperties(ctx, nil)
		errc <- err
	}()
	select {
	case <-inflight:
	case err := <-errc:
		t.Fatalf("GetProperties returned before reaching the server: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach the server")
	}
	cancel()

	select {
	case err := <-errc:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("GetProperties did not return after its context was canceled")
	}
}

type tokenCredentialFunc func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (f tokenCredentialFunc) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f(ctx, opts)
}

// Token requests of a bearer-token policy, which azblob adds after the
// per-call policies, do not see values of the caller's context either.
func TestWithoutContextValuesHidesValuesFromTokenRequests(t *testing.T) {
	var got any = "unset"
	cred := tokenCredentialFunc(func(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
		got = ctx.Value(ctxKey{})
		return azcore.AccessToken{Token: "token", ExpiresOn: time.Now().Add(time.Hour)}, nil
	})
	pl := runtime.NewPipeline("azblobclient", "test",
		runtime.PipelineOptions{PerRetry: []policy.Policy{runtime.NewBearerTokenPolicy(cred, []string{"scope"}, nil)}},
		&policy.ClientOptions{
			PerCallPolicies: []policy.Policy{withoutContextValues{}},
			Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
			}),
		})

	req, err := runtime.NewRequest(context.WithValue(context.Background(), ctxKey{}, "v"), http.MethodGet, "https://acct.blob.core.windows.net/")
	if !assert.NoError(t, err) {
		return
	}
	resp, err := pl.Do(req)
	if !assert.NoError(t, err) {
		return
	}
	resp.Body.Close()
	assert.Nil(t, got, "token request saw a value of the caller's context")
}
