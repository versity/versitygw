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

package iamapi

import (
	"testing"

	"github.com/versity/versitygw/iamapi/storage"
)

// TestOIDCConfigParseDiscoveryURLs covers the "<provider url>=<discovery
// url>" pairs the CLI and Helm chart pass through: a malformed pair fails at
// startup rather than at the first AssumeRoleWithWebIdentity, and a valid one
// is keyed by the provider's stored Url so the lookup at fetch time hits.
func TestOIDCConfigParseDiscoveryURLs(t *testing.T) {
	const discoveryURL = "https://oidc.oidc-ns/.well-known/openid-configuration"

	tests := []struct {
		name     string
		pairs    []string
		insecure bool
		want     map[string]string
	}{
		{
			name:  "https provider keyed scheme-stripped",
			pairs: []string{"https://oidc.example.com=" + discoveryURL},
			want:  map[string]string{"oidc.example.com": discoveryURL},
		},
		{
			name:  "provider port survives into the key",
			pairs: []string{"https://oidc.example.com:8443=" + discoveryURL},
			want:  map[string]string{"oidc.example.com:8443": discoveryURL},
		},
		{
			name:     "http provider keeps its scheme",
			pairs:    []string{"http://127.0.0.1:8080=" + discoveryURL},
			insecure: true,
			want:     map[string]string{"http://127.0.0.1:8080": discoveryURL},
		},
		{
			name:     "plaintext discovery url with insecure transport",
			pairs:    []string{"https://oidc.example.com=http://127.0.0.1:8080/.well-known/openid-configuration"},
			insecure: true,
			want:     map[string]string{"oidc.example.com": "http://127.0.0.1:8080/.well-known/openid-configuration"},
		},
		{
			name:  "plaintext discovery url without insecure transport",
			pairs: []string{"https://oidc.example.com=http://127.0.0.1:8080/.well-known/openid-configuration"},
		},
		{
			name:  "no separator",
			pairs: []string{"https://oidc.example.com"},
		},
		{
			name:  "empty discovery url",
			pairs: []string{"https://oidc.example.com="},
		},
		{
			name:  "provider url without a scheme",
			pairs: []string{"oidc.example.com=" + discoveryURL},
		},
		{
			name:  "discovery url without a scheme",
			pairs: []string{"https://oidc.example.com=oidc.oidc-ns"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := OIDCConfig{DiscoveryURLs: tt.pairs, AllowInsecureTransport: tt.insecure}
			err := cfg.parseDiscoveryURLs()
			if tt.want == nil {
				if err == nil {
					t.Fatalf("parseDiscoveryURLs(%q) = nil, want an error", tt.pairs)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDiscoveryURLs(%q): %v", tt.pairs, err)
			}
			got := cfg.endpointPolicy().DiscoveryURLs
			if len(got) != len(tt.want) {
				t.Fatalf("DiscoveryURLs = %v, want %v", got, tt.want)
			}
			for provider, want := range tt.want {
				if got[provider] != want {
					t.Errorf("DiscoveryURLs[%q] = %q, want %q", provider, got[provider], want)
				}
			}
		})
	}
}

// TestNewRejectsInvalidDiscoveryURLs confirms the parse runs at construction
// time, so a bad flag value never reaches a running server.
func TestNewRejectsInvalidDiscoveryURLs(t *testing.T) {
	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	if _, err := New(store, testRoot, WithQuiet(), WithOIDCDiscoveryURLs([]string{"not-a-pair"})); err == nil {
		t.Fatal("New with a malformed discovery url = nil error, want a failure")
	}
}
