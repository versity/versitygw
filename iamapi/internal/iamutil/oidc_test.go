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

package iamutil

import (
	"strings"
	"testing"
)

var (
	strictOIDCPolicy   = OIDCEndpointPolicy{}
	privateOIDCPolicy  = OIDCEndpointPolicy{AllowPrivateEndpoints: true}
	insecureOIDCPolicy = OIDCEndpointPolicy{AllowPrivateEndpoints: true, AllowInsecureTransport: true}
)

func TestValidateOIDCProviderURL(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		policy OIDCEndpointPolicy
		want   string // "" means the URL must be rejected
	}{
		// Default posture: AWS's own rules.
		{"https host", "https://example.com", strictOIDCPolicy, "example.com"},
		{"https host with path", "https://example.com/oidc", strictOIDCPolicy, "example.com/oidc"},
		{"no scheme", "example.com", strictOIDCPolicy, ""},
		{"http rejected by default", "http://example.com", strictOIDCPolicy, ""},
		{"port rejected by default", "https://example.com:8443", strictOIDCPolicy, ""},
		{"userinfo", "https://user@example.com", strictOIDCPolicy, ""},
		{"query", "https://example.com?a=b", strictOIDCPolicy, ""},
		{"fragment", "https://example.com#frag", strictOIDCPolicy, ""},
		{"too long", "https://" + strings.Repeat("a", MaxOIDCProviderURLLen) + ".com", strictOIDCPolicy, ""},
		{"empty", "", strictOIDCPolicy, ""},

		// AllowPrivateEndpoints: an explicit port becomes legal. A private
		// address was always legal *syntax* - it is the fetch that refuses
		// it - so a bare private host is accepted under both policies.
		{"port allowed", "https://spire-oidc.spire.svc:8443", privateOIDCPolicy, "spire-oidc.spire.svc:8443"},
		{"loopback with port", "https://127.0.0.1:8443", privateOIDCPolicy, "127.0.0.1:8443"},
		{"ipv6 literal with port", "https://[::1]:8443", privateOIDCPolicy, "[::1]:8443"},
		{"cluster service no port", "https://spire-oidc.spire.svc", privateOIDCPolicy, "spire-oidc.spire.svc"},
		{"http still rejected", "http://127.0.0.1:8080", privateOIDCPolicy, ""},

		// AllowInsecureTransport: http is accepted and, unlike https, keeps
		// its scheme in the stored form.
		{"http kept verbatim", "http://127.0.0.1:8080", insecureOIDCPolicy, "http://127.0.0.1:8080"},
		{"http with path", "http://127.0.0.1:8080/oidc", insecureOIDCPolicy, "http://127.0.0.1:8080/oidc"},
		{"https still stripped", "https://example.com", insecureOIDCPolicy, "example.com"},
		{"other scheme still rejected", "ftp://example.com", insecureOIDCPolicy, ""},
		{"http userinfo still rejected", "http://user@127.0.0.1:8080", insecureOIDCPolicy, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateOIDCProviderURL(tt.rawURL, tt.policy)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("ValidateOIDCProviderURL(%q, %+v) = %q, want an error", tt.rawURL, tt.policy, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateOIDCProviderURL(%q, %+v): %v", tt.rawURL, tt.policy, err)
			}
			if got != tt.want {
				t.Errorf("ValidateOIDCProviderURL(%q, %+v) = %q, want %q", tt.rawURL, tt.policy, got, tt.want)
			}
		})
	}
}

// TestOIDCProviderURLSchemeStaysDistinguishable pins down why an http
// provider keeps its scheme in the stored form: the stored Url is what an
// incoming token's iss claim is matched against, so if "http://host" were
// stored stripped it would be indistinguishable from a separately
// registered "https://host", and a token from either issuer would satisfy
// the other's trust policy.
func TestOIDCProviderURLSchemeStaysDistinguishable(t *testing.T) {
	secure, err := ValidateOIDCProviderURL("https://idp.example", insecureOIDCPolicy)
	if err != nil {
		t.Fatalf("ValidateOIDCProviderURL(https): %v", err)
	}
	insecure, err := ValidateOIDCProviderURL("http://idp.example", insecureOIDCPolicy)
	if err != nil {
		t.Fatalf("ValidateOIDCProviderURL(http): %v", err)
	}
	if secure == insecure {
		t.Fatalf("http and https providers for the same host both stored as %q", secure)
	}

	// WebIdentityIssuer is the other half: it must map each token's iss back
	// onto exactly the provider that issued it.
	for iss, want := range map[string]string{
		"https://idp.example": secure,
		"http://idp.example":  insecure,
	} {
		got, ok := WebIdentityIssuer(map[string]any{"iss": iss})
		if !ok || got != want {
			t.Errorf("WebIdentityIssuer(%q) = (%q, %v), want (%q, true)", iss, got, ok, want)
		}
	}
}

func TestOIDCEndpointURL(t *testing.T) {
	tests := []struct{ providerURL, want string }{
		{"example.com", "https://example.com"},
		{"example.com/oidc", "https://example.com/oidc"},
		{"spire-oidc.spire.svc:8443", "https://spire-oidc.spire.svc:8443"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1:8080/oidc", "http://127.0.0.1:8080/oidc"},
	}
	for _, tt := range tests {
		t.Run(tt.providerURL, func(t *testing.T) {
			if got := OIDCEndpointURL(tt.providerURL); got != tt.want {
				t.Errorf("OIDCEndpointURL(%q) = %q, want %q", tt.providerURL, got, tt.want)
			}
			if got := IsInsecureOIDCProviderURL(tt.providerURL); got != strings.HasPrefix(tt.want, "http://") {
				t.Errorf("IsInsecureOIDCProviderURL(%q) = %v", tt.providerURL, got)
			}
		})
	}
}

// TestBuildOIDCProviderArnRoundTripsRelaxedURLs confirms the ARN encoding
// survives the two new Url shapes: an explicit port and a retained
// "http://" both contain characters ParseOIDCProviderArn splits on, so a
// naive split would truncate the provider Url or misread the account id.
func TestBuildOIDCProviderArnRoundTripsRelaxedURLs(t *testing.T) {
	for _, url := range []string{
		"example.com",
		"spire-oidc.spire.svc:8443",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:8080/oidc",
	} {
		t.Run(url, func(t *testing.T) {
			arn := BuildOIDCProviderArn(DefaultAccountID, url)
			got, err := ParseOIDCProviderArn(arn)
			if err != nil {
				t.Fatalf("ParseOIDCProviderArn(%q): %v", arn, err)
			}
			if got != url {
				t.Errorf("ParseOIDCProviderArn(%q) = %q, want %q", arn, got, url)
			}
		})
	}
}
