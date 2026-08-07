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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func signTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return signed
}

func testJWKSet(t *testing.T, key *rsa.PrivateKey, kid string) *jwkSet {
	t.Helper()
	return &jwkSet{Keys: []jwk{{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
}

func TestParseWebIdentityClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	valid := signTestToken(t, key, "k1", jwt.MapClaims{"iss": "https://example.com", "sub": "user1"})

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "valid shape", token: valid},
		{name: "not a jwt", token: "not-a-jwt", wantErr: true},
		{name: "empty", token: "", wantErr: true},
		{name: "two segments", token: "aaaa.bbbb", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ParseWebIdentityClaims(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got claims %#v", claims)
				}
				var apiErr iamerr.Error
				if !errors.As(err, &apiErr) || apiErr.Code != "InvalidIdentityToken" {
					t.Fatalf("expected InvalidIdentityToken, got %#v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if claims["iss"] != "https://example.com" {
				t.Fatalf("unexpected claims: %#v", claims)
			}
		})
	}
}

func TestWebIdentityIssuer(t *testing.T) {
	tests := []struct {
		claims jwt.MapClaims
		want   string
		wantOk bool
	}{
		{claims: jwt.MapClaims{"iss": "https://example.com/path"}, want: "example.com/path", wantOk: true},
		// Not https: left unstripped so it can never coincidentally equal a
		// registered (always-https) provider's stored Url.
		{claims: jwt.MapClaims{"iss": "http://example.com"}, want: "http://example.com", wantOk: true},
		{claims: jwt.MapClaims{}, wantOk: false},
		{claims: jwt.MapClaims{"iss": ""}, wantOk: false},
		{claims: jwt.MapClaims{"iss": 123}, wantOk: false},
	}
	for _, tt := range tests {
		got, ok := WebIdentityIssuer(tt.claims)
		if ok != tt.wantOk || (ok && got != tt.want) {
			t.Errorf("WebIdentityIssuer(%#v) = (%q, %v), want (%q, %v)", tt.claims, got, ok, tt.want, tt.wantOk)
		}
	}
}

func TestWebIdentityAudience(t *testing.T) {
	tests := []struct {
		name         string
		claims       jwt.MapClaims
		want         string
		wantOriginal []string
		wantErr      bool
	}{
		{name: "single string aud", claims: jwt.MapClaims{"aud": "client1"}, want: "client1"},
		{name: "single-element array", claims: jwt.MapClaims{"aud": []any{"client1"}}, want: "client1"},
		{name: "no aud", claims: jwt.MapClaims{}, wantErr: true},
		{name: "empty aud", claims: jwt.MapClaims{"aud": ""}, wantErr: true},
		{
			name:         "multi aud with matching azp",
			claims:       jwt.MapClaims{"aud": []any{"other", "client1"}, "azp": "client1"},
			want:         "client1",
			wantOriginal: []string{"other", "client1"},
		},
		{
			name:    "multi aud without azp",
			claims:  jwt.MapClaims{"aud": []any{"other", "client1"}},
			wantErr: true,
		},
		{
			name: "single aud with azp: azp still wins, original aud exposed",
			claims: jwt.MapClaims{
				"aud": "backend-project", "azp": "oauth-client-1",
			},
			want:         "oauth-client-1",
			wantOriginal: []string{"backend-project"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, original, err := WebIdentityAudience(tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if !slices.Equal(original, tt.wantOriginal) {
				t.Fatalf("original = %v, want %v", original, tt.wantOriginal)
			}
		})
	}
}

func TestWebIdentityAudienceMultipleWithoutAzpMessage(t *testing.T) {
	_, _, err := WebIdentityAudience(jwt.MapClaims{"aud": []any{"a", "b"}})
	var apiErr iamerr.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected iamerr.Error, got %#v", err)
	}
	if apiErr.Message != "Token audience contains more than one audience while authorized party is not present" {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
}

func TestVerifyWebIdentityExpiration(t *testing.T) {
	now := time.Unix(1_000_000, 0)

	tests := []struct {
		name    string
		exp     float64
		wantErr bool
	}{
		{name: "not yet expired", exp: float64(now.Unix() + 10)},
		{name: "within leeway", exp: float64(now.Unix() - 200)},
		{name: "expired beyond leeway", exp: float64(now.Unix() - 400), wantErr: true},
		{name: "missing exp", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tt.name != "missing exp" {
				claims["exp"] = tt.exp
			}
			err := VerifyWebIdentityExpiration(claims, now)
			if tt.wantErr != (err != nil) {
				t.Fatalf("VerifyWebIdentityExpiration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyWebIdentityRequiredClaims(t *testing.T) {
	now := time.Unix(1_000_000, 0)

	tests := []struct {
		name    string
		claims  jwt.MapClaims
		wantErr bool
	}{
		{name: "iat and sub present", claims: jwt.MapClaims{"iat": float64(now.Unix()), "sub": "user1"}},
		{name: "missing iat", claims: jwt.MapClaims{"sub": "user1"}, wantErr: true},
		{name: "missing sub", claims: jwt.MapClaims{"iat": float64(now.Unix())}, wantErr: true},
		{name: "empty sub", claims: jwt.MapClaims{"iat": float64(now.Unix()), "sub": ""}, wantErr: true},
		{
			name:   "nbf in the past is fine",
			claims: jwt.MapClaims{"iat": float64(now.Unix()), "sub": "user1", "nbf": float64(now.Unix() - 10)},
		},
		{
			name:   "nbf within leeway is fine",
			claims: jwt.MapClaims{"iat": float64(now.Unix()), "sub": "user1", "nbf": float64(now.Unix() + 200)},
		},
		{
			name:    "nbf beyond leeway is not yet valid",
			claims:  jwt.MapClaims{"iat": float64(now.Unix()), "sub": "user1", "nbf": float64(now.Unix() + 400)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyWebIdentityRequiredClaims(tt.claims, now)
			if tt.wantErr != (err != nil) {
				t.Fatalf("VerifyWebIdentityRequiredClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOIDCConnection(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates

	thumbprint, err := ThumbprintFromChain(chain)
	if err != nil {
		t.Fatalf("ThumbprintFromChain: %v", err)
	}

	t.Run("matching pinned thumbprint bypasses CA trust but still requires a valid chain for the host", func(t *testing.T) {
		// The httptest cert's SANs include "example.com" (see
		// net/http/internal/testcert), and it is self-signed, so it forms a
		// valid one-certificate chain rooted at itself for that name.
		cs := tls.ConnectionState{PeerCertificates: chain, ServerName: "example.com"}
		if err := verifyOIDCConnection(cs, []string{thumbprint}); err != nil {
			t.Fatalf("expected pinned thumbprint to be accepted for a matching hostname: %v", err)
		}
	})

	t.Run("matching pinned thumbprint does not bypass hostname verification", func(t *testing.T) {
		cs := tls.ConnectionState{PeerCertificates: chain, ServerName: "totally-different-host.example"}
		if err := verifyOIDCConnection(cs, []string{thumbprint}); err == nil {
			t.Fatal("expected pinned thumbprint to still be rejected for a non-matching hostname")
		}
	})

	t.Run("pinned thumbprint match does not bypass chain validation for an appended unrelated leaf", func(t *testing.T) {
		// An attacker-controlled leaf (self-signed by a key the pinned CA
		// never touched) followed by the real pinned certificate must not
		// validate: thumbprint equality alone must not grant trust when the
		// pinned certificate never actually issued this leaf.
		unrelatedLeaf := generateSelfSignedCert(t, "example.com")

		forged := append([]*x509.Certificate{unrelatedLeaf}, chain...)
		cs := tls.ConnectionState{PeerCertificates: forged, ServerName: "example.com"}
		if err := verifyOIDCConnection(cs, []string{thumbprint}); err == nil {
			t.Fatal("expected forged chain (unrelated leaf + appended pinned cert) to be rejected")
		}
	})

	t.Run("non-matching thumbprint falls back to standard verification and fails", func(t *testing.T) {
		cs := tls.ConnectionState{PeerCertificates: chain, ServerName: "example.com"}
		if err := verifyOIDCConnection(cs, []string{"0000000000000000000000000000000000000000"}); err == nil {
			t.Fatal("expected standard verification to fail for a self-signed cert not in the system pool")
		}
	})

	t.Run("no thumbprints falls back to standard verification and fails", func(t *testing.T) {
		cs := tls.ConnectionState{PeerCertificates: chain, ServerName: "example.com"}
		if err := verifyOIDCConnection(cs, nil); err == nil {
			t.Fatal("expected standard verification to fail for a self-signed cert not in the system pool")
		}
	})

	t.Run("no certificates presented", func(t *testing.T) {
		if err := verifyOIDCConnection(tls.ConnectionState{}, nil); err == nil {
			t.Fatal("expected error when no certificate is presented")
		}
	})
}

func TestVerifySignatureWithKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	keys := testJWKSet(t, key, "k1")

	t.Run("valid signature", func(t *testing.T) {
		token := signTestToken(t, key, "k1", jwt.MapClaims{"iss": "https://example.com", "sub": "u1"})
		claims, err := verifySignatureWithKeys(token, keys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims["sub"] != "u1" {
			t.Fatalf("unexpected claims: %#v", claims)
		}
	})

	t.Run("wrong signing key", func(t *testing.T) {
		token := signTestToken(t, otherKey, "k1", jwt.MapClaims{"iss": "https://example.com"})
		if _, err := verifySignatureWithKeys(token, keys); err == nil {
			t.Fatal("expected signature verification failure")
		}
	})

	t.Run("no kid in token, single key set still matches", func(t *testing.T) {
		token := signTestToken(t, key, "", jwt.MapClaims{"iss": "https://example.com"})
		if _, err := verifySignatureWithKeys(token, keys); err != nil {
			t.Fatalf("single-key JWKS should match a token with no kid: %v", err)
		}
	})

	t.Run("mismatched kid against single key set fails", func(t *testing.T) {
		token := signTestToken(t, key, "unknown-kid", jwt.MapClaims{"iss": "https://example.com"})
		if _, err := verifySignatureWithKeys(token, keys); err == nil {
			t.Fatal("a kid that doesn't match the single known key should not be accepted")
		}
	})

	t.Run("multi-key set reports errUnknownKID for an unrecognized kid", func(t *testing.T) {
		multiKeySet := testJWKSet(t, key, "k1")
		multiKeySet.Keys = append(multiKeySet.Keys, testJWKSet(t, otherKey, "k2").Keys[0])

		token := signTestToken(t, key, "unknown-kid", jwt.MapClaims{"iss": "https://example.com"})
		_, err := verifySignatureWithKeys(token, multiKeySet)
		if !errors.Is(err, errUnknownKID) {
			t.Fatalf("expected errUnknownKID, got %v", err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		token := signTestToken(t, key, "k1", jwt.MapClaims{"iss": "https://example.com"})
		tampered := token[:len(token)-4] + "AAAA"
		if _, err := verifySignatureWithKeys(tampered, keys); err == nil {
			t.Fatal("expected tampered token to fail verification")
		}
	})
}

func TestRoleNameFromAssumeArn(t *testing.T) {
	const account = "000000000000"

	tests := []struct {
		name      string
		arn       string
		wantName  string
		wantFound bool
	}{
		{name: "simple", arn: "arn:aws:iam::000000000000:role/my-role", wantName: "my-role", wantFound: true},
		{name: "with path", arn: "arn:aws:iam::000000000000:role/path/to/my-role", wantName: "my-role", wantFound: true},
		{name: "wrong account", arn: "arn:aws:iam::111111111111:role/my-role", wantFound: false},
		{name: "wrong resource type", arn: "arn:aws:iam::000000000000:user/my-user", wantFound: false},
		{name: "not an arn", arn: "not-an-arn", wantFound: false},
		{name: "empty resource", arn: "arn:aws:iam::000000000000:role/", wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := RoleNameFromAssumeArn(tt.arn, account)
			if ok != tt.wantFound || (ok && got != tt.wantName) {
				t.Errorf("RoleNameFromAssumeArn(%q) = (%q, %v), want (%q, %v)", tt.arn, got, ok, tt.wantName, tt.wantFound)
			}
		})
	}
}

func TestValidateRoleSessionName(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: "my-session_1.2@3"},
		{name: "too short", value: "a", wantErr: true},
		{name: "too long", value: string(make([]byte, 65)), wantErr: true},
		{name: "invalid chars", value: "bad session!!", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRoleSessionName(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRoleSessionName(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestExtractClaimContext(t *testing.T) {
	claims := jwt.MapClaims{
		"iss":    "https://example.com",
		"aud":    "client1",
		"sub":    "user1",
		"exp":    float64(1000),
		"amr":    []any{"pwd", "mfa"},
		"groups": "admins",
		// golang-jwt decodes every JSON number as float64 and every JSON
		// bool as bool - without claimScalarString handling both, a Bool or
		// Numeric trust-policy Condition against a custom claim like these
		// would silently never match, since the claim would never reach
		// the output map at all (the key would always look "absent").
		"tier":   float64(3),
		"admin":  true,
		"scores": []any{float64(1), "x", true},
	}
	got := ExtractClaimContext(claims)

	if _, ok := got["iss"]; ok {
		t.Errorf("well-known claim iss should be excluded, got %#v", got)
	}
	if got["groups"][0] != "admins" {
		t.Errorf("unexpected groups value: %#v", got["groups"])
	}
	if len(got["amr"]) != 2 || got["amr"][0] != "pwd" || got["amr"][1] != "mfa" {
		t.Errorf("unexpected amr value: %#v", got["amr"])
	}
	if len(got["tier"]) != 1 || got["tier"][0] != "3" {
		t.Errorf("unexpected tier value: %#v", got["tier"])
	}
	if len(got["admin"]) != 1 || got["admin"][0] != "true" {
		t.Errorf("unexpected admin value: %#v", got["admin"])
	}
	if len(got["scores"]) != 3 || got["scores"][0] != "1" || got["scores"][1] != "x" || got["scores"][2] != "true" {
		t.Errorf("unexpected scores value: %#v", got["scores"])
	}
}

func TestBuildAssumedRoleArn(t *testing.T) {
	got := BuildAssumedRoleArn("000000000000", "my-role", "my-session")
	want := "arn:aws:sts::000000000000:assumed-role/my-role/my-session"
	if got != want {
		t.Errorf("BuildAssumedRoleArn() = %q, want %q", got, want)
	}
}

// generateSelfSignedCert returns a freshly generated, self-signed
// certificate for dnsName, signed by a key unrelated to any other
// certificate in the test — used to simulate an attacker-controlled leaf
// that a real pinned CA never issued.
func generateSelfSignedCert(t *testing.T, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestValidateDiscoveryIssuer(t *testing.T) {
	tests := []struct {
		name      string
		doc       oidcDiscoveryDoc
		issuerURL string
		wantErr   bool
	}{
		{name: "matching issuer", doc: oidcDiscoveryDoc{Issuer: "https://example.com"}, issuerURL: "example.com", wantErr: false},
		{name: "mismatched issuer", doc: oidcDiscoveryDoc{Issuer: "https://attacker.example"}, issuerURL: "example.com", wantErr: true},
		{name: "missing issuer", doc: oidcDiscoveryDoc{Issuer: ""}, issuerURL: "example.com", wantErr: true},
		{name: "issuer with different path is not an exact match", doc: oidcDiscoveryDoc{Issuer: "https://example.com/tenant"}, issuerURL: "example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiscoveryIssuer(tt.doc, tt.issuerURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDiscoveryIssuer(%+v, %q) error = %v, wantErr %v", tt.doc, tt.issuerURL, err, tt.wantErr)
			}
		})
	}
}

func TestJWKSCacheKeyBindsThumbprints(t *testing.T) {
	base := jwksCacheKey("example.com", []string{"aaaa"})

	if got := jwksCacheKey("example.com", []string{"bbbb"}); got == base {
		t.Errorf("jwksCacheKey did not change when thumbprint changed: %q", got)
	}
	if got := jwksCacheKey("example.com", nil); got == base {
		t.Errorf("jwksCacheKey did not change when thumbprint was removed: %q", got)
	}
	if got := jwksCacheKey("other.example.com", []string{"aaaa"}); got == base {
		t.Errorf("jwksCacheKey did not change when issuer changed: %q", got)
	}
	// Storage doesn't guarantee ThumbprintList order is stable across reads
	// of an unchanged provider, so the key must not depend on input order.
	if got := jwksCacheKey("example.com", []string{"bbbb", "aaaa"}); got != jwksCacheKey("example.com", []string{"aaaa", "bbbb"}) {
		t.Errorf("jwksCacheKey is sensitive to thumbprint order: %q", got)
	}
}

func TestForceRefreshJWKSCacheGatesFailedAttempts(t *testing.T) {
	issuer := "localhost"
	key := jwksCacheKey(issuer, nil)
	jwksCacheMu.Lock()
	delete(jwksCache, key)
	jwksCacheMu.Unlock()
	t.Cleanup(func() {
		jwksCacheMu.Lock()
		delete(jwksCache, key)
		jwksCacheMu.Unlock()
	})

	ctx := context.Background()

	if _, err := forceRefreshJWKSCache(ctx, issuer, nil); err == nil {
		t.Fatal("forceRefreshJWKSCache() = nil error, want an error for a disallowed loopback target")
	}

	jwksCacheMu.Lock()
	entry, ok := jwksCache[key]
	jwksCacheMu.Unlock()
	if !ok || entry.lastForcedRefresh.IsZero() {
		t.Fatal("forceRefreshJWKSCache did not record lastForcedRefresh for a failed attempt")
	}
	before := entry.lastForcedRefresh

	// A second forced refresh within jwksMinForcedRefreshInterval must be
	// gated - failing immediately with no cached keys to fall back on -
	// rather than attempting another fetch.
	if _, err := forceRefreshJWKSCache(ctx, issuer, nil); err == nil {
		t.Fatal("forceRefreshJWKSCache() = nil error on gated retry, want an error (no cached keys available)")
	}
	jwksCacheMu.Lock()
	after := jwksCache[key].lastForcedRefresh
	jwksCacheMu.Unlock()
	if !after.Equal(before) {
		t.Errorf("forceRefreshJWKSCache re-attempted a fetch within jwksMinForcedRefreshInterval: lastForcedRefresh changed from %v to %v", before, after)
	}
}
