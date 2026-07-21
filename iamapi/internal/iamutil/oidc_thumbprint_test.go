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
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"testing"
)

// TestThumbprintFromChain exercises the pure cert-chain-hashing logic
// (AWS's OIDC thumbprint is the SHA-1 hash of the DER bytes of the
// last/top-most certificate in the peer's presented chain, hex encoded and
// lowercased) against a real TLS handshake with a locally generated
// self-signed certificate.
//
// This deliberately dials httptest.NewTLSServer directly with tls.Dial
// rather than going through FetchThumbprint, whose SSRF guard must always
// reject loopback targets — exactly what a local test server is.
func TestThumbprintFromChain(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		t.Fatal("expected at least one peer certificate")
	}

	got, err := ThumbprintFromChain(chain)
	if err != nil {
		t.Fatalf("ThumbprintFromChain: %v", err)
	}

	sum := sha1.Sum(chain[len(chain)-1].Raw)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("ThumbprintFromChain = %q, want %q", got, want)
	}
	if len(got) != OIDCThumbprintLen {
		t.Fatalf("thumbprint length = %d, want %d", len(got), OIDCThumbprintLen)
	}
}

func TestThumbprintFromChainEmptyChain(t *testing.T) {
	if _, err := ThumbprintFromChain(nil); err == nil {
		t.Fatal("expected error for empty certificate chain")
	}
}

// TestFetchThumbprintSSRFGuard confirms FetchThumbprint refuses to dial
// loopback/private targets before any network attempt, matching the
// mandatory SSRF hardening design: 127.0.0.1 is exactly the kind of
// address a malicious CreateOpenIDConnectProvider caller could supply to
// probe the gateway's own local network.
func TestFetchThumbprintSSRFGuard(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"169.254.169.254", // cloud metadata endpoint
		"::1",
	}
	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			_, err := FetchThumbprint(context.Background(), host)
			if err == nil {
				t.Fatalf("FetchThumbprint(%q): expected SSRF guard error, got nil", host)
			}
		})
	}
}

func TestFetchThumbprintDNSFailure(t *testing.T) {
	_, err := FetchThumbprint(context.Background(), "this-host-should-not-resolve.invalid")
	if err == nil {
		t.Fatal("expected error for unresolvable host")
	}
}

func TestIsDisallowedFetchTarget(t *testing.T) {
	tests := []struct {
		ip         string
		disallowed bool
	}{
		{"127.0.0.1", true},
		{"169.254.169.254", true},
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid test IP %q", tt.ip)
		}
		if got := isDisallowedFetchTarget(ip); got != tt.disallowed {
			t.Errorf("isDisallowedFetchTarget(%q) = %v, want %v", tt.ip, got, tt.disallowed)
		}
	}
}
