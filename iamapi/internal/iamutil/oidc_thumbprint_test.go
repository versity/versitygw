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
	"crypto/x509"
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

// TestDialAndVerifyThumbprintRejectsUntrustedCert verifies that
// dialAndVerifyThumbprint rejects a certificate that doesn't chain to a
// trusted root, rather than trusting whatever the peer presents — trusting
// any presented chain is exactly what would let an active network/DNS
// attacker at enrollment time have their own chain pinned as the provider's
// permanent trust anchor. A self-signed test server's certificate, which
// chains to nothing any real trust store recognizes, must be rejected
// instead of silently hashed.
func TestDialAndVerifyThumbprintRejectsUntrustedCert(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	// roots=nil selects the host system's real trust store, the same as
	// FetchThumbprint's actual usage - httptest's self-signed certificate
	// must not verify against it.
	if _, err := dialAndVerifyThumbprint(context.Background(), srv.Listener.Addr().String(), "example.com", nil); err == nil {
		t.Fatal("dialAndVerifyThumbprint: expected verification error for untrusted self-signed certificate, got nil")
	}
}

// TestDialAndVerifyThumbprintAcceptsVerifiedCert is the positive
// counterpart: once the peer's certificate does verify (here, against an
// explicit pool containing the test server's own certificate, standing in
// for a real public CA in FetchThumbprint's system-trust-store case),
// auto-fetch must still succeed and compute the same thumbprint
// TestThumbprintFromChain gets by hashing the chain directly - proving the
// stricter check rejects only genuinely untrusted chains, not every chain.
func TestDialAndVerifyThumbprintAcceptsVerifiedCert(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	got, err := dialAndVerifyThumbprint(context.Background(), srv.Listener.Addr().String(), "example.com", roots)
	if err != nil {
		t.Fatalf("dialAndVerifyThumbprint: %v", err)
	}

	sum := sha1.Sum(srv.Certificate().Raw)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("dialAndVerifyThumbprint thumbprint = %q, want %q", got, want)
	}
}

// TestFetchThumbprintSSRFGuard confirms FetchThumbprint refuses to dial
// loopback/private targets before any network attempt: 127.0.0.1 is exactly
// the kind of address a malicious CreateOpenIDConnectProvider caller could
// supply to probe the gateway's own local network.
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
