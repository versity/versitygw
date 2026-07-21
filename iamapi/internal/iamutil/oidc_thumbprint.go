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
	"errors"
	"net"
	"strings"
	"time"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
)

const oidcThumbprintFetchTimeout = 8 * time.Second

// FetchThumbprint implements CreateOpenIDConnectProvider's auto-fetch
// behavior: it opens a raw TLS handshake (crypto/tls, not a full
// HTTP GET) to host:443, where host is derived from providerURL (a
// scheme-stripped OIDC provider Url), and returns the SHA-1 thumbprint of
// the last (top-most/intermediate CA) certificate in the peer's presented
// chain.
//
// SSRF hardening (mandatory): the hostname is resolved once via
// net.DefaultResolver.LookupIP; if any resolved address is
// loopback/private/link-local/unspecified/multicast (this range covers
// 169.254.169.254 and other cloud metadata endpoints), the fetch is
// rejected before any connection attempt. The TLS dial then targets one of
// the pre-validated IPs directly (never re-resolving the hostname at dial
// time, closing the DNS-rebinding TOCTOU gap) while presenting the original
// hostname via tls.Config.ServerName for SNI/certificate purposes.
//
// tls.Config.InsecureSkipVerify is deliberately set: this handshake exists
// solely to observe whatever certificate chain the peer presents — that is
// the entire point of AWS's thumbprint-pinning feature (trusting an
// operator-established fingerprint for IDPs whose certs may not pass
// standard verification). No application data is sent or received over
// this connection, so skipping chain verification does not expose any real
// traffic to a MITM.
func FetchThumbprint(ctx context.Context, providerURL string) (string, error) {
	host := hostFromOIDCUrl(providerURL)
	displayURL := "https://" + providerURL

	ctx, cancel := context.WithTimeout(ctx, oidcThumbprintFetchTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		debuglogger.Logf("oidc thumbprint fetch: dns lookup failed for %q: %v", host, err)
		return "", iamerr.OpenIdIdpCommunicationError(displayURL)
	}
	for _, ip := range ips {
		if isDisallowedFetchTarget(ip) {
			debuglogger.Logf("oidc thumbprint fetch: refusing to dial disallowed address %q for host %q", ip, host)
			return "", iamerr.OpenIdIdpCommunicationError(displayURL)
		}
	}

	dialer := &tls.Dialer{Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), "443"))
	if err != nil {
		debuglogger.Logf("oidc thumbprint fetch: tls dial failed for %q (%s): %v", host, ips[0], err)
		return "", iamerr.OpenIdIdpCommunicationError(displayURL)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", iamerr.OpenIdIdpCommunicationError(displayURL)
	}

	thumbprint, err := ThumbprintFromChain(tlsConn.ConnectionState().PeerCertificates)
	if err != nil {
		debuglogger.Logf("oidc thumbprint fetch: %v", err)
		return "", iamerr.OpenIdIdpCommunicationError(displayURL)
	}
	return thumbprint, nil
}

// ThumbprintFromChain computes AWS's documented OIDC thumbprint: the SHA-1
// hash of the DER bytes of the last (top-most/intermediate CA) certificate
// in chain, hex-encoded and lowercased. Split out from FetchThumbprint as a
// pure function specifically so it is unit-testable (e.g. against a chain
// obtained from httptest.NewTLSServer) without going through
// FetchThumbprint's SSRF guard, which must always reject loopback targets
// and therefore can never itself be exercised against a same-process test
// server.
func ThumbprintFromChain(chain []*x509.Certificate) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("iamutil: empty certificate chain")
	}
	top := chain[len(chain)-1]
	sum := sha1.Sum(top.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func isDisallowedFetchTarget(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// hostFromOIDCUrl extracts the host (no scheme, no path — OIDC provider
// URLs are validated to disallow explicit ports) from a scheme-stripped
// provider Url.
func hostFromOIDCUrl(providerURL string) string {
	if before, _, ok := strings.Cut(providerURL, "/"); ok {
		return before
	}
	return providerURL
}
