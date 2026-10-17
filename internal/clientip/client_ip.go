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

// Package clientip resolves the client address recorded in the request logs
// and access logs. It lives here rather than in s3api/utils so the standalone
// IAM and WebUI servers can use it without importing the S3 side.
package clientip

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/httpctx"
)

// Proxy headers the client address can be read from when the operator opts in
// with the client-ip-header option.
const (
	ClientIPHeaderForwardedFor = "X-Forwarded-For"
	ClientIPHeaderRealIP       = "X-Real-Ip"
)

// trustUnixEntry is the trusted-proxies entry that trusts the peer of a
// listener bound to a unix socket path.
const trustUnixEntry = "unix"

// TrustedProxies is the set of peers whose forwarding headers are honoured.
type TrustedProxies struct {
	// Prefixes holds the trusted IP addresses and CIDR prefixes.
	Prefixes []netip.Prefix
	// Unix trusts a peer that connected over a unix domain socket. fasthttp
	// reports such a peer as 0.0.0.0, which only a prefix covering 0.0.0.0
	// (0.0.0.0/32, 0.0.0.0/0) matches, so without this entry a proxy on a
	// unix socket listener is not trusted.
	Unix bool
}

// IsEmpty reports whether no peer is trusted.
func (t TrustedProxies) IsEmpty() bool {
	return len(t.Prefixes) == 0 && !t.Unix
}

// NormalizeClientIPHeader validates a configured client IP header and returns
// its canonical spelling. An empty value means the option is disabled.
func NormalizeClientIPHeader(header string) (string, error) {
	trimmed := strings.TrimSpace(header)
	switch {
	case trimmed == "":
		return "", nil
	case strings.EqualFold(trimmed, ClientIPHeaderForwardedFor):
		return ClientIPHeaderForwardedFor, nil
	case strings.EqualFold(trimmed, ClientIPHeaderRealIP):
		return ClientIPHeaderRealIP, nil
	default:
		return "", fmt.Errorf("invalid client IP header %q: must be %q or %q",
			header, ClientIPHeaderForwardedFor, ClientIPHeaderRealIP)
	}
}

// ParseTrustedProxies parses a comma-separated list of IP addresses, CIDR
// prefixes and the literal "unix" into the set of peers whose forwarding
// headers are trusted. The "unix" entry trusts a peer connected over a unix
// domain socket; an empty list yields an empty set.
func ParseTrustedProxies(list string) (TrustedProxies, error) {
	var trusted TrustedProxies
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, trustUnixEntry) {
			trusted.Unix = true
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			trusted.Prefixes = append(trusted.Prefixes, normalizePrefix(prefix))
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q: must be an IP address, a CIDR prefix, or %q", entry, trustUnixEntry)
		}
		addr = addr.Unmap()
		trusted.Prefixes = append(trusted.Prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return trusted, nil
}

// normalizePrefix unmaps an IPv4-mapped IPv6 prefix so it matches the unmapped
// addresses the trusted set compares.
func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	if addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix
}

// ClientIP returns the address to record for a request. The client IP
// middleware stores the address resolved from the configured proxy header;
// without it this is the socket peer address from ctx.IP().
func ClientIP(ctx fiber.Ctx) string {
	if ip, ok := httpctx.ContextKeyClientIP.Get(ctx).(string); ok && ip != "" {
		return ip
	}
	return ctx.IP()
}

// ClientIPFromHeader resolves the client address from header. The header is
// only honoured when the connection peer is one of the configured trusted
// proxies; from any other peer it is ignored and the socket peer address is
// returned, so a client cannot choose the address that gets logged.
//
// X-Forwarded-For is a comma-separated chain, oldest hop first. It is walked
// right to left, skipping the trusted proxies that appended to it; the first
// address that is not a trusted proxy is the client. A proxy may also add its
// own header line instead of appending to the existing one, so every line is
// walked, last line first. Some proxies write "ip:port" entries, which are
// accepted too. X-Real-Ip carries a single address; when a proxy adds a line
// rather than replacing the client's, the last line is the proxy's, so the
// last line is the one read.
//
// When every hop is a trusted proxy — a deployment whose trusted-proxies is
// the ingress pod CIDR, say — the leftmost hop is returned, as nginx's
// real_ip_recursive does. The socket peer would otherwise be the nearest
// proxy, which is never the client. It is no less safe than stopping at an
// untrusted hop: a trusted peer can already choose the logged address by
// putting any untrusted address on the left.
//
// Any unusable entry falls back to the socket peer address rather than
// returning a value from further up the chain.
func ClientIPFromHeader(ctx fiber.Ctx, header string, trusted TrustedProxies) string {
	peer := ctx.IP()
	if !trusted.matchesPeer(ctx, peer) {
		return peer
	}

	if header == ClientIPHeaderRealIP {
		// a proxy that adds its own line rather than replacing the client's
		// leaves the client's line first, so take the last one
		lines := ctx.Request().Header.PeekAll(header)
		if len(lines) == 0 {
			return peer
		}
		if addr, ok := parseAddr(string(lines[len(lines)-1])); ok {
			return addr.String()
		}
		return peer
	}

	lines := ctx.Request().Header.PeekAll(header)
	var leftmost netip.Addr
	haveLeftmost := false
	for i := len(lines) - 1; i >= 0; i-- {
		hops := strings.Split(string(lines[i]), ",")
		for j := len(hops) - 1; j >= 0; j-- {
			addr, ok := parseAddr(strings.TrimSpace(hops[j]))
			if !ok {
				return peer
			}
			if trusted.contains(addr) {
				leftmost, haveLeftmost = addr, true
				continue
			}
			return addr.String()
		}
	}
	if haveLeftmost {
		return leftmost.String()
	}
	return peer
}

// matchesPeer reports whether the connection peer may speak for the client.
func (t TrustedProxies) matchesPeer(ctx fiber.Ctx, peer string) bool {
	if t.Unix {
		if _, ok := ctx.RequestCtx().RemoteAddr().(*net.UnixAddr); ok {
			return true
		}
	}
	if addr, ok := parseAddr(peer); ok {
		return t.contains(addr)
	}
	return false
}

// contains reports whether addr is covered by one of the trusted prefixes.
func (t TrustedProxies) contains(addr netip.Addr) bool {
	for _, prefix := range t.Prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// parseAddr parses an address, accepting the "ip:port" form some proxies write
// in a forwarding header, and returns it unmapped from IPv4-in-IPv6 form so
// every spelling of one client compares equal. An address with an IPv6 zone is
// rejected: the zone is free text and would be written to the logs verbatim.
func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		addrPort, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, false
		}
		addr = addrPort.Addr()
	}
	if addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
