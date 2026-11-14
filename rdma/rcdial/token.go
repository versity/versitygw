// Package rcdial implements the hipobj-rc-v3 wire format and the
// RDMA CM dialer the gateway uses to reach a client's RC listener.
//
// The wire itself (see hipObject's src/rdma/everpure/v3-wire.h) is
// two single-line ASCII strings carried as HTTP headers:
//
//	x-amz-rc-rdma-token:  <ip-hex32>:<port-hex4>:<rkey-hex8>:<remoteAddr-hex16>:<length-hex16>
//	x-amz-rc-rdma-reply:  <httpStatus>:<bytesTransferred-hex16>
//
// This file holds the pure-Go encoding and decoding of both, shared
// by every build configuration; the transport lives in the
// build-tagged files.
package rcdial

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// tokenPrefix optionally precedes the token on the wire. hipObject
// does not emit it yet; the parser accepts both forms so a later
// library that adds it (upstream issue #61) needs no gateway change.
const tokenPrefix = "AMD:RC:3:"

// fieldWidths are the exact hex widths of the five token fields.
var fieldWidths = [5]int{32, 4, 8, 16, 16}

// Token is a parsed x-amz-rc-rdma-token.
type Token struct {
	// ListenIP is the client's RC-CM listener address. IPv4
	// listeners arrive IPv4-mapped (RFC 4291 2.5.5.2); ListenIP
	// holds the decoded 16-byte form either way.
	ListenIP [16]byte
	// ListenPort is the TCP port the listener is bound to.
	ListenPort uint16
	// RKey is the remote key of the transfer's memory region.
	RKey uint32
	// RemoteAddr is the region's base address (already offset into
	// the registration by the client).
	RemoteAddr uint64
	// Length is the transfer length in bytes.
	Length uint64
}

// ParseToken decodes an x-amz-rc-rdma-token value. It accepts an
// optional scheme prefix and requires the five fields at their exact
// widths in lowercase or uppercase hex; anything else is an error.
func ParseToken(s string) (Token, error) {
	var t Token
	s = strings.TrimPrefix(s, tokenPrefix)
	fields := strings.Split(s, ":")
	if len(fields) != len(fieldWidths) {
		return t, fmt.Errorf("rc-v3 token: want %d fields, got %d", len(fieldWidths), len(fields))
	}
	ip, err := decodeHexBytes(fields[0], fieldWidths[0], 16)
	if err != nil {
		return t, fmt.Errorf("rc-v3 token: listen ip: %w", err)
	}
	var allZero bool
	nonZero := false
	for _, b := range ip {
		if b != 0 {
			nonZero = true
			break
		}
	}
	allZero = !nonZero
	if allZero {
		return t, fmt.Errorf("rc-v3 token: listen ip is unspecified")
	}
	copy(t.ListenIP[:], ip)
	port, err := decodeHexUint(fields[1], fieldWidths[1], 16)
	if err != nil || port == 0 {
		return t, fmt.Errorf("rc-v3 token: listen port: %w", err)
	}
	t.ListenPort = uint16(port)
	rkey, err := decodeHexUint(fields[2], fieldWidths[2], 32)
	if err != nil {
		return t, fmt.Errorf("rc-v3 token: rkey: %w", err)
	}
	t.RKey = uint32(rkey)
	addr, err := decodeHexUint(fields[3], fieldWidths[3], 64)
	if err != nil {
		return t, fmt.Errorf("rc-v3 token: remote addr: %w", err)
	}
	t.RemoteAddr = addr
	length, err := decodeHexUint(fields[4], fieldWidths[4], 64)
	if err != nil || length == 0 {
		return t, fmt.Errorf("rc-v3 token: length: %w", err)
	}
	t.Length = length
	return t, nil
}

// FormatToken encodes a Token without the scheme prefix, the form
// hipObject emits today.
func FormatToken(t Token) string {
	return fmt.Sprintf("%032x:%04x:%08x:%016x:%016x",
		t.ListenIP, t.ListenPort, t.RKey, t.RemoteAddr, t.Length)
}

// Reply is a parsed x-amz-rc-rdma-reply.
type Reply struct {
	Status int
	Bytes  uint64
}

// FormatReply encodes an x-amz-rc-rdma-reply value.
func FormatReply(status int, bytes uint64) string {
	return fmt.Sprintf("%d:%016x", status, bytes)
}

// ParseReply decodes an x-amz-rc-rdma-reply value.
func ParseReply(s string) (Reply, error) {
	var r Reply
	fields := strings.Split(s, ":")
	if len(fields) != 2 {
		return r, fmt.Errorf("rc-v3 reply: want 2 fields, got %d", len(fields))
	}
	// The wire grammar is exactly three decimal digits: no sign,
	// no leading zeros, no longer forms.
	if len(fields[0]) != 3 || fields[0][0] < '1' || fields[0][0] > '9' {
		return r, fmt.Errorf("rc-v3 reply: status %q", fields[0])
	}
	status := int(fields[0][0]-'0')*100 + int(fields[0][1]-'0')*10 + int(fields[0][2]-'0')
	if status < 100 || status > 599 {
		return r, fmt.Errorf("rc-v3 reply: status: %d", status)
	}
	b, err := decodeHexUint(fields[1], fieldWidths[4], 64)
	if err != nil {
		return r, fmt.Errorf("rc-v3 reply: bytes: %w", err)
	}
	r.Status = status
	r.Bytes = b
	return r, nil
}

// ListenAddr renders the listener address as host:port for dialing.
func (t Token) ListenAddr() string {
	ip := net.IP(t.ListenIP[:])
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(t.ListenPort)))
}

// decodeHexUint parses exactly width hex digits into a uint64 with
// the given bit limit.
func decodeHexUint(s string, width, bits int) (uint64, error) {
	v, err := strconv.ParseUint(s, 16, bits)
	if err != nil {
		return 0, err
	}
	if len(s) != width {
		return 0, fmt.Errorf("width %d, got %d", width, len(s))
	}
	return v, nil
}

// decodeHexBytes parses exactly width hex digits into n bytes.
func decodeHexBytes(s string, width, n int) ([]byte, error) {
	if len(s) != width {
		return nil, fmt.Errorf("width %d, got %d", width, len(s))
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}
