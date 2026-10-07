// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
// This file is licensed under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

//go:build linux && amd64

package rcobj

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// connLost reports a broken control transport, not a local abort.
// Deadlines, TLS/HTTPS misconfiguration, and other local errors
// stay negative so admission evidence is not dropped for a failure
// that never reached the peer.
func connLost(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return false
		}
		return true
	}
	return false
}

// replyTokenPayload strips the status prefix the x-amz-rdma-reply
// header carries ("<three digits>:<token>" from the bridge and
// gateway). Only that shape yields a payload;
// a bare token without the prefix, a malformed prefix, or an empty
// suffix all return empty so the caller treats the header as
// absent rather than fabricating a token.
func replyTokenPayload(v string) string {
	if len(v) < 4 || v[3] != ':' {
		return ""
	}
	for i := 0; i < 3; i++ {
		if v[i] < '0' || v[i] > '9' {
			return ""
		}
	}
	return v[4:]
}

// checksumValid is the pure predicate for the wire checksum
// contract, so tests can pin it without cgo.
func checksumValid(v string) bool {
	const prefix = "CRC64NVME "
	if !strings.HasPrefix(v, prefix) {
		return false
	}
	payload := v[len(prefix):]
	if len(payload) != 12 || payload[11] != '=' {
		return false
	}
	for i := 0; i < 11; i++ {
		c := payload[i]
		isB64 := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/'
		if !isB64 {
			return false
		}
	}
	// The final data character carries two padding bits that must
	// be zero (the bridge rejects b64v(payload[10]) & 0x3), so a
	// syntactically valid string with set padding bits is not a
	// canonical encoding the gateway would have produced.
	return b64v(payload[10])&0x3 == 0
}

// b64v decodes one base64 character to its six-bit value.
func b64v(c byte) byte {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A'
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26
	case c >= '0' && c <= '9':
		return c - '0' + 52
	case c == '+':
		return 62
	default: // '/'
		return 63
	}
}
