// Copyright 2026 Versity Software
// Copyright 2026 Gluesys and Jihyeon Gim
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
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestReplyTokenPayload(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"200:" + strings.Repeat("ab", 44), strings.Repeat("ab", 44)},
		{"204:tok", "tok"},
		{"garbage:tok", ""},
		{":tok", ""},
		{"2000:tok", ""},
		{"200:", ""},
		{"200", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := replyTokenPayload(c.in); got != c.want {
			t.Errorf("replyTokenPayload(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestConnLost(t *testing.T) {
	if connLost(nil) {
		t.Error("nil error classified as lost")
	}
	if connLost(context.DeadlineExceeded) {
		t.Error("context deadline classified as lost")
	}
	if connLost(os.ErrDeadlineExceeded) {
		t.Error("os deadline classified as lost")
	}
	if connLost(errors.New("http: server gave HTTP response to HTTPS client")) {
		t.Error("HTTPS scheme mismatch classified as lost")
	}
	if connLost(fmt.Errorf("unsupported protocol scheme")) {
		t.Error("unsupported scheme classified as lost")
	}
	for _, e := range []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		&net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE},
		&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
	} {
		if !connLost(e) {
			t.Errorf("%v classified as not lost", e)
		}
	}
}

func TestConnLostChains(t *testing.T) {
	wrapped := fmt.Errorf("dial: %w", context.DeadlineExceeded)
	if connLost(wrapped) {
		t.Error("wrapped deadline classified as lost")
	}
	opErr := &net.OpError{Op: "read", Net: "tcp",
		Err: syscall.ECONNRESET}
	if !connLost(opErr) {
		t.Error("net.OpError reset classified as not lost")
	}
	if !connLost(io.EOF) {
		t.Error("io.EOF classified as not lost")
	}
	if !connLost(io.ErrUnexpectedEOF) {
		t.Error("unexpected EOF classified as not lost")
	}
}

func TestChecksumValid(t *testing.T) {
	valid := []string{
		"CRC64NVME AQIDBAUGBwg=",
		"CRC64NVME AAAAAAAAAAA=",
		"CRC64NVME AAAAAAAAAAE=",
	}
	for _, v := range valid {
		if !checksumValid(v) {
			t.Errorf("checksumValid(%q) rejected", v)
		}
	}
	bad := []string{
		"CRC64NVME AAAAAAAAAAB=",
		"CRC64NVME ============",
		"CRC64NVME AQIDBAUGBwg",
		"CRC64NVMEAQIDBAUGBwg=",
		"crc64nvme AQIDBAUGBwg=",
		"CRC64NVME AQIDBAUGBw==",
		"CRC64NVME AQIDBAUGBwg=extra",
		"CRC64NVME AQ=DAUGBwg=",
		"",
	}
	for _, b := range bad {
		if checksumValid(b) {
			t.Errorf("checksumValid(%q) accepted", b)
		}
	}
}
