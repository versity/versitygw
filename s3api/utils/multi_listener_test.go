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

package utils

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestMultiListener(t *testing.T) {
	// Create multiple underlying listeners
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener 1: %v", err)
	}
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener 2: %v", err)
	}
	defer ln2.Close()

	// Create MultiListener
	ml := NewMultiListener(ln1, ln2)
	if ml == nil {
		t.Fatal("NewMultiListener returned nil")
	}
	defer ml.Close()

	// Test connections to both listeners
	addr1 := ln1.Addr().String()
	addr2 := ln2.Addr().String()

	// Connect to first listener
	go func() {
		conn, err := net.Dial("tcp", addr1)
		if err != nil {
			t.Errorf("Failed to dial first address: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello from ln1"))
	}()

	// Accept from MultiListener
	conn1, err := ml.Accept()
	if err != nil {
		t.Fatalf("Failed to accept from MultiListener: %v", err)
	}
	defer conn1.Close()

	buf := make([]byte, 100)
	n, _ := conn1.Read(buf)
	if string(buf[:n]) != "hello from ln1" {
		t.Errorf("Unexpected data from first connection: %s", string(buf[:n]))
	}

	// Connect to second listener
	go func() {
		conn, err := net.Dial("tcp", addr2)
		if err != nil {
			t.Errorf("Failed to dial second address: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello from ln2"))
	}()

	// Accept from MultiListener
	conn2, err := ml.Accept()
	if err != nil {
		t.Fatalf("Failed to accept second connection: %v", err)
	}
	defer conn2.Close()

	n, _ = conn2.Read(buf)
	if string(buf[:n]) != "hello from ln2" {
		t.Errorf("Unexpected data from second connection: %s", string(buf[:n]))
	}
}

func TestMultiListenerClose(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	ml := NewMultiListener(ln1)
	if ml == nil {
		t.Fatal("NewMultiListener returned nil")
	}

	// Start accepting in a goroutine
	acceptErrors := make(chan error, 1)
	go func() {
		_, err := ml.Accept()
		acceptErrors <- err
	}()

	// Give the accept goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// Close the MultiListener
	if err := ml.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// The accept should now return an error
	select {
	case err := <-acceptErrors:
		if err == nil {
			t.Error("Accept() should fail after Close()")
		}
	case <-time.After(2 * time.Second):
		t.Error("Accept() did not return after Close()")
	}

	// Try to accept after close - should fail immediately
	_, err = ml.Accept()
	if err == nil {
		t.Error("Accept() should fail after Close() on subsequent calls")
	}
}

func TestResolveHostnameAddrs(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantErr     bool
		checkResult func([]string) bool
	}{
		{
			name:    "IPv4 address",
			address: "127.0.0.1:8080",
			wantErr: false,
			checkResult: func(addrs []string) bool {
				return len(addrs) == 1 && addrs[0] == "127.0.0.1:8080"
			},
		},
		{
			name:    "IPv6 address",
			address: "[::1]:8080",
			wantErr: false,
			checkResult: func(addrs []string) bool {
				return len(addrs) == 1 && addrs[0] == "[::1]:8080"
			},
		},
		{
			name:    "localhost hostname",
			address: "localhost:8080",
			wantErr: false,
			checkResult: func(addrs []string) bool {
				// localhost should resolve to at least one address
				return len(addrs) >= 1
			},
		},
		{
			name:    "invalid address",
			address: "invalid-no-port",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs, err := resolveHostnameAddrs(tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveHostnameAddrs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkResult != nil {
				if !tt.checkResult(addrs) {
					t.Errorf("resolveHostnameAddrs() returned unexpected result: %v", addrs)
				}
			}
		})
	}
}

func TestResolveHostnameIPs(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantErr     bool
		checkResult func([]string) bool
	}{
		{
			name:    "IPv4 address",
			address: "127.0.0.1:8080",
			wantErr: false,
			checkResult: func(ips []string) bool {
				return len(ips) == 1 && ips[0] == "127.0.0.1"
			},
		},
		{
			name:    "IPv6 address",
			address: "[::1]:8080",
			wantErr: false,
			checkResult: func(ips []string) bool {
				return len(ips) == 1 && ips[0] == "::1"
			},
		},
		{
			name:    "localhost hostname",
			address: "localhost:8080",
			wantErr: false,
			checkResult: func(ips []string) bool {
				// localhost should resolve to at least one address
				// On most systems, it resolves to both 127.0.0.1 and ::1
				return len(ips) >= 1
			},
		},
		{
			name:    "empty host",
			address: ":8080",
			wantErr: false,
			checkResult: func(ips []string) bool {
				return len(ips) == 1 && ips[0] == ""
			},
		},
		{
			name:    "invalid address",
			address: "invalid-no-port",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ResolveHostnameIPs(tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveHostnameIPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkResult != nil {
				if !tt.checkResult(ips) {
					t.Errorf("ResolveHostnameIPs() returned unexpected result: %v", ips)
				}
			}
		})
	}
}

func TestNewMultiAddrListener(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{
			name:    "IPv4 loopback",
			address: "127.0.0.1:0",
			wantErr: false,
		},
		{
			name:    "IPv6 loopback",
			address: "[::1]:0",
			wantErr: false,
		},
		{
			name:    "localhost with port",
			address: "localhost:0",
			wantErr: false,
		},
		{
			name:    "invalid hostname",
			address: "this-hostname-should-not-exist-12345.invalid:8080",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := NewMultiAddrListener("tcp", tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMultiAddrListener() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if ln != nil {
				defer ln.Close()

				// Try to connect to verify listener is working
				addr := ln.Addr().String()
				go func() {
					conn, err := net.Dial("tcp", addr)
					if err != nil {
						return
					}
					conn.Close()
				}()

				// Accept connection with timeout
				type result struct {
					conn net.Conn
					err  error
				}
				ch := make(chan result, 1)
				go func() {
					conn, err := ln.Accept()
					ch <- result{conn, err}
				}()

				select {
				case res := <-ch:
					if res.err != nil {
						t.Errorf("Failed to accept connection: %v", res.err)
					}
					if res.conn != nil {
						res.conn.Close()
					}
				case <-time.After(2 * time.Second):
					t.Error("Timeout waiting for connection")
				}
			}
		})
	}
}

func TestNewMultiAddrTLSListener(t *testing.T) {
	// Create a simple test certificate
	getCertFunc := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := tls.X509KeyPair([]byte(testCert), []byte(testKey))
		return &cert, err
	}

	ln, err := NewMultiAddrTLSListener("tcp", "127.0.0.1:0", getCertFunc)
	if err != nil {
		t.Fatalf("NewMultiAddrTLSListener() error = %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Try to connect with TLS
	go func() {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		conn.Write([]byte("test"))
		conn.Close()
	}()

	// Accept connection
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Failed to accept TLS connection: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 100)
	_, err = io.ReadAtLeast(conn, buf, 4)
	if err != nil {
		t.Errorf("Failed to read from TLS connection: %v", err)
	}
}

// Test certificate and key for TLS tests
const testCert = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

const testKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`
