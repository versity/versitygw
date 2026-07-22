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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// newTestCertificate returns an in-memory self-signed certificate usable by the
// TLS listener under test.
func newTestCertificate(t *testing.T) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLSAccept accepts connections from ln and drives a single read on each so
// that the TLS handshake (and any plaintext-HTTP detection) is triggered, exactly
// like a real HTTP server would. Accepted request bytes are echoed back so the
// no-regression test can observe a successful round trip.
func serveTLSAccept(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 512)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			_, _ = c.Write(buf[:n])
		}(conn)
	}
}

// TestMultiAddrTLSListenerRejectsPlaintextHTTP reproduces versity/versitygw#2261:
// a client that speaks plaintext HTTP to a TLS listener must receive an
// actionable HTTP 400 instead of an aborted/empty response (curl exit code 52).
func TestMultiAddrTLSListenerRejectsPlaintextHTTP(t *testing.T) {
	cert := newTestCertificate(t)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }

	ln, err := NewMultiAddrTLSListener("tcp", "127.0.0.1:0", getCert, ListenerOptions{})
	if err != nil {
		t.Fatalf("create TLS listener: %v", err)
	}
	defer ln.Close()

	go serveTLSAccept(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("write plaintext request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected an HTTP 400 response, got read error (empty/aborted reply): %v", err)
	}

	resp := buf[:n]
	if !bytes.Contains(resp, []byte("400")) {
		t.Fatalf("expected a 400 status in response, got: %q", resp)
	}
	if !bytes.HasPrefix(resp, []byte("HTTP/")) {
		t.Fatalf("expected a plaintext HTTP response, got: %q", resp)
	}
}

// TestMultiAddrTLSListenerAllowsRealTLS ensures the plaintext-HTTP detection does
// not interfere with legitimate TLS clients.
func TestMultiAddrTLSListenerAllowsRealTLS(t *testing.T) {
	cert := newTestCertificate(t)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }

	ln, err := NewMultiAddrTLSListener("tcp", "127.0.0.1:0", getCert, ListenerOptions{})
	if err != nil {
		t.Fatalf("create TLS listener: %v", err)
	}
	defer ln.Close()

	go serveTLSAccept(ln)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial failed (regression): %v", err)
	}
	defer conn.Close()

	msg := []byte("ping over tls")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("tls write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("tls read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("expected echo %q, got %q", msg, buf[:n])
	}
}
