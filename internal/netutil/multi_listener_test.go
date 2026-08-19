// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutil

import (
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

func TestRequireSecureTransport(t *testing.T) {
	tests := []struct {
		name    string
		address string
		hasMTLS bool
		wantErr bool
	}{
		{name: "unix socket without mTLS is fine", address: "/tmp/private.sock", hasMTLS: false, wantErr: false},
		{name: "unix socket with mTLS is fine", address: "/tmp/private.sock", hasMTLS: true, wantErr: false},
		{name: "abstract socket without mTLS is fine", address: "@private", hasMTLS: false, wantErr: false},
		{name: "TCP without mTLS is rejected", address: "127.0.0.1:9443", hasMTLS: false, wantErr: true},
		{name: "TCP with mTLS is fine", address: "127.0.0.1:9443", hasMTLS: true, wantErr: false},
		{name: "bare port without mTLS is rejected", address: ":9443", hasMTLS: false, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireSecureTransport(tt.address, tt.hasMTLS)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequireSecureTransport(%q, %v) error = %v, wantErr %v", tt.address, tt.hasMTLS, err, tt.wantErr)
			}
		})
	}
}

// TestMTLSListenerRejectsClientWithoutCert confirms a listener built with
// TLSOptions{ClientCAs, RequireClientCert: true} — the shape the private
// IAM endpoints use — refuses a TLS handshake from a client presenting no
// certificate, and accepts one presenting a cert signed by the configured
// CA. This is the core security boundary the whole standalone-IAM-service
// design leans on ("otherwise this endpoint should not serve anything"),
// so it's worth verifying the handshake itself, not just the config shape.
func TestMTLSListenerRejectsClientWithoutCert(t *testing.T) {
	ca := generateTestCA(t)
	serverCert := issueTestCert(t, ca, "server")
	clientCert := issueTestCert(t, ca, "client")

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	addr := "127.0.0.1:0"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Pinned to TLS 1.2: TLS 1.3 clients can report Dial as successful before
	// observing the server's post-handshake rejection alert for a missing
	// client cert, making that half of this test flaky. TLS 1.2 client-cert
	// verification is synchronous within the initial handshake flight.
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	defer tlsLn.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()
		serverErrCh <- conn.(*tls.Conn).Handshake()
	}()

	t.Run("no client cert is rejected", func(t *testing.T) {
		conn, err := tls.Dial("tcp", tlsLn.Addr().String(), &tls.Config{
			RootCAs:    caPool,
			MaxVersion: tls.VersionTLS12,
			ServerName: "server",
		})
		if err == nil {
			conn.Close()
			t.Fatal("expected handshake to fail without a client certificate")
		}
		<-serverErrCh
	})

	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()
		serverErrCh <- conn.(*tls.Conn).Handshake()
	}()

	t.Run("valid client cert is accepted", func(t *testing.T) {
		conn, err := tls.Dial("tcp", tlsLn.Addr().String(), &tls.Config{
			RootCAs:      caPool,
			MaxVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{clientCert},
			ServerName:   "server",
		})
		if err != nil {
			t.Fatalf("expected handshake to succeed with a valid client certificate: %v", err)
		}
		conn.Close()
		if err := <-serverErrCh; err != nil {
			t.Fatalf("server-side handshake failed: %v", err)
		}
	})
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func generateTestCA(t *testing.T) testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return testCA{cert: cert, key: key}
}

func issueTestCert(t *testing.T, ca testCA, cn string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", cn, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create %s cert: %v", cn, err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
