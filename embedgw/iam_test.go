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

package embedgw

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunIAMAPIValidatesConfig(t *testing.T) {
	base := IAMConfig{
		RootUserAccess: "root",
		RootUserSecret: "secret",
		Ports:          []string{"127.0.0.1:0"},
		MaxConnections: 1,
		MaxRequests:    1,
		IAMDir:         t.TempDir(),
		Quiet:          true,
	}

	tests := []struct {
		name    string
		mutate  func(*IAMConfig)
		wantErr string
	}{
		{
			name: "missing root access",
			mutate: func(cfg *IAMConfig) {
				cfg.RootUserAccess = ""
			},
			wantErr: "root access key is required",
		},
		{
			name: "missing root secret",
			mutate: func(cfg *IAMConfig) {
				cfg.RootUserSecret = ""
			},
			wantErr: "root secret key is required",
		},
		{
			name: "missing ports",
			mutate: func(cfg *IAMConfig) {
				cfg.Ports = nil
			},
			wantErr: "no ports specified",
		},
		{
			name: "invalid max connections",
			mutate: func(cfg *IAMConfig) {
				cfg.MaxConnections = 0
			},
			wantErr: "max-connections must be positive",
		},
		{
			name: "invalid max requests",
			mutate: func(cfg *IAMConfig) {
				cfg.MaxRequests = 0
			},
			wantErr: "max-requests must be positive",
		},
		{
			name: "missing storer",
			mutate: func(cfg *IAMConfig) {
				cfg.IAMDir = ""
			},
			wantErr: "no IAM storer config specified",
		},
		{
			name: "invalid socket permission",
			mutate: func(cfg *IAMConfig) {
				cfg.SocketPerm = "nope"
			},
			wantErr: "invalid SocketPerm value",
		},
		{
			name: "missing tls cert",
			mutate: func(cfg *IAMConfig) {
				cfg.CertFile = ""
				cfg.KeyFile = "server.key"
			},
			wantErr: "TLS key specified without cert file",
		},
		{
			name: "missing tls key",
			mutate: func(cfg *IAMConfig) {
				cfg.CertFile = "server.crt"
				cfg.KeyFile = ""
			},
			wantErr: "TLS cert specified without key file",
		},
		{
			name: "multiple storers",
			mutate: func(cfg *IAMConfig) {
				cfg.VaultEndpointURL = "https://vault.example.com"
			},
			wantErr: "multiple IAM storer configs specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.IAMDir = t.TempDir()
			tt.mutate(&cfg)

			err := RunIAMAPI(context.Background(), &cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunIAMAPIRejectsNilConfig(t *testing.T) {
	err := RunIAMAPI(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "iam config is required") {
		t.Fatalf("error = %q", err)
	}
}

// TestRunIAMAPIReloadsCertsOnSigHup rotates every certificate and CA file the
// IAM service reads to a new CA and sends one SIGHUP: the public API, the
// private listener and the hosted WebUI must all serve the new certificates,
// and the private listener must switch to verifying gateways against the new
// client CA.
func TestRunIAMAPIReloadsCertsOnSigHup(t *testing.T) {
	oldCA := newIAMTestCA(t, "old-ca")
	newCA := newIAMTestCA(t, "new-ca")
	oldGateway := oldCA.issue(t, "gateway")
	newGateway := newCA.issue(t, "gateway")

	dir := t.TempDir()
	certFile := filepath.Join(dir, "iam.crt")
	keyFile := filepath.Join(dir, "iam.key")
	privCertFile := filepath.Join(dir, "private.crt")
	privKeyFile := filepath.Join(dir, "private.key")
	clientCAFile := filepath.Join(dir, "client-ca.pem")
	writeCerts := func(ca iamTestCA) {
		ca.writeCertFiles(t, "iam", certFile, keyFile)
		ca.writeCertFiles(t, "iam-private", privCertFile, privKeyFile)
		ca.writeCAFile(t, clientCAFile)
	}
	writeCerts(oldCA)

	// A unix socket path is limited to ~104 bytes on macOS, which t.TempDir()
	// can exceed once it embeds the test name.
	sockDir, err := os.MkdirTemp("", "vgw-iam")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	publicSock := filepath.Join(sockDir, "api.sock")
	privateSock := filepath.Join(sockDir, "priv.sock")
	webuiSock := filepath.Join(sockDir, "web.sock")

	sigHup := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunIAMAPI(ctx, &IAMConfig{
			RootUserAccess:      "root",
			RootUserSecret:      "secret",
			Ports:               []string{publicSock},
			MaxConnections:      16,
			MaxRequests:         16,
			CertFile:            certFile,
			KeyFile:             keyFile,
			Quiet:               true,
			PrivatePorts:        []string{privateSock},
			PrivateCertFile:     privCertFile,
			PrivateKeyFile:      privKeyFile,
			PrivateClientCAFile: clientCAFile,
			IAMDir:              t.TempDir(),
			CORSAllowOrigin:     "*",
			WebuiPorts:          []string{webuiSock},
			SigHup:              sigHup,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("RunIAMAPI: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("RunIAMAPI did not return after cancel")
		}
	})

	// servedBy dials sock and returns the CN of the CA that issued the
	// certificate it serves. Pinned to TLS 1.2 so a refused client
	// certificate fails the handshake itself, as in netutil's mTLS tests.
	servedBy := func(sock string, clientCert *tls.Certificate) (string, error) {
		conf := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}
		if clientCert != nil {
			conf.Certificates = []tls.Certificate{*clientCert}
		}
		conn, err := tls.Dial("unix", sock, conf)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Issuer.CommonName, nil
	}
	// expect reports the first listener not in the state ca describes:
	// serving certificates from ca and accepting only gateways ca issued.
	expect := func(ca iamTestCA, accepted, refused *tls.Certificate) error {
		for _, sock := range []string{publicSock, webuiSock} {
			issuer, err := servedBy(sock, nil)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Base(sock), err)
			}
			if issuer != ca.cert.Subject.CommonName {
				return fmt.Errorf("%s serves a cert issued by %s, want %s", filepath.Base(sock), issuer, ca.cert.Subject.CommonName)
			}
		}
		issuer, err := servedBy(privateSock, accepted)
		if err != nil {
			return fmt.Errorf("private listener refused a gateway cert issued by %s: %w", ca.cert.Subject.CommonName, err)
		}
		if issuer != ca.cert.Subject.CommonName {
			return fmt.Errorf("private listener serves a cert issued by %s, want %s", issuer, ca.cert.Subject.CommonName)
		}
		if _, err := servedBy(privateSock, refused); err == nil {
			return fmt.Errorf("private listener accepted a gateway cert from a CA other than %s", ca.cert.Subject.CommonName)
		}
		return nil
	}
	waitFor := func(ca iamTestCA, accepted, refused *tls.Certificate) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			err := expect(ca, accepted, refused)
			if err == nil {
				return
			}
			select {
			case runErr := <-errCh:
				t.Fatalf("RunIAMAPI exited early: %v", runErr)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	waitFor(oldCA, oldGateway, newGateway)

	writeCerts(newCA)
	select {
	case sigHup <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("RunIAMAPI is not receiving SIGHUP notifications")
	}

	waitFor(newCA, newGateway, oldGateway)
}

type iamTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newIAMTestCA(t *testing.T, cn string) iamTestCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
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

	return iamTestCA{cert: cert, key: key}
}

func (ca iamTestCA) issue(t *testing.T, cn string) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", cn, err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
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

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (ca iamTestCA) writeCertFiles(t *testing.T, cn, certFile, keyFile string) {
	t.Helper()

	cert := ca.issue(t, cn)
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal %s key: %v", cn, err)
	}
	writeIAMTestPEM(t, certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	writeIAMTestPEM(t, keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (ca iamTestCA) writeCAFile(t *testing.T, path string) {
	t.Helper()
	writeIAMTestPEM(t, path, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

func writeIAMTestPEM(t *testing.T, path string, block *pem.Block) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
