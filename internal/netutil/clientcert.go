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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadClientCert loads a client certificate/key pair for presenting on an
// outbound mTLS connection
func LoadClientCert(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load client certificate: %w", err)
	}
	return cert, nil
}

// LoadCACertPool loads a PEM-encoded CA bundle for verifying a peer's
// certificate on an outbound connection (the server's cert, from a
// client's perspective) or, on an inbound mTLS listener, a connecting
// client's certificate.
func LoadCACertPool(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %q: %w", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no valid certificates found in %q", caFile)
	}

	return pool, nil
}
