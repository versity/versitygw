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

package netutil

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

type CertStorage struct {
	cert atomic.Pointer[tls.Certificate]
}

func NewCertStorage() *CertStorage {
	return &CertStorage{}
}

func (cs *CertStorage) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cs.cert.Load(), nil
}

func (cs *CertStorage) SetCertificate(certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("unable to set certificate: %w", err)
	}

	cs.cert.Store(&cert)

	return nil
}
