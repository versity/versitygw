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
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// MultiListener implements net.Listener and accepts connections from multiple
// underlying listeners.
type MultiListener struct {
	listeners []net.Listener
	acceptCh  chan acceptResult
	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func NewMultiListener(listeners ...net.Listener) *MultiListener {
	if len(listeners) == 0 {
		return nil
	}

	ml := &MultiListener{
		listeners: listeners,
		acceptCh:  make(chan acceptResult, 2*len(listeners)),
		closeCh:   make(chan struct{}),
	}

	for _, ln := range listeners {
		ml.wg.Add(1)
		go ml.acceptLoop(ln)
	}

	return ml
}

func (ml *MultiListener) acceptLoop(ln net.Listener) {
	defer ml.wg.Done()

	for {
		conn, err := ln.Accept()

		select {
		case <-ml.closeCh:
			if conn != nil {
				conn.Close()
			}
			return
		case ml.acceptCh <- acceptResult{conn: conn, err: err}:
			if err != nil {
				return
			}
		}
	}
}

func (ml *MultiListener) Accept() (net.Conn, error) {
	select {
	case <-ml.closeCh:
		return nil, errors.New("listener closed")
	case result, ok := <-ml.acceptCh:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return result.conn, result.err
	}
}

func (ml *MultiListener) Close() error {
	var errs []error

	ml.closeOnce.Do(func() {
		close(ml.closeCh)

		for _, ln := range ml.listeners {
			if err := ln.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		ml.wg.Wait()

		close(ml.acceptCh)
		for range ml.acceptCh {
		}
	})

	if len(errs) > 0 {
		return fmt.Errorf("errors closing listeners: %v", errs)
	}
	return nil
}

func (ml *MultiListener) Addr() net.Addr {
	if len(ml.listeners) > 0 {
		return ml.listeners[0].Addr()
	}
	return nil
}

func IsUnixSocketPath(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err != nil
}

func AbsSocketPaths(addrs []string) ([]string, error) {
	result := make([]string, len(addrs))
	for i, addr := range addrs {
		if strings.HasPrefix(addr, "./") {
			abs, err := filepath.Abs(addr)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve socket path %q: %w", addr, err)
			}
			result[i] = abs
		} else {
			result[i] = addr
		}
	}
	return result, nil
}

func isAbstractSocket(addr string) bool {
	return strings.HasPrefix(addr, "@")
}

func removeStaleSocket(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat socket path %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path %q already exists and is not a socket (mode %s)", path, fi.Mode())
	}
	return os.Remove(path)
}

func ResolveHostnameIPs(address string) ([]string, error) {
	if IsUnixSocketPath(address) {
		return []string{address}, nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}

	if host == "" {
		return []string{""}, nil
	}

	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for hostname %q", host)
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}

func resolveHostnameAddrs(address string) ([]string, error) {
	if IsUnixSocketPath(address) {
		return []string{address}, nil
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}

	if host == "" || net.ParseIP(host) != nil {
		return []string{address}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for hostname %q", host)
	}

	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.JoinHostPort(ip.String(), port))
	}

	return addrs, nil
}

type ListenerOptions struct {
	SocketPerm os.FileMode
}

func NewMultiAddrListener(network, address string, opts ListenerOptions) (net.Listener, error) {
	if IsUnixSocketPath(address) {
		if !isAbstractSocket(address) {
			if err := removeStaleSocket(address); err != nil {
				return nil, err
			}
		}
		ln, err := net.Listen("unix", address)
		if err != nil {
			return nil, fmt.Errorf("failed to bind unix socket listener %s: %w", address, err)
		}
		if opts.SocketPerm != 0 && !isAbstractSocket(address) {
			if err := os.Chmod(address, opts.SocketPerm); err != nil {
				ln.Close()
				return nil, fmt.Errorf("failed to set permissions on socket %s: %w", address, err)
			}
		}
		return NewMultiListener(ln), nil
	}

	addrs, err := resolveHostnameAddrs(address)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := net.Listen(network, addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("failed to bind listener %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
	}

	return NewMultiListener(listeners...), nil
}

// TLSOptions configures the server-side tls.Config for
// NewMultiAddrTLSListenerWithOptions. A non-nil ClientCAs enables mTLS:
// inbound connections must present a certificate verified against that
// pool
type TLSOptions struct {
	GetCertificate    func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	ClientCAs         *x509.CertPool
	RequireClientCert bool
}

// NewMultiAddrTLSListener creates TLS listeners for all IP addresses that the
// hostname in the address resolves to. Similar to NewMultiAddrListener but with TLS.
func NewMultiAddrTLSListener(network, address string, getCertificateFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error), opts ListenerOptions) (net.Listener, error) {
	return NewMultiAddrTLSListenerWithOptions(network, address, TLSOptions{GetCertificate: getCertificateFunc}, opts)
}

// NewMultiAddrTLSListenerWithOptions is NewMultiAddrTLSListener with control
// over client-certificate verification (mTLS), for listeners — such as the
// standalone IAM service's private endpoints — that must authenticate the
// connecting client, not just the server.
func NewMultiAddrTLSListenerWithOptions(network, address string, tlsOpts TLSOptions, opts ListenerOptions) (net.Listener, error) {
	config := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: tlsOpts.GetCertificate,
	}
	if tlsOpts.ClientCAs != nil {
		config.ClientCAs = tlsOpts.ClientCAs
		if tlsOpts.RequireClientCert {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			config.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	if IsUnixSocketPath(address) {
		if !isAbstractSocket(address) {
			if err := removeStaleSocket(address); err != nil {
				return nil, err
			}
		}
		ln, err := net.Listen("unix", address)
		if err != nil {
			return nil, fmt.Errorf("failed to bind unix TLS socket listener %s: %w", address, err)
		}
		if opts.SocketPerm != 0 && !isAbstractSocket(address) {
			if err := os.Chmod(address, opts.SocketPerm); err != nil {
				ln.Close()
				return nil, fmt.Errorf("failed to set permissions on socket %s: %w", address, err)
			}
		}
		return NewMultiListener(tls.NewListener(ln, config)), nil
	}

	addrs, err := resolveHostnameAddrs(address)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := net.Listen(network, addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("failed to bind TLS listener %s: %w", addr, err)
		}
		listeners = append(listeners, tls.NewListener(ln, config))
	}

	return NewMultiListener(listeners...), nil
}

// RequireSecureTransport enforces mTLS or unix socket a unix socket
// is always acceptable (the filesystem is the trust boundary),
// but a TCP address is only acceptable when mTLS (a server cert plus
// mandatory client-certificate verification) is actually configured for
// it
func RequireSecureTransport(address string, hasMTLS bool) error {
	if IsUnixSocketPath(address) {
		return nil
	}
	if !hasMTLS {
		return fmt.Errorf("private listener %q requires either a unix socket path or mTLS (server cert + client CA); refusing to serve on plain TCP", address)
	}
	return nil
}
