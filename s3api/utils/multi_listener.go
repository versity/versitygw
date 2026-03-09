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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// MultiListener implements net.Listener and accepts connections from multiple
// underlying listeners. This is useful for listening on multiple IP addresses
// that a hostname resolves to (e.g., both IPv4 and IPv6 for "localhost").
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

// NewMultiListener creates a new MultiListener that accepts connections from
// all provided listeners.
func NewMultiListener(listeners ...net.Listener) *MultiListener {
	if len(listeners) == 0 {
		return nil
	}

	ml := &MultiListener{
		listeners: listeners,
		acceptCh:  make(chan acceptResult, 2*len(listeners)),
		closeCh:   make(chan struct{}),
	}

	// Start accepting from each listener in its own goroutine
	for _, ln := range listeners {
		ml.wg.Add(1)
		go ml.acceptLoop(ln)
	}

	return ml
}

// acceptLoop continuously accepts connections from a single listener
// and forwards them to the accept channel
func (ml *MultiListener) acceptLoop(ln net.Listener) {
	defer ml.wg.Done()

	for {
		conn, err := ln.Accept()

		select {
		case <-ml.closeCh:
			// MultiListener is closing
			if conn != nil {
				conn.Close()
			}
			return
		case ml.acceptCh <- acceptResult{conn: conn, err: err}:
			// Connection or error sent successfully
			if err != nil {
				return
			}
		}
	}
}

// Accept waits for and returns the next connection from any of the listeners
func (ml *MultiListener) Accept() (net.Conn, error) {
	select {
	case <-ml.closeCh:
		return nil, errors.New("listener closed")
	case result, ok := <-ml.acceptCh:
		if !ok {
			// Channel closed
			return nil, errors.New("listener closed")
		}
		return result.conn, result.err
	}
}

// Close closes all underlying listeners
func (ml *MultiListener) Close() error {
	var errs []error

	ml.closeOnce.Do(func() {
		close(ml.closeCh)

		// Close all listeners
		for _, ln := range ml.listeners {
			if err := ln.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		// Wait for all accept loops to finish
		ml.wg.Wait()

		// Drain any remaining accepts
		close(ml.acceptCh)
		for range ml.acceptCh {
		}
	})

	if len(errs) > 0 {
		return fmt.Errorf("errors closing listeners: %v", errs)
	}
	return nil
}

// Addr returns the address of the first listener
func (ml *MultiListener) Addr() net.Addr {
	if len(ml.listeners) > 0 {
		return ml.listeners[0].Addr()
	}
	return nil
}

// IsUnixSocketPath reports whether addr should be treated as a UNIX domain
// socket path rather than a TCP/IP address. It does so by attempting to parse
// addr as a host:port spec using net.SplitHostPort; anything that cannot be
// parsed that way (e.g. "/path/to/socket", "./rel/socket", "@abstract") is
// considered a socket path.
func IsUnixSocketPath(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err != nil
}

// AbsSocketPaths converts any relative UNIX socket paths in addrs to absolute
// paths using the current working directory. Non-socket addresses (TCP/IP) and
// abstract sockets ("@name") are returned unchanged. This should be called
// early in program startup — before any backend that calls os.Chdir — so that
// relative paths are resolved against the shell's working directory.
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

// isAbstractSocket reports whether addr is a Linux abstract namespace socket.
// Abstract sockets start with "@"; Go's net package maps this to a leading
// null byte (\0) in the sockaddr, so no socket file is created on disk.
func isAbstractSocket(addr string) bool {
	return strings.HasPrefix(addr, "@")
}

// removeStaleSocket removes a leftover UNIX socket file at path so the
// address can be reused. It returns an error if the path exists but is not
// a socket, protecting regular files and directories from accidental deletion.
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

// ResolveHostnameIPs resolves a hostname to all its IP addresses (IPv4 and IPv6).
// If the input is already an IP address or empty, it returns it as-is.
// This is useful for determining all addresses a server will listen on.
func ResolveHostnameIPs(address string) ([]string, error) {
	if IsUnixSocketPath(address) {
		return []string{address}, nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}

	// Handle empty host (e.g., ":8080" means all interfaces)
	if host == "" {
		return []string{""}, nil
	}

	// If already an IP address, return as is
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	// Resolve hostname to all IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for hostname %q", host)
	}

	// Convert IPs to strings
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}

// resolveHostnameAddrs resolves a hostname to all its IP addresses (IPv4 and IPv6)
// and returns them as a list of addresses with the port attached.
func resolveHostnameAddrs(address string) ([]string, error) {
	if IsUnixSocketPath(address) {
		return []string{address}, nil
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}

	// If host is empty or already an IP address, return as is
	if host == "" || net.ParseIP(host) != nil {
		return []string{address}, nil
	}

	// Resolve hostname to all IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for hostname %q", host)
	}

	// Build list of addresses with port
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// NewMultiAddrListener creates listeners for all IP addresses that the hostname
// in the address resolves to. If the address is already an IP, it creates a
// single listener. Returns a MultiListener if multiple addresses are resolved,
// or a single listener if only one address is found.
//
// UNIX domain socket forms are also supported:
//   - "/path/to/socket" or "./rel/socket" — file-backed socket; any stale
//     socket file is removed before binding.
//   - "@name" — Linux abstract namespace socket; no file is created or removed.
func NewMultiAddrListener(network, address string) (net.Listener, error) {
	if IsUnixSocketPath(address) {
		// For file-backed sockets, remove any stale socket file so re-binding works cleanly.
		// Abstract sockets (@name) have no filesystem entry; skip removal for them.
		if !isAbstractSocket(address) {
			if err := removeStaleSocket(address); err != nil {
				return nil, err
			}
		}
		ln, err := net.Listen("unix", address)
		if err != nil {
			return nil, fmt.Errorf("failed to bind unix socket listener %s: %w", address, err)
		}
		return NewMultiListener(ln), nil
	}

	addrs, err := resolveHostnameAddrs(address)
	if err != nil {
		return nil, err
	}

	// Create listeners for all resolved addresses
	listeners := make([]net.Listener, 0, len(addrs))

	for _, addr := range addrs {
		ln, err := net.Listen(network, addr)
		if err != nil {
			// Close any listeners we've already created
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("failed to bind listener %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
	}

	// Return MultiListener for multiple addresses
	return NewMultiListener(listeners...), nil
}

// NewMultiAddrTLSListener creates TLS listeners for all IP addresses that the
// hostname in the address resolves to. Similar to NewMultiAddrListener but with TLS.
//
// UNIX domain socket forms are also supported:
//   - "/path/to/socket" or "./rel/socket" — file-backed socket; any stale
//     socket file is removed before binding.
//   - "@name" — Linux abstract namespace socket; no file is created or removed.
func NewMultiAddrTLSListener(network, address string, getCertificateFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (net.Listener, error) {
	config := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: getCertificateFunc,
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
		return NewMultiListener(tls.NewListener(ln, config)), nil
	}

	addrs, err := resolveHostnameAddrs(address)
	if err != nil {
		return nil, err
	}

	// Create TLS listeners for all resolved addresses
	listeners := make([]net.Listener, 0, len(addrs))

	for _, addr := range addrs {
		ln, err := net.Listen(network, addr)
		if err != nil {
			// Close any listeners we've already created
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("failed to bind TLS listener %s: %w", addr, err)
		}
		listeners = append(listeners, tls.NewListener(ln, config))
	}

	// Return MultiListener for multiple addresses
	return NewMultiListener(listeners...), nil
}
