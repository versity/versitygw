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
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countingListener struct {
	net.Listener
	read *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return countingConn{Conn: c, read: l.read}, nil
}

type countingConn struct {
	net.Conn
	read *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// TestWrapListenerSeesTLSWireBytes checks that WrapListener sits below the
// TLS layer: the wrapper observes encrypted bytes, handshake included, while
// the server still accepts a *tls.Conn it can query for connection state.
func TestWrapListenerSeesTLSWireBytes(t *testing.T) {
	var wire atomic.Int64
	cert := issueTestCert(t, generateTestCA(t), "localhost")
	ln, err := NewMultiAddrTLSListener("tcp", "127.0.0.1:0", func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}, ListenerOptions{WrapListener: func(ln net.Listener) net.Listener {
		return countingListener{Listener: ln, read: &wire}
	}})
	if err != nil {
		t.Fatalf("NewMultiAddrTLSListener() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const payload = "ping"
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		if _, ok := c.(*tls.Conn); !ok {
			t.Errorf("accepted %T, want *tls.Conn", c)
		}
		buf := make([]byte, len(payload))
		_, err = io.ReadFull(c, buf)
		accepted <- err
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive the payload")
	}
	// A ClientHello alone is a few hundred bytes, far more than the payload.
	if got := wire.Load(); got <= 100 {
		t.Fatalf("wrapper read %d bytes, want the TLS handshake and records, not just the %d byte payload", got, len(payload))
	}
}
