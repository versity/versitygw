// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutil

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// serveTestTLS accepts from ln and runs each connection the way a server built
// on net.Conn does: hand the handshake to the connection first, then read. The
// bytes read are echoed back so the TLS case can observe a round trip.
func serveTestTLS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()

			if hs, ok := c.(interface{ Handshake() error }); ok {
				_ = hs.Handshake()
			}

			buf := make([]byte, 512)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			_, _ = c.Write(buf[:n])
		}(conn)
	}
}

func newTestTLSListener(t *testing.T) net.Listener {
	t.Helper()

	cert := issueTestCert(t, generateTestCA(t), "localhost")
	ln, err := NewMultiAddrTLSListener("tcp", "127.0.0.1:0", func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}, ListenerOptions{})
	if err != nil {
		t.Fatalf("NewMultiAddrTLSListener() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go serveTestTLS(ln)

	return ln
}

// TestMultiAddrTLSListenerAnswersPlaintextHTTP is the regression test for
// versity/versitygw#2261: a plaintext HTTP request to a TLS listener has to
// come back with a 400 that names the mistake, not an empty reply
// (curl exit code 52).
func TestMultiAddrTLSListenerAnswersPlaintextHTTP(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("http client", func(t *testing.T) {
		ln := newTestTLSListener(t)

		resp, err := client.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatalf("plaintext HTTP request to the TLS listener: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		if !strings.Contains(string(body), "HTTPS server") {
			t.Errorf("body = %q, want it to mention the HTTPS server", body)
		}
	})

	t.Run("absolute form request line", func(t *testing.T) {
		ln := newTestTLSListener(t)

		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}

		request := "GET http://" + ln.Addr().String() + "/ HTTP/1.1\r\nHost: " + ln.Addr().String() + "\r\n\r\n"
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatalf("write request: %v", err)
		}

		raw, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if !strings.HasPrefix(string(raw), "HTTP/1.1 400 Bad Request") {
			t.Errorf("response = %q, want an HTTP 400", raw)
		}
	})

	t.Run("head has no body", func(t *testing.T) {
		ln := newTestTLSListener(t)

		resp, err := client.Head("http://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatalf("plaintext HEAD to the TLS listener: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("HEAD body = %q, want none", body)
		}
	})
}

// TestMultiAddrTLSListenerStillServesTLS guards the other side of the change:
// a real TLS client must still complete the handshake and round-trip data.
func TestMultiAddrTLSListenerStillServesTLS(t *testing.T) {
	ln := newTestTLSListener(t)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want %q", buf, "ping")
	}
}
