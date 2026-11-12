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

package s3api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/bwlimit"
	"github.com/versity/versitygw/internal/netutil"
)

type bandwidthTestMetrics struct {
	mu   sync.Mutex
	wait map[string]time.Duration
}

func (*bandwidthTestMetrics) Send(fiber.Ctx, error, string, int64, int)                   {}
func (*bandwidthTestMetrics) SendWithBucket(fiber.Ctx, error, string, int64, int, string) {}
func (*bandwidthTestMetrics) Close()                                                      {}

func (m *bandwidthTestMetrics) SendBandwidthWait(direction string, wait time.Duration) {
	m.mu.Lock()
	if m.wait == nil {
		m.wait = make(map[string]time.Duration)
	}
	m.wait[direction] += wait
	m.mu.Unlock()
}

func (m *bandwidthTestMetrics) waited(direction string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.wait[direction]
}

func setBandwidthTestCertificate(t *testing.T, s *S3ApiServer) {
	t.Helper()
	s.CertStorage = &netutil.CertStorage{}
	if err := s.CertStorage.SetCertificate("../tests/certs/azurite.pem", "../tests/certs/azurite-key.pem"); err != nil {
		t.Fatal(err)
	}
}

func waitBandwidthListeners(t *testing.T, listening <-chan []net.Addr, served <-chan error) []net.Addr {
	t.Helper()
	select {
	case addr := <-listening:
		return addr
	case err := <-served:
		t.Fatalf("server exited before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	return nil
}

func TestBandwidthTLSIsSharedAcrossPorts(t *testing.T) {
	const (
		rate    = 256 << 10
		burst   = 32 << 10
		size    = 128 << 10
		clients = 2
	)
	payload := bytes.Repeat([]byte("d"), size)
	for _, ingress := range []bool{true, false} {
		direction := "egress"
		if ingress {
			direction = "ingress"
		}
		t.Run(direction, func(t *testing.T) {
			listening := make(chan []net.Addr, 1)
			method := http.MethodGet
			option := WithBandwidthLimit(0, 0, rate, burst)
			handler := func(ctx fiber.Ctx) error { return ctx.Send(payload) }
			if ingress {
				method = http.MethodPost
				option = WithBandwidthLimit(rate, burst, 0, 0)
				handler = func(ctx fiber.Ctx) error {
					var got []byte
					if stream := ctx.Request().BodyStream(); stream != nil {
						var err error
						got, err = io.ReadAll(stream)
						if err != nil {
							return err
						}
					} else {
						got = ctx.BodyRaw()
					}
					if !bytes.Equal(got, payload) {
						return errors.New("upload differs from payload")
					}
					return ctx.SendStatus(http.StatusNoContent)
				}
			}
			s, err := newTestS3ApiServer(
				option,
				WithRoute(method, "/bandwidth", handler),
				WithOnListenAddrs(func(addrs []net.Addr) { listening <- addrs }),
			)
			if err != nil {
				t.Fatal(err)
			}
			setBandwidthTestCertificate(t, s)
			served := make(chan error, 1)
			go func() {
				served <- s.ServeMultiPort([]string{"127.0.0.1:0", "127.0.0.1:0"})
			}()
			t.Cleanup(func() { _ = s.ShutDown() })
			addrs := waitBandwidthListeners(t, listening, served)
			if len(addrs) != clients {
				t.Fatalf("got %d listening addresses, want %d", len(addrs), clients)
			}
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate
				DisableKeepAlives: true,
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			done := make(chan error, clients)
			start := time.Now()
			for _, addr := range addrs {
				go func(addr net.Addr) {
					var body io.Reader
					if ingress {
						body = bytes.NewReader(payload)
					}
					req, err := http.NewRequest(method, "https://"+addr.String()+"/bandwidth", body)
					if err != nil {
						done <- err
						return
					}
					res, err := client.Do(req)
					if err == nil {
						var got []byte
						got, err = io.ReadAll(res.Body)
						_ = res.Body.Close()
						if err == nil && (ingress && res.StatusCode != http.StatusNoContent ||
							!ingress && (res.StatusCode != http.StatusOK || !bytes.Equal(got, payload))) {
							err = fmt.Errorf("unexpected response: status %d, body size %d", res.StatusCode, len(got))
						}
					}
					done <- err
				}(addr)
			}
			for range clients {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			want := time.Duration(float64(clients*size-burst) / rate * float64(time.Second))
			if elapsed := time.Since(start); elapsed < want*8/10 {
				t.Fatalf("concurrent TLS %s took %v, want at least about %v", direction, elapsed, want)
			}
			if err := s.ShutDown(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-served:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not stop")
			}
		})
	}
}

func TestBandwidthServerRestart(t *testing.T) {
	listening := make(chan []net.Addr, 4)
	s, err := newTestS3ApiServerWithMetrics(
		&bandwidthTestMetrics{},
		WithBandwidthLimit(0, 0, 1<<20, 0),
		WithOnListenAddrs(func(addrs []net.Addr) { listening <- addrs }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.ShutDown() })
	for i := 0; i < 2; i++ {
		served := make(chan error, 1)
		go func() { served <- s.ServeMultiPort([]string{"127.0.0.1:0"}) }()
		select {
		case <-listening:
		case <-time.After(2 * time.Second):
			t.Fatalf("run %d did not start", i)
		}
		stopped := make(chan error, 1)
		go func() { stopped <- s.ShutDown() }()
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatalf("run %d shutdown: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("run %d shutdown blocked", i)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Fatalf("run %d did not return", i)
		}
		select {
		case addrs := <-listening:
			t.Fatalf("run %d invoked the listen hook more than once: %v", i, addrs)
		default:
		}
	}
}

func TestBandwidthStartupShutdown(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, err := newTestS3ApiServerWithMetrics(
			&bandwidthTestMetrics{},
			WithBandwidthLimit(0, 0, 1<<20, 0),
		)
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		stopped := make(chan error, 1)
		go func() { served <- s.ServeMultiPort([]string{"127.0.0.1:0"}) }()
		go func() { stopped <- s.ShutDown() }()
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatalf("iteration %d shutdown: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d shutdown blocked", i)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d continued serving after shutdown", i)
		}
	}
}

func TestBandwidthWaitReportedAfterListenerFailure(t *testing.T) {
	listening := make(chan []net.Addr, 1)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHandler()
	mm := &bandwidthTestMetrics{}
	s, err := newTestS3ApiServerWithMetrics(
		mm,
		WithBandwidthLimit(0, 0, 1<<20, bwlimit.MinBurst),
		WithRoute(http.MethodGet, "/bandwidth", func(ctx fiber.Ctx) error {
			close(started)
			<-release
			return ctx.Send(make([]byte, 2*bwlimit.MinBurst))
		}),
		WithOnListenAddrs(func(addrs []net.Addr) { listening <- addrs }),
	)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.ServeMultiPort([]string{"127.0.0.1:0"}) }()
	t.Cleanup(func() { _ = s.ShutDown() })
	addr := waitBandwidthListeners(t, listening, served)[0]
	response := make(chan error, 1)
	go func() {
		res, err := http.Get("http://" + addr.String() + "/bandwidth")
		if err == nil {
			_, err = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
		response <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	if err := s.listener.Load().Close(); err != nil {
		t.Fatal(err)
	}
	releaseHandler()
	select {
	case err := <-response:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("response did not finish")
	}
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish draining after listener failure")
	}
	if got := mm.waited("egress"); got <= 0 {
		t.Fatal("bandwidth wait from the final response was not reported")
	}
}

// exhaustBandwidth uses a second socket sharing the server's limiter to put
// the egress bucket in the saturated state without relying on private tokens.
func exhaustBandwidth(t *testing.T, lim *bwlimit.Limiter) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := bwlimit.NewListener(raw, nil, lim)
	defer ln.Close()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, client)
		close(drained)
	}()
	buf := make([]byte, bwlimit.MinBurst)
	for size := len(buf); size > 0; size /= 2 {
		for {
			if err := server.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			n, err := server.Write(buf[:size])
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil || n != size {
				t.Fatalf("exhausting bandwidth: wrote %d, %v; want %d", n, err, size)
			}
		}
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	<-drained
}

func TestBandwidthTLSShutdownTimeout(t *testing.T) {
	listening := make(chan []net.Addr, 1)
	mm := &bandwidthTestMetrics{}
	s, err := newTestS3ApiServerWithMetrics(
		mm,
		WithBandwidthLimit(0, 0, 6, bwlimit.MinBurst),
		WithKeepAlive(),
		WithRoute(http.MethodGet, "/bandwidth", func(ctx fiber.Ctx) error {
			return ctx.SendString("ok")
		}),
		WithOnListenAddrs(func(addrs []net.Addr) { listening <- addrs }),
	)
	if err != nil {
		t.Fatal(err)
	}
	setBandwidthTestCertificate(t, s)
	served := make(chan error, 1)
	go func() { served <- s.ServeMultiPort([]string{"127.0.0.1:0"}) }()
	t.Cleanup(func() { _ = s.ShutDown() })
	addr := waitBandwidthListeners(t, listening, served)[0]
	var clients []*tls.Conn
	for i := 0; i < 4; i++ {
		c, err := tls.Dial("tcp", addr.String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		defer c.Close()
		if _, err := fmt.Fprintf(c, "GET /bandwidth HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	exhaustBandwidth(t, s.egressLimiter)
	start := time.Now()
	err = s.ShutDown()
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ShutDown() error = %v, want deadline exceeded", err)
	}
	if elapsed > shutDownDuration+3*time.Second {
		t.Fatalf("ShutDown() took %v, want at most %v", elapsed, shutDownDuration+3*time.Second)
	}
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after shutdown")
	}
	if got := mm.waited("egress"); got < 8*time.Second {
		t.Fatalf("reported egress wait = %v, want at least 8 seconds", got)
	}
	for _, c := range clients {
		if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		_, err := c.Read(make([]byte, 1))
		if netErr, ok := err.(net.Error); err == nil || ok && netErr.Timeout() {
			t.Fatalf("connection remained open after shutdown: %v", err)
		}
	}
}
