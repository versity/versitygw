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
	"path/filepath"
	"runtime"
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

func TestBandwidthLimitsUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-domain sockets are not portable on Windows")
	}
	const rate = 256 << 10
	const burst = 32 << 10
	const size = 160 << 10
	listening := make(chan []net.Addr, 1)
	s, err := newTestS3ApiServer(
		WithBandwidthLimit(0, 0, rate, burst),
		WithRoute(http.MethodGet, "/bandwidth", func(ctx fiber.Ctx) error {
			return ctx.Send(make([]byte, size))
		}),
		WithOnListenAddrs(func(addrs []net.Addr) { listening <- addrs }),
	)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	path := filepath.Join(t.TempDir(), "s")
	go func() { served <- s.ServeMultiPort([]string{path}) }()
	t.Cleanup(func() { _ = s.ShutDown() })
	waitBandwidthListeners(t, listening, served)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	if _, err := fmt.Fprint(conn, "GET /bandwidth HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if n, err := io.Copy(io.Discard, resp.Body); err != nil || n != size {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	want := time.Duration(float64(size-burst) / rate * float64(time.Second))
	if elapsed := time.Since(start); elapsed < want*8/10 {
		t.Fatalf("unix socket transfer took %v, want at least about %v", elapsed, want)
	}
}

func TestBandwidthWaitReportedOnShutdown(t *testing.T) {
	listening := make(chan []net.Addr, 1)
	mm := &bandwidthTestMetrics{}
	s, err := newTestS3ApiServerWithMetrics(
		mm,
		WithBandwidthLimit(0, 0, bwlimit.MinRate, bwlimit.MinBurst),
		WithRoute(http.MethodGet, "/bandwidth", func(ctx fiber.Ctx) error {
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
	res, err := http.Get("http://" + addr.String() + "/bandwidth")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ShutDown(); err != nil {
		t.Fatal(err)
	}
	if got := mm.waited("egress"); got <= 0 {
		t.Fatal("bandwidth wait was not reported on shutdown")
	}
}

func TestBandwidthTLSShutdownTimeout(t *testing.T) {
	const (
		idleConnections = 12
		rate            = bwlimit.MinRate
		burst           = bwlimit.MinBurst
	)
	listening := make(chan []net.Addr, 1)
	s, err := newTestS3ApiServer(
		WithBandwidthLimit(0, 0, rate, burst),
		WithRoute(http.MethodGet, "/idle", func(ctx fiber.Ctx) error {
			return ctx.SendStatus(http.StatusNoContent)
		}),
		WithRoute(http.MethodGet, "/download", func(ctx fiber.Ctx) error {
			return ctx.Send(make([]byte, 2<<20))
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

	transports := make([]*http.Transport, idleConnections)
	for i := range transports {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate
		}
		transports[i] = transport
		res, err := (&http.Client{Transport: transport}).Get("https://" + addr.String() + "/idle")
		if err != nil {
			t.Fatalf("opening idle TLS connection %d: %v", i, err)
		}
		_ = res.Body.Close()
	}
	t.Cleanup(func() {
		for _, transport := range transports {
			transport.CloseIdleConnections()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr.String()+"/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	downloadTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate
	}
	defer downloadTransport.CloseIdleConnections()
	downloadDone := make(chan error, 1)
	go func() {
		res, err := downloadTransport.RoundTrip(req)
		if err == nil {
			_, err = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
		downloadDone <- err
	}()

	deadline := time.Now().Add(5 * time.Second)
	for s.egressLimiter.DrainWaitTime() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("download did not enter the bandwidth wait queue")
		}
		time.Sleep(time.Millisecond)
	}

	shutdownDone := make(chan error, 1)
	start := time.Now()
	go func() { shutdownDone <- s.ShutDown() }()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("ShutDown() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("ShutDown() remained blocked by bandwidth-limited TLS connections")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("ShutDown() took %v, want less than 5s", elapsed)
	}

	select {
	case err := <-downloadDone:
		if err != nil {
			t.Fatalf("download during shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("download did not drain after lifting the bandwidth limit")
	}
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after shutdown")
	}
}

func TestBandwidthLimitRestoredAfterReserve(t *testing.T) {
	const size = 4 * bwlimit.MinBurst
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	mm := &bandwidthTestMetrics{}
	s, err := newTestS3ApiServerWithMetrics(
		mm,
		WithBandwidthLimit(0, 0, bwlimit.MinRate, bwlimit.MinBurst),
		WithRoute(http.MethodGet, "/bandwidth", func(ctx fiber.Ctx) error {
			return ctx.Send(make([]byte, size))
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.ShutDown() })
	minElapsed := time.Duration(float64(size-bwlimit.MinBurst) / bwlimit.MinRate * float64(time.Second))
	for run := range 2 {
		served := make(chan error, 1)
		go func() { served <- s.ServeMultiPort([]string{addr}) }()
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		var res *http.Response
		var start time.Time
		deadline := time.Now().Add(5 * time.Second)
		for {
			start = time.Now()
			res, err = client.Get("http://" + addr + "/bandwidth")
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		_, err = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed < minElapsed*8/10 {
			t.Fatalf("run %d: download took %v, want at least about %v", run, elapsed, minElapsed)
		}
		if err := s.ShutDown(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Fatalf("run %d: server did not stop", run)
		}
		if got := mm.waited("egress"); got <= 0 {
			t.Fatalf("run %d: bandwidth wait was not reported", run)
		}
		mm.mu.Lock()
		mm.wait = nil
		mm.mu.Unlock()
	}
}
