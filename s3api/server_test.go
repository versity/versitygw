// Copyright 2023 Versity Software
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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/internal/netutil"
	"github.com/versity/versitygw/s3api/middlewares"
)

func newTestS3ApiServer(opts ...Option) (*S3ApiServer, error) {
	allOpts := append([]Option{WithConcurrencyLimiter(10, 10)}, opts...)

	return New(
		backend.BackendUnsupported{},
		middlewares.RootUserConfig{Access: "access", Secret: "secret"},
		"us-east-1",
		auth.NewIAMServiceSingle(auth.Account{Access: "access", Secret: "secret"}),
		nil,
		nil,
		nil,
		nil,
		allOpts...,
	)
}

func TestS3ApiServer_Serve(t *testing.T) {
	tests := []struct {
		name    string
		sa      *S3ApiServer
		wantErr bool
		port    string
	}{
		{
			name:    "Serve-invalid-tcp-address",
			wantErr: true,
			sa: &S3ApiServer{
				app:     fiber.New(),
				backend: backend.BackendUnsupported{},
				Router:  &S3ApiRouter{},
			},
			port: "localhost:notaport",
		},
		{
			name:    "Serve-invalid-tcp-address-with-certificate",
			wantErr: true,
			sa: &S3ApiServer{
				app:         fiber.New(),
				backend:     backend.BackendUnsupported{},
				Router:      &S3ApiRouter{},
				CertStorage: &netutil.CertStorage{},
			},
			port: "localhost:notaport",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.sa.ServeMultiPort([]string{tt.port}); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiServer.Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestWithOnListenAddrs serves on port 0 and checks that the listen hook
// reports the port the kernel chose, after the bind, for a listener that
// accepts connections.
func TestWithOnListenAddrs(t *testing.T) {
	got := make(chan []net.Addr, 1)
	sa, err := newTestS3ApiServer(WithOnListenAddrs(func(addrs []net.Addr) { got <- addrs }))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- sa.ServeMultiPort([]string{"127.0.0.1:0"}) }()

	var addrs []net.Addr
	select {
	case addrs = <-got:
	case err := <-served:
		t.Fatalf("ServeMultiPort() returned before the listen hook fired: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("listen hook did not fire")
	}
	if len(addrs) != 1 {
		t.Fatalf("hook received %d addresses, want 1: %v", len(addrs), addrs)
	}
	tcp, ok := addrs[0].(*net.TCPAddr)
	if !ok || tcp.Port == 0 || !tcp.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("hook received %v, want a 127.0.0.1 address with the bound port", addrs[0])
	}
	conn, err := net.DialTimeout("tcp", tcp.String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialing the reported address: %v", err)
	}
	conn.Close()

	if err := sa.ShutDown(); err != nil {
		t.Fatalf("ShutDown() error = %v", err)
	}
	// ServeMultiPort reports the closed listener on the way out; only that
	// it returns matters here.
	select {
	case <-served:
	case <-time.After(shutDownDuration + time.Second):
		t.Fatal("ServeMultiPort() did not return after ShutDown()")
	}
}

func TestWithRouteRegistersBeforeMiddleware(t *testing.T) {
	const routePath = "/custom/route"

	middlewareCalled := false
	server, err := newTestS3ApiServer(
		WithRoute(http.MethodGet, routePath, func(ctx fiber.Ctx) error {
			return ctx.SendStatus(http.StatusNoContent)
		}),
		WithMiddleware("/", func(ctx fiber.Ctx) error {
			middlewareCalled = true
			return ctx.SendStatus(http.StatusMisdirectedRequest)
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := server.app.Test(httptest.NewRequest(http.MethodGet, routePath, nil))
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("response close error = %v", err)
		}
	}()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if middlewareCalled {
		t.Fatal("middleware was called for top-level route")
	}
}

func TestWithRouteRegistersAfterRateLimiter(t *testing.T) {
	const routePath = "/custom/limited"

	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	var once sync.Once

	server, err := newTestS3ApiServer(
		WithConcurrencyLimiter(10, 1),
		WithRoute(http.MethodGet, routePath, func(ctx fiber.Ctx) error {
			once.Do(func() {
				close(started)
			})
			<-release
			return ctx.SendStatus(http.StatusNoContent)
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	go func() {
		resp, err := server.app.Test(httptest.NewRequest(http.MethodGet, routePath, nil), fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
		if err != nil {
			firstDone <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			firstDone <- fiber.NewError(resp.StatusCode)
			return
		}
		firstDone <- nil
	}()

	<-started

	resp, err := server.app.Test(httptest.NewRequest(http.MethodGet, routePath, nil), fiber.TestConfig{Timeout: time.Duration(100) * time.Millisecond})
	if err != nil {
		close(release)
		t.Fatalf("second app.Test() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		close(release)
		t.Fatalf("second status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request error = %v", err)
	}
}

func TestCustomMountValidation(t *testing.T) {
	validHandler := func(ctx fiber.Ctx) error {
		return ctx.SendStatus(http.StatusNoContent)
	}

	tests := []struct {
		name    string
		opt     Option
		wantErr string
	}{
		{
			name:    "route empty method",
			opt:     WithRoute("", "/custom", validHandler),
			wantErr: "empty method",
		},
		{
			name:    "route unsupported HTTP method",
			opt:     WithRoute("BREW", "/custom", validHandler),
			wantErr: "invalid HTTP method",
		},
		{
			name:    "route empty path",
			opt:     WithRoute(http.MethodGet, "", validHandler),
			wantErr: "must start with /",
		},
		{
			name:    "route relative path",
			opt:     WithRoute(http.MethodGet, "custom", validHandler),
			wantErr: "must start with /",
		},
		{
			name:    "route no handlers",
			opt:     WithRoute(http.MethodGet, "/custom"),
			wantErr: "no handlers",
		},
		{
			name:    "route nil handler",
			opt:     WithRoute(http.MethodGet, "/custom", fiber.Handler(nil)),
			wantErr: "nil handler",
		},
		{
			name:    "middleware empty prefix",
			opt:     WithMiddleware("", validHandler),
			wantErr: "must start with /",
		},
		{
			name:    "middleware relative prefix",
			opt:     WithMiddleware("custom", validHandler),
			wantErr: "must start with /",
		},
		{
			name:    "middleware nil handler",
			opt:     WithMiddleware("/custom", nil),
			wantErr: "nil handler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTestS3ApiServer(tt.opt)
			if err == nil {
				t.Fatal("New() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
