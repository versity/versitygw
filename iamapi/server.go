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

package iamapi

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/internal/netutil"
)

const (
	shutDownDuration     = time.Second * 10
	requestHeaderMaxSize = 8 * 1024
)

// RootCredentials re-exports the type from iammiddleware so callers only need
// to import iamapi.
type RootCredentials = iammiddleware.RootCredentials

type CertStorage = netutil.CertStorage

func NewCertStorage() *CertStorage {
	return netutil.NewCertStorage()
}

type IAMApiServer struct {
	Router         *IAMApiRouter
	app            *fiber.App
	store          storage.Storer
	rootCreds      *RootCredentials
	CertStorage    *CertStorage
	quiet          bool
	keepAlive      bool
	health         string
	maxConnections int
	maxRequests    int
	socketPerm     os.FileMode
	onListen       func()
	// oidcThumbprintAutoFetchDisabled disables CreateOpenIDConnectProvider's
	// TLS auto-fetch fallback; see WithOIDCThumbprintAutoFetchDisabled.
	oidcThumbprintAutoFetchDisabled bool
}

func New(store storage.Storer, opts ...Option) (*IAMApiServer, error) {
	if store == nil {
		return nil, fmt.Errorf("iamapi: storer is required")
	}

	server := &IAMApiServer{
		store: store,
		Router: &IAMApiRouter{
			store: store,
		},
	}

	for _, opt := range opts {
		opt(server)
	}

	app := fiber.New(fiber.Config{
		AppName:           "versitygw-iam",
		ServerHeader:      "VERSITYGW",
		DisableKeepalive:  !server.keepAlive,
		ErrorHandler:      iammiddleware.GlobalErrorHandler,
		Concurrency:       server.maxConnections,
		ReadBufferSize:    requestHeaderMaxSize,
		StreamRequestBody: false,
	})

	server.app = app
	server.Router.app = app
	server.Router.rootCreds = server.rootCreds
	server.Router.oidcThumbprintAutoFetchDisabled = server.oidcThumbprintAutoFetchDisabled

	app.Use("*", recover.New(recover.Config{
		EnableStackTrace:  true,
		StackTraceHandler: iammiddleware.StackTraceHandler,
	}))

	if !server.quiet {
		app.Use("*", logger.New(logger.Config{
			Format: "${time} | vgw-iam | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error} | ${queryParams}\n",
		}))
	}

	app.Use("*", iammiddleware.RequestIDs())

	if server.health != "" {
		app.Get(server.health, func(ctx fiber.Ctx) error {
			return ctx.SendStatus(http.StatusOK)
		})
	}

	if server.maxRequests > 0 {
		app.Use("*", iammiddleware.RateLimiter(server.maxRequests))
	}

	if debuglogger.IsDebugEnabled() {
		app.Use("*", iammiddleware.DebugLogger())
	}

	server.Router.Init()

	return server, nil
}

type Option func(*IAMApiServer)

func WithTLS(cs *CertStorage) Option {
	return func(s *IAMApiServer) { s.CertStorage = cs }
}

func WithQuiet() Option {
	return func(s *IAMApiServer) { s.quiet = true }
}

func WithHealth(health string) Option {
	return func(s *IAMApiServer) { s.health = health }
}

func WithKeepAlive() Option {
	return func(s *IAMApiServer) { s.keepAlive = true }
}

func WithConcurrencyLimiter(maxConnections, maxRequests int) Option {
	return func(s *IAMApiServer) {
		s.maxConnections = maxConnections
		s.maxRequests = maxRequests
	}
}

func WithSocketPerm(perm os.FileMode) Option {
	return func(s *IAMApiServer) { s.socketPerm = perm }
}

func WithOnListen(fn func()) Option {
	return func(s *IAMApiServer) { s.onListen = fn }
}

func WithRootUserCreds(root RootCredentials) Option {
	return func(s *IAMApiServer) {
		s.rootCreds = &root
	}
}

// WithOIDCThumbprintAutoFetchDisabled disables CreateOpenIDConnectProvider's
// TLS auto-fetch fallback for when ThumbprintList is omitted. When set, an
// omitted ThumbprintList is rejected with a MissingValue error instead of
// the gateway making an outbound TLS connection to the caller-supplied URL
// — an operational safety valve for restricted/air-gapped deployments.
func WithOIDCThumbprintAutoFetchDisabled() Option {
	return func(s *IAMApiServer) { s.oidcThumbprintAutoFetchDisabled = true }
}

func (s *IAMApiServer) ServeMultiPort(ports []string) error {
	if len(ports) == 0 {
		return fmt.Errorf("no ports specified")
	}

	var listeners []net.Listener
	for _, portSpec := range ports {
		var ln net.Listener
		var err error

		if s.CertStorage != nil {
			ln, err = netutil.NewMultiAddrTLSListener(fiber.NetworkTCP, portSpec, s.CertStorage.GetCertificate, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		} else {
			ln, err = netutil.NewMultiAddrListener(fiber.NetworkTCP, portSpec, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		}
		if err != nil {
			return fmt.Errorf("failed to bind iam listener %s: %w", portSpec, err)
		}

		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to create any iam listeners")
	}

	finalListener := netutil.NewMultiListener(listeners...)

	if s.onListen != nil {
		fn := s.onListen
		s.app.Hooks().OnListen(func(fiber.ListenData) error {
			fn()
			return nil
		})
	}

	return s.app.Listener(finalListener, fiber.ListenConfig{
		DisableStartupMessage: true,
	})
}

func (s *IAMApiServer) Shutdown() error {
	return s.app.ShutdownWithTimeout(shutDownDuration)
}
