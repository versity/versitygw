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

package website

import (
	"fmt"
	"net"
	"os"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/internal/httpctx"
	"github.com/versity/versitygw/internal/netutil"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
)

// Server is the static website hosting endpoint.
type Server struct {
	app            *fiber.App
	CertStorage    *netutil.CertStorage
	domain         string
	quiet          bool
	socketPerm     os.FileMode
	clientIPHeader string
	trustedProxies utils.TrustedProxies
	// clientIPHeaderErr holds an invalid WithClientIPHeader value; NewServer
	// has no error return, so ServeMultiPort reports it at startup rather
	// than logging the socket address silently.
	clientIPHeaderErr error
}

// Option sets various options for NewServer().
type Option func(*Server)

// WithQuiet silences default logging output.
func WithQuiet() Option {
	return func(s *Server) { s.quiet = true }
}

// WithTLS sets TLS credentials.
func WithTLS(cs *netutil.CertStorage) Option {
	return func(s *Server) { s.CertStorage = cs }
}

// WithSocketPerm sets the file-mode permissions applied to file-backed UNIX
// domain sockets after binding. It has no effect on TCP/IP or abstract
// namespace sockets.
func WithSocketPerm(perm os.FileMode) Option {
	return func(s *Server) { s.socketPerm = perm }
}

// WithClientIPHeader records the client address from the named proxy header in
// the website request log. The accepted values are
// utils.ClientIPHeaderForwardedFor and utils.ClientIPHeaderRealIP; an empty
// value (the default) keeps the socket peer address. The header is only
// honoured from a peer listed in WithTrustedProxies.
func WithClientIPHeader(header string) Option {
	return func(s *Server) { s.clientIPHeader = header }
}

// WithTrustedProxies sets the peers whose client IP header is trusted, as
// parsed by utils.ParseTrustedProxies. It only has an effect together with
// WithClientIPHeader.
func WithTrustedProxies(trusted utils.TrustedProxies) Option {
	return func(s *Server) { s.trustedProxies = trusted }
}

// NewServer creates a new static website hosting server.
// The domain parameter is the base domain for virtual-host routing:
//   - Host "blog.<domain>" resolves to bucket "blog"
//   - Host "<domain>" (apex, no subdomain) resolves to bucket "<domain>"
func NewServer(be backend.Backend, domain string, opts ...Option) *Server {
	app := fiber.NewWithCustomCtx(httpctx.NewCtx, fiber.Config{
		AppName:      "versitygw-website",
		ServerHeader: "VERSITYGW",
	})

	server := &Server{
		app:    app,
		domain: domain,
	}

	for _, opt := range opts {
		opt(server)
	}

	// validate the header here, so the request path can compare it directly
	// instead of re-normalizing on every request; an invalid value is
	// reported by ServeMultiPort
	if server.clientIPHeader != "" {
		header, err := utils.NormalizeClientIPHeader(server.clientIPHeader)
		if err != nil {
			server.clientIPHeaderErr = err
			server.clientIPHeader = ""
		} else {
			server.clientIPHeader = header
		}
	}

	domainInfo := "catch-all"
	if domain != "" {
		domainInfo = "domain: " + domain
	}

	// Panic recovery
	app.Use("*", recover.New())

	// Request logging
	if !server.quiet {
		fmt.Printf("initializing website endpoint (%s)\n", domainInfo)
		app.Use("*", logger.New(logger.Config{
			Format: "${time} | website | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
			CustomTags: map[string]logger.LogFunc{
				logger.TagIP: utils.ClientIPTag,
			},
		}))
	}

	// resolve the logged client address from a trusted proxy header, when
	// one is configured
	if server.clientIPHeader != "" {
		app.Use("*", utils.ClientIPMiddleware(server.clientIPHeader, server.trustedProxies))
	}

	// initialize the debug logger in debug mode
	if debuglogger.IsDebugEnabled() {
		app.Use("*", middlewares.DebugLogger())
	}

	registerWebsiteRoutes(app, be, domain)

	return server
}

// ServeMultiPort creates listeners for multiple address specifications and serves
// on all of them simultaneously.
func (s *Server) ServeMultiPort(ports []string) error {
	if s.clientIPHeaderErr != nil {
		return s.clientIPHeaderErr
	}
	if len(ports) == 0 {
		return fmt.Errorf("no addresses specified")
	}

	var listeners []net.Listener

	for _, addrSpec := range ports {
		var ln net.Listener
		var err error

		if s.CertStorage != nil {
			ln, err = netutil.NewMultiAddrTLSListener(fiber.NetworkTCP, addrSpec, s.CertStorage.GetCertificate, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		} else {
			ln, err = netutil.NewMultiAddrListener(fiber.NetworkTCP, addrSpec, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		}

		if err != nil {
			return fmt.Errorf("failed to bind website listener %s: %w", addrSpec, err)
		}

		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to create any website listeners")
	}

	finalListener := netutil.NewMultiListener(listeners...)

	return s.app.Listener(finalListener, fiber.ListenConfig{
		DisableStartupMessage: true,
	})
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}
