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

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
)

// Server is the static website hosting endpoint.
type Server struct {
	app         *fiber.App
	CertStorage *utils.CertStorage
	domain      string
	quiet       bool
}

// Option sets various options for NewServer().
type Option func(*Server)

// WithQuiet silences default logging output.
func WithQuiet() Option {
	return func(s *Server) { s.quiet = true }
}

// WithTLS sets TLS credentials.
func WithTLS(cs *utils.CertStorage) Option {
	return func(s *Server) { s.CertStorage = cs }
}

// NewServer creates a new static website hosting server.
// The domain parameter is the base domain for virtual-host routing:
//   - Host "blog.<domain>" resolves to bucket "blog"
//   - Host "<domain>" (apex, no subdomain) resolves to bucket "<domain>"
func NewServer(be backend.Backend, domain string, opts ...Option) *Server {
	app := fiber.New(fiber.Config{
		AppName:               "versitygw-website",
		ServerHeader:          "VERSITYGW",
		DisableStartupMessage: true,
		Network:               fiber.NetworkTCP,
	})

	server := &Server{
		app:    app,
		domain: domain,
	}

	for _, opt := range opts {
		opt(server)
	}

	domainInfo := "catch-all"
	if domain != "" {
		domainInfo = "domain: " + domain
	}
	fmt.Printf("initializing website endpoint (%s)\n", domainInfo)

	// Panic recovery
	app.Use(recover.New())

	// Request logging
	if !server.quiet {
		app.Use(logger.New(logger.Config{
			Format: "${time} | website | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
		}))
	}

	// All requests go through the website handler
	app.Use(newHandler(be, domain))

	return server
}

// ServeMultiPort creates listeners for multiple address specifications and serves
// on all of them simultaneously.
func (s *Server) ServeMultiPort(ports []string) error {
	if len(ports) == 0 {
		return fmt.Errorf("no addresses specified")
	}

	var listeners []net.Listener

	for _, addrSpec := range ports {
		var ln net.Listener
		var err error

		if s.CertStorage != nil {
			ln, err = utils.NewMultiAddrTLSListener(s.app.Config().Network, addrSpec, s.CertStorage.GetCertificate)
		} else {
			ln, err = utils.NewMultiAddrListener(s.app.Config().Network, addrSpec)
		}

		if err != nil {
			return fmt.Errorf("failed to bind website listener %s: %w", addrSpec, err)
		}

		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to create any website listeners")
	}

	finalListener := utils.NewMultiListener(listeners...)

	return s.app.Listener(finalListener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}
