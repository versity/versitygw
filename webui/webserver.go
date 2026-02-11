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

package webui

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/versity/versitygw/s3api/utils"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	ListenAddr    string
	Gateways      []string // S3 API gateways
	AdminGateways []string // Admin API gateways (defaults to Gateways if empty)
	Region        string
	CORSOrigin    string
}

// Server is the main GUI server
type Server struct {
	app         *fiber.App
	CertStorage *utils.CertStorage
	config      *ServerConfig
	quiet       bool
}

// Option sets various options for NewServer()
type Option func(*Server)

// WithQuiet silences default logging output.
func WithQuiet() Option {
	return func(s *Server) { s.quiet = true }
}

// WithTLS sets TLS Credentials
func WithTLS(cs *utils.CertStorage) Option {
	return func(s *Server) { s.CertStorage = cs }
}

// NewServer creates a new GUI server instance
func NewServer(cfg *ServerConfig, opts ...Option) (*Server, error) {
	app := fiber.New(fiber.Config{
		AppName:      "versitygw",
		ServerHeader: "VERSITYGW",
	})

	server := &Server{
		app:    app,
		config: cfg,
	}

	for _, opt := range opts {
		opt(server)
	}

	server.setupMiddleware()
	err := server.setupRoutes()
	if err != nil {
		return nil, err
	}

	fmt.Printf("initializing web dashboard on %s\n", cfg.ListenAddr)

	return server, nil
}

// setupMiddleware configures middleware
func (s *Server) setupMiddleware() {
	// Panic recovery
	s.app.Use("*", recover.New())

	// Request logging
	if !s.quiet {
		s.app.Use("*", logger.New(logger.Config{
			Format: "${time} | web | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
		}))
	}
}

// setupRoutes configures all routes
func (s *Server) setupRoutes() error {
	// API endpoint to get configured gateways
	s.app.Get("/api/gateways", s.handleGetGateways)

	// create a subtree from 'web' directory
	// so that routing works correctly
	// currently there's a bug in fasthttp resolving fs root
	// https://github.com/valyala/fasthttp/issues/2141
	// TODO: remove sub fs after the bug fix
	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}

	s.app.Use("/", static.New("", static.Config{
		FS:         subFS,
		Browse:     false,
		IndexNames: []string{"index.html"},
	}))

	return nil
}

// handleGetGateways returns the configured gateway URLs (both S3 and Admin)
func (s *Server) handleGetGateways(c fiber.Ctx) error {
	adminGateways := s.config.AdminGateways
	if len(adminGateways) == 0 {
		// Fallback to S3 gateways if admin gateways not configured
		adminGateways = s.config.Gateways
	}

	return c.JSON(fiber.Map{
		"gateways":      s.config.Gateways,
		"adminGateways": adminGateways,
		"defaultRegion": s.config.Region,
	})
}

// Serve starts the server
func (s *Server) Serve() error {
	addr := strings.TrimSpace(s.config.ListenAddr)
	if addr == "" {
		return fmt.Errorf("webui: listen address is required")
	}

	// Check if TLS is configured
	if s.CertStorage != nil {
		ln, err := utils.NewTLSListener(fiber.NetworkTCP, addr, s.CertStorage.GetCertificate)
		if err != nil {
			return err
		}

		return s.app.Listener(ln,
			fiber.ListenConfig{
				ListenerNetwork:       fiber.NetworkTCP,
				DisableStartupMessage: true,
			})
	}

	return s.app.Listen(addr,
		fiber.ListenConfig{
			ListenerNetwork:       fiber.NetworkTCP,
			DisableStartupMessage: true,
		})
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}
