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
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	ListenAddr    string
	Gateways      []string // S3 API gateways
	AdminGateways []string // Admin API gateways (defaults to Gateways if empty)
	Region        string
	TLSCert       string
	TLSKey        string
	CORSOrigin    string
}

// Server is the main GUI server
type Server struct {
	app    *fiber.App
	config *ServerConfig
	quiet  bool
}

// Option sets various options for NewServer()
type Option func(*Server)

// WithQuiet silences default logging output.
func WithQuiet() Option {
	return func(s *Server) { s.quiet = true }
}

// NewServer creates a new GUI server instance
func NewServer(cfg *ServerConfig, opts ...Option) *Server {
	app := fiber.New(fiber.Config{
		AppName:               "versitygw",
		ServerHeader:          "VERSITYGW",
		DisableStartupMessage: true,
	})

	server := &Server{
		app:    app,
		config: cfg,
	}

	for _, opt := range opts {
		opt(server)
	}

	server.setupMiddleware()
	server.setupRoutes()

	fmt.Printf("initializing web dashboard on %s\n", cfg.ListenAddr)

	return server
}

// setupMiddleware configures middleware
func (s *Server) setupMiddleware() {
	// Panic recovery
	s.app.Use(recover.New())

	// Request logging
	if !s.quiet {
		s.app.Use(logger.New(logger.Config{
			Format: "${time} | web | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
		}))
	}
}

// setupRoutes configures all routes
func (s *Server) setupRoutes() {
	// API endpoint to get configured gateways
	s.app.Get("/api/gateways", s.handleGetGateways)

	// Serve embedded static files from web/
	s.app.Use("/", filesystem.New(filesystem.Config{
		Root:         http.FS(webFS),
		PathPrefix:   "web",
		Index:        "index.html",
		NotFoundFile: "index.html", // SPA fallback
		Browse:       false,
	}))
}

// handleGetGateways returns the configured gateway URLs (both S3 and Admin)
func (s *Server) handleGetGateways(c *fiber.Ctx) error {
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
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return s.app.ListenTLS(addr, s.config.TLSCert, s.config.TLSKey)
	}

	return s.app.Listen(addr)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}
