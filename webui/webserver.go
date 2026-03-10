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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/versity/versitygw/s3api/utils"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
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
	pathPrefix  string
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

// WithPathPrefix mounts the entire web UI under the given path prefix
func WithPathPrefix(prefix string) Option {
	return func(s *Server) { s.pathPrefix = prefix }
}

// NewServer creates a new GUI server instance
func NewServer(cfg *ServerConfig, opts ...Option) *Server {
	app := fiber.New(fiber.Config{
		AppName:               "versitygw",
		ServerHeader:          "VERSITYGW",
		DisableStartupMessage: true,
		Network:               fiber.NetworkTCP,
	})

	server := &Server{
		app:    app,
		config: cfg,
	}

	for _, opt := range opts {
		opt(server)
	}

	fmt.Printf("initializing web dashboard\n")

	server.setupMiddleware()
	server.setupRoutes()

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
	prefix := s.pathPrefix

	// Serve index.html with server-side config injection
	s.app.Get(prefix+"/", s.handleIndexHTML)
	s.app.Get(prefix+"/index.html", s.handleIndexHTML)

	// Serve embedded static files from web/
	s.app.Use(prefix+"/", filesystem.New(filesystem.Config{
		Root:       http.FS(webFS),
		PathPrefix: "web",
		Browse:     false,
	}))

	// Catch-all: absorb any request the filesystem did not fully handle.
	// The filesystem middleware calls Next() for non-GET/HEAD methods and for
	// paths not found in the embedded FS, which would otherwise fall through
	// to the S3 router and be interpreted as bucket/object operations.
	s.app.Use(prefix+"/", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusBadRequest)
	})
}

// handleIndexHTML serves index.html with server config injected as an inline script.
func (s *Server) handleIndexHTML(c *fiber.Ctx) error {
	data, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		return fiber.ErrInternalServerError
	}

	adminGateways := s.config.AdminGateways
	if len(adminGateways) == 0 {
		adminGateways = s.config.Gateways
	}

	configJSON, err := json.Marshal(map[string]any{
		"gateways":      s.config.Gateways,
		"adminGateways": adminGateways,
		"defaultRegion": s.config.Region,
	})
	if err != nil {
		return fiber.ErrInternalServerError
	}

	basePath := s.pathPrefix + "/"
	html := strings.Replace(string(data), "{{.BasePath}}", basePath, 1)
	html = strings.Replace(
		html,
		"</head>",
		"<script>window.__VGWCONFIG__ = "+string(configJSON)+";</script></head>",
		1,
	)

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.SendString(html)
}

// ServeMultiPort creates listeners for multiple address specifications and serves
// on all of them simultaneously. This supports listening on multiple addresses.
func (s *Server) ServeMultiPort(ports []string) error {
	if len(ports) == 0 {
		return fmt.Errorf("no addresses specified")
	}

	// Multiple addresses - create listeners for each
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
			return fmt.Errorf("failed to bind webui listener %s: %w", addrSpec, err)
		}

		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to create any webui listeners")
	}

	// Combine all listeners
	finalListener := utils.NewMultiListener(listeners...)

	return s.app.Listener(finalListener)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}

// MountOn registers the WebUI routes on an existing Fiber app at the given path prefix.
// This allows hosting the WebUI on the same port as another service (e.g. the S3 API server).
// The prefix must start with "/" and must not be empty or just "/".
func MountOn(app *fiber.App, prefix string, cfg *ServerConfig) {
	s := &Server{
		app:        app,
		config:     cfg,
		pathPrefix: prefix,
	}
	fmt.Printf("initializing web dashboard\n")
	s.setupRoutes()
}
