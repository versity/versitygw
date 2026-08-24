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
	"io/fs"
	"net"
	"os"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/etag"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/versity/versitygw/internal/netutil"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	Gateways      []string // S3 API gateways
	AdminGateways []string // Admin API gateways (defaults to Gateways if empty)
	// IAMGateways are standalone IAM service (versitygw iam) endpoints, used
	// to seed the WebUI's optional IAM endpoint field. Unlike AdminGateways
	// there is no fallback to Gateways: the IAM service is a separate
	// process, so empty means "no IAM endpoint to offer".
	IAMGateways []string
	Region      string
	CORSOrigin  string
}

// Server is the main GUI server
type Server struct {
	app         *fiber.App
	CertStorage *netutil.CertStorage
	config      *ServerConfig
	pathPrefix  string
	quiet       bool
	socketPerm  os.FileMode
}

// Option sets various options for NewServer()
type Option func(*Server)

// WithQuiet silences default logging output.
func WithQuiet() Option {
	return func(s *Server) { s.quiet = true }
}

// WithTLS sets TLS Credentials
func WithTLS(cs *netutil.CertStorage) Option {
	return func(s *Server) { s.CertStorage = cs }
}

// WithPathPrefix mounts the entire web UI under the given path prefix
func WithPathPrefix(prefix string) Option {
	return func(s *Server) { s.pathPrefix = prefix }
}

// WithSocketPerm sets the file-mode permissions applied to file-backed UNIX
// domain sockets after binding. It has no effect on TCP/IP or abstract
// namespace sockets.
func WithSocketPerm(perm os.FileMode) Option {
	return func(s *Server) { s.socketPerm = perm }
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

	fmt.Printf("initializing web dashboard\n")

	server.setupMiddleware()
	if err := server.setupRoutes(); err != nil {
		return nil, err
	}

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
	prefix := s.pathPrefix

	// Must come before the routes it applies to: a Use() registered after a
	// matching route never runs, since those handlers don't call Next().
	s.app.Use(prefix+"/", s.revalidateAssets)
	s.app.Use(prefix+"/", etag.New())

	// Serve index.html with server-side config injection
	s.app.Get(prefix+"/", s.handleIndexHTML)
	s.app.Get(prefix+"/index.html", s.handleIndexHTML)

	staticFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("initialize embedded web UI filesystem: %w", err)
	}

	// Serve embedded static files from web/.
	s.app.Use(prefix+"/", static.New("", static.Config{
		FS:     staticFS,
		Browse: false,
	}))

	// Catch-all: absorb any request the static middleware did not fully handle.
	s.app.Use(prefix+"/", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusBadRequest)
	})

	return nil
}

// revalidateAssets makes browsers check back with the gateway before reusing a
// cached copy of the web UI.
//
// The UI is embedded in the binary, so its files go out stamped with the zero
// modification time. With no Cache-Control to go on, a browser's heuristic
// freshness rule turns that apparent age into a centuries-long expiry, and an
// upgraded gateway ends up serving new HTML against stale cached assets.
// no-cache keeps the copy but forces revalidation, which the ETag middleware
// answers with a 304 when the file has not changed.
func (s *Server) revalidateAssets(c fiber.Ctx) error {
	if err := c.Next(); err != nil {
		return err
	}

	c.Response().Header.Del(fiber.HeaderLastModified)
	c.Set(fiber.HeaderCacheControl, "no-cache")

	return nil
}

// handleIndexHTML serves index.html with server config injected as an inline script.
func (s *Server) handleIndexHTML(c fiber.Ctx) error {
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
		"iamGateways":   s.config.IAMGateways,
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
			ln, err = netutil.NewMultiAddrTLSListener(fiber.NetworkTCP, addrSpec, s.CertStorage.GetCertificate, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		} else {
			ln, err = netutil.NewMultiAddrListener(fiber.NetworkTCP, addrSpec, netutil.ListenerOptions{SocketPerm: s.socketPerm})
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
	finalListener := netutil.NewMultiListener(listeners...)

	return s.app.Listener(finalListener, fiber.ListenConfig{
		DisableStartupMessage: true,
	})
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}

// MountOn registers the WebUI routes on an existing Fiber app at the given path prefix.
// This allows hosting the WebUI on the same port as another service (e.g. the S3 API server).
// The prefix must start with "/" and must not be empty or just "/".
func MountOn(app *fiber.App, prefix string, cfg *ServerConfig) error {
	s := &Server{
		app:        app,
		config:     cfg,
		pathPrefix: prefix,
	}
	fmt.Printf("initializing web dashboard\n")
	return s.setupRoutes()
}
