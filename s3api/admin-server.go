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
	"fmt"
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3log"
)

type S3AdminServer struct {
	app             *fiber.App
	backend         backend.Backend
	router          *S3AdminRouter
	CertStorage     *utils.CertStorage
	quiet           bool
	debug           bool
	corsAllowOrigin string
	maxConnections  int
	maxRequests     int
}

func NewAdminServer(be backend.Backend, root middlewares.RootUserConfig, region string, iam auth.IAMService, l s3log.AuditLogger, ctrl controllers.S3ApiController, opts ...AdminOpt) *S3AdminServer {
	server := &S3AdminServer{
		backend: be,
		router: &S3AdminRouter{
			s3api: ctrl,
		},
	}

	for _, opt := range opts {
		opt(server)
	}

	app := fiber.New(fiber.Config{
		AppName:               "versitygw",
		ServerHeader:          "VERSITYGW",
		Network:               fiber.NetworkTCP,
		DisableStartupMessage: true,
		ErrorHandler:          globalErrorHandler,
		Concurrency:           server.maxConnections,
	})

	server.app = app

	app.Use(recover.New(
		recover.Config{
			EnableStackTrace:  true,
			StackTraceHandler: stackTraceHandler,
		}))

	// Logging middlewares
	if !server.quiet {
		app.Use(logger.New(logger.Config{
			Format: "${time} | adm | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error} | ${queryParams}\n",
		}))
	}

	// initialize total requests cap limiter middleware
	app.Use(middlewares.RateLimiter(server.maxRequests, nil, l))

	app.Use(controllers.WrapMiddleware(middlewares.DecodeURL, l, nil))

	// initialize the debug logger in debug mode
	if debuglogger.IsDebugEnabled() {
		app.Use(middlewares.DebugLogger())
	}

	server.router.Init(app, be, iam, l, root, region, server.debug, server.corsAllowOrigin)

	return server
}

type AdminOpt func(s *S3AdminServer)

func WithAdminSrvTLS(cs *utils.CertStorage) AdminOpt {
	return func(s *S3AdminServer) { s.CertStorage = cs }
}

// WithQuiet silences default logging output
func WithAdminQuiet() AdminOpt {
	return func(s *S3AdminServer) { s.quiet = true }
}

// WithAdminDebug enables the debug logging
func WithAdminDebug() AdminOpt {
	return func(s *S3AdminServer) { s.debug = true }
}

// WithAdminCORSAllowOrigin sets the default CORS Access-Control-Allow-Origin value
// for the standalone admin server.
func WithAdminCORSAllowOrigin(origin string) AdminOpt {
	return func(s *S3AdminServer) { s.corsAllowOrigin = origin }
}

// WithAdminConcurrencyLimiter sets the admin standalone server's maximum
// connection limit and the hard limit for in-flight requests.
func WithAdminConcurrencyLimiter(maxConnections, maxRequests int) AdminOpt {
	return func(s *S3AdminServer) {
		s.maxConnections = maxConnections
		s.maxRequests = maxRequests
	}
}

// ServeMultiPort creates listeners for multiple port specifications and serves
// on all of them simultaneously. This supports listening on multiple ports and/or
// addresses (e.g., [":8080", "localhost:8081"]).
func (sa *S3AdminServer) ServeMultiPort(ports []string) error {
	if len(ports) == 0 {
		return fmt.Errorf("no ports specified")
	}

	// Multiple ports - create listeners for each
	var listeners []net.Listener

	for _, portSpec := range ports {
		var ln net.Listener
		var err error

		if sa.CertStorage != nil {
			ln, err = utils.NewMultiAddrTLSListener(sa.app.Config().Network, portSpec, sa.CertStorage.GetCertificate)
		} else {
			ln, err = utils.NewMultiAddrListener(sa.app.Config().Network, portSpec)
		}

		if err != nil {
			return fmt.Errorf("failed to bind admin listener %s: %w", portSpec, err)
		}

		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to create any admin listeners")
	}

	// Combine all listeners
	finalListener := utils.NewMultiListener(listeners...)

	return sa.app.Listener(finalListener)
}

// ShutDown gracefully shuts down the server with a context timeout
func (sa S3AdminServer) Shutdown() error {
	return sa.app.ShutdownWithTimeout(shutDownDuration)
}
