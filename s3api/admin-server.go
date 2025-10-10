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
	"crypto/tls"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3log"
)

type S3AdminServer struct {
	app     *fiber.App
	backend backend.Backend
	router  *S3AdminRouter
	port    string
	cert    *tls.Certificate
	quiet   bool
	debug   bool
}

func NewAdminServer(be backend.Backend, root middlewares.RootUserConfig, port, region string, iam auth.IAMService, l s3log.AuditLogger, opts ...AdminOpt) *S3AdminServer {
	server := &S3AdminServer{
		backend: be,
		router:  new(S3AdminRouter),
		port:    port,
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
			Format: "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error} | ${queryParams}\n",
		}))
	}
	app.Use(controllers.WrapMiddleware(middlewares.DecodeURL, l, nil))
	app.Use(middlewares.DebugLogger())

	server.router.Init(app, be, iam, l, root, region, server.debug)

	return server
}

type AdminOpt func(s *S3AdminServer)

func WithAdminSrvTLS(cert tls.Certificate) AdminOpt {
	return func(s *S3AdminServer) { s.cert = &cert }
}

// WithQuiet silences default logging output
func WithAdminQuiet() AdminOpt {
	return func(s *S3AdminServer) { s.quiet = true }
}

// WithAdminDebug enables the debug logging
func WithAdminDebug() AdminOpt {
	return func(s *S3AdminServer) { s.debug = true }
}

func (sa *S3AdminServer) Serve() (err error) {
	if sa.cert != nil {
		return sa.app.ListenTLSWithCertificate(sa.port, *sa.cert)
	}
	return sa.app.Listen(sa.port)
}

// ShutDown gracefully shuts down the server with a context timeout
func (sa S3AdminServer) Shutdown() error {
	return sa.app.ShutdownWithTimeout(shutDownDuration)
}
