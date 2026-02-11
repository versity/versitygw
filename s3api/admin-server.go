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
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
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
	port            string
	CertStorage     *utils.CertStorage
	quiet           bool
	debug           bool
	corsAllowOrigin string
}

func NewAdminServer(be backend.Backend, root middlewares.RootUserConfig, port, region string, iam auth.IAMService, l s3log.AuditLogger, ctrl controllers.S3ApiController, opts ...AdminOpt) *S3AdminServer {
	server := &S3AdminServer{
		backend: be,
		router: &S3AdminRouter{
			s3api: ctrl,
		},
		port: port,
	}

	for _, opt := range opts {
		opt(server)
	}

	app := fiber.New(fiber.Config{
		AppName:      "versitygw",
		ServerHeader: "VERSITYGW",
		ErrorHandler: globalErrorHandler,
	})

	server.app = app

	app.Use("*", recover.New(
		recover.Config{
			EnableStackTrace:  true,
			StackTraceHandler: stackTraceHandler,
		}))

	// Logging middlewares
	if !server.quiet {
		app.Use("*", logger.New(logger.Config{
			Format: "${time} | adm | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error} | ${queryParams}\n",
		}))
	}
	app.Use("*", controllers.WrapMiddleware(middlewares.DecodeURL, l, nil))

	// initialize the debug logger in debug mode
	if debuglogger.IsDebugEnabled() {
		app.Use("*", middlewares.DebugLogger())
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

func (sa *S3AdminServer) Serve() (err error) {
	if sa.CertStorage != nil {
		ln, err := utils.NewTLSListener(fiber.NetworkTCP, sa.port, sa.CertStorage.GetCertificate)
		if err != nil {
			return err
		}

		return sa.app.Listener(ln,
			fiber.ListenConfig{
				ListenerNetwork:       fiber.NetworkTCP,
				DisableStartupMessage: true,
			})
	}
	return sa.app.Listen(sa.port,
		fiber.ListenConfig{
			ListenerNetwork:       fiber.NetworkTCP,
			DisableStartupMessage: true,
		})
}

// ShutDown gracefully shuts down the server with a context timeout
func (sa S3AdminServer) Shutdown() error {
	return sa.app.ShutdownWithTimeout(shutDownDuration)
}
