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
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

type S3ApiServer struct {
	app           *fiber.App
	backend       backend.Backend
	router        *S3ApiRouter
	port          string
	cert          *tls.Certificate
	quiet         bool
	readonly      bool
	keepAlive     bool
	health        string
	virtualDomain string
}

func New(
	be backend.Backend,
	root middlewares.RootUserConfig,
	port, region string,
	iam auth.IAMService,
	l s3log.AuditLogger,
	adminLogger s3log.AuditLogger,
	evs s3event.S3EventSender,
	mm metrics.Manager,
	opts ...Option,
) (*S3ApiServer, error) {
	server := &S3ApiServer{
		backend: be,
		router:  new(S3ApiRouter),
		port:    port,
	}

	for _, opt := range opts {
		opt(server)
	}

	app := fiber.New(fiber.Config{
		AppName:               "versitygw",
		ServerHeader:          "VERSITYGW",
		StreamRequestBody:     true,
		DisableKeepalive:      !server.keepAlive,
		Network:               fiber.NetworkTCP,
		DisableStartupMessage: true,
		ErrorHandler:          globalErrorHandler,
	})

	server.app = app

	// initialize the panic recovery middleware
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
	// Set up health endpoint if specified
	if server.health != "" {
		app.Get(server.health, func(ctx *fiber.Ctx) error {
			return ctx.SendStatus(http.StatusOK)
		})
	}

	// initilaze the default value setter middleware
	app.Use(middlewares.SetDefaultValues(root, region))

	// initialize the 'DecodeURL' middleware which
	// path unescapes the url
	app.Use(controllers.WrapMiddleware(middlewares.DecodeURL, l, mm))

	// initialize host-style parser in virtual domain is specified
	if server.virtualDomain != "" {
		app.Use(middlewares.HostStyleParser(server.virtualDomain))
	}

	// initialize the debug logger in debug mode
	if debuglogger.IsDebugEnabled() {
		app.Use(middlewares.DebugLogger())
	}

	server.router.Init(app, be, iam, l, adminLogger, evs, mm, server.readonly, region, root)

	return server, nil
}

// Option sets various options for New()
type Option func(*S3ApiServer)

// WithTLS sets TLS Credentials
func WithTLS(cert tls.Certificate) Option {
	return func(s *S3ApiServer) { s.cert = &cert }
}

// WithAdminServer runs admin endpoints with the gateway in the same network
func WithAdminServer() Option {
	return func(s *S3ApiServer) { s.router.WithAdmSrv = true }
}

// WithQuiet silences default logging output
func WithQuiet() Option {
	return func(s *S3ApiServer) { s.quiet = true }
}

// WithHealth sets up a GET health endpoint
func WithHealth(health string) Option {
	return func(s *S3ApiServer) { s.health = health }
}

func WithReadOnly() Option {
	return func(s *S3ApiServer) { s.readonly = true }
}

// WithHostStyle enabled host-style bucket addressing on the server
func WithHostStyle(virtualDomain string) Option {
	return func(s *S3ApiServer) { s.virtualDomain = virtualDomain }
}

// WithKeepAlive enables the server keep alive
func WithKeepAlive() Option {
	return func(s *S3ApiServer) { s.keepAlive = true }
}

func (sa *S3ApiServer) Serve() (err error) {
	if sa.cert != nil {
		return sa.app.ListenTLSWithCertificate(sa.port, *sa.cert)
	}
	return sa.app.Listen(sa.port)
}

// stackTraceHandler stores the system panics
// in the context locals
func stackTraceHandler(ctx *fiber.Ctx, e any) {
	utils.ContextKeyStack.Set(ctx, e)
}

// globalErrorHandler catches the errors before reaching to
// the handlers and any system panics
func globalErrorHandler(ctx *fiber.Ctx, er error) error {
	if utils.ContextKeyStack.IsSet(ctx) {
		// if stack is set, it means the stack trace
		// has caught a panic
		// log it as a panic log
		debuglogger.Panic(er)
	} else {
		// handle the fiber specific errors
		var fiberErr *fiber.Error
		if errors.As(er, &fiberErr) {
			if strings.Contains(fiberErr.Message, "cannot parse Content-Length") {
				ctx.Status(http.StatusBadRequest)
				return nil
			}
		}

		// additionally log the internal error
		debuglogger.InernalError(er)
	}

	ctx.Status(http.StatusInternalServerError)

	return ctx.Send(s3err.GetAPIErrorResponse(
		s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
}
