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
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/middlewares"
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
	debug         bool
	readonly      bool
	health        string
	virtualDomain string
}

func New(
	app *fiber.App,
	be backend.Backend,
	root middlewares.RootUserConfig,
	port, region string,
	iam auth.IAMService,
	l s3log.AuditLogger,
	adminLogger s3log.AuditLogger,
	evs s3event.S3EventSender,
	mm *metrics.Manager,
	opts ...Option,
) (*S3ApiServer, error) {
	server := &S3ApiServer{
		app:     app,
		backend: be,
		router:  new(S3ApiRouter),
		port:    port,
	}

	for _, opt := range opts {
		opt(server)
	}

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
	app.Use(middlewares.DecodeURL(l, mm))

	// initialize host-style parser in virtual domain is specified
	if server.virtualDomain != "" {
		app.Use(middlewares.HostStyleParser(server.virtualDomain))
	}

	// initilaze the default value setter middleware
	app.Use(middlewares.SetDefaultValues(root, region))

	// initialize the debug logger in debug mode
	if server.debug {
		app.Use(middlewares.DebugLogger())
	}

	// initialize the bucket/object name validator
	app.Use(middlewares.BucketObjectNameValidator(l, mm))

	// Public buckets access checker
	app.Use(middlewares.AuthorizePublicBucketAccess(be, l, mm))

	// Authentication middlewares
	app.Use(middlewares.VerifyPresignedV4Signature(root, iam, l, mm, region, server.debug))
	app.Use(middlewares.VerifyV4Signature(root, iam, l, mm, region, server.debug))
	app.Use(middlewares.VerifyMD5Body(l))
	app.Use(middlewares.AclParser(be, l, server.readonly))

	server.router.Init(app, be, iam, l, adminLogger, evs, mm, server.debug, server.readonly)

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

// WithDebug sets debug output
func WithDebug() Option {
	return func(s *S3ApiServer) { s.debug = true }
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

func (sa *S3ApiServer) Serve() (err error) {
	if sa.cert != nil {
		return sa.app.ListenTLSWithCertificate(sa.port, *sa.cert)
	}
	return sa.app.Listen(sa.port)
}
