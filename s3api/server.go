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
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/middlewares"
)

type S3ApiServer struct {
	app     *fiber.App
	backend backend.Backend
	router  *S3ApiRouter
	port    string
	cert    *tls.Certificate
	debug   bool
}

func New(app *fiber.App, be backend.Backend, root middlewares.RootUserConfig, port, region string, iam auth.IAMService, opts ...Option) (*S3ApiServer, error) {
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
	app.Use(logger.New())
	app.Use(middlewares.RequestLogger(server.debug))

	// Authentication middlewares
	app.Use(middlewares.VerifyV4Signature(root, iam, region, server.debug))
	app.Use(middlewares.VerifyMD5Body())

	server.router.Init(app, be, iam)

	return server, nil
}

// Option sets various options for New()
type Option func(*S3ApiServer)

// WithTLS sets TLS Credentials
func WithTLS(cert tls.Certificate) Option {
	return func(s *S3ApiServer) { s.cert = &cert }
}

// WithDebug sets debug output
func WithDebug() Option {
	return func(s *S3ApiServer) { s.debug = true }
}

func (sa *S3ApiServer) Serve() (err error) {
	if sa.cert != nil {
		return sa.app.ListenTLSWithCertificate(sa.port, *sa.cert)
	}
	return sa.app.Listen(sa.port)
}
