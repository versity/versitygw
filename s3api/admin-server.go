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
	"github.com/versity/versitygw/s3log"
)

type S3AdminServer struct {
	app     *fiber.App
	backend backend.Backend
	router  *S3AdminRouter
	port    string
	cert    *tls.Certificate
}

func NewAdminServer(app *fiber.App, be backend.Backend, root middlewares.RootUserConfig, port, region string, iam auth.IAMService, l s3log.AuditLogger, opts ...AdminOpt) *S3AdminServer {
	server := &S3AdminServer{
		app:     app,
		backend: be,
		router:  new(S3AdminRouter),
		port:    port,
	}

	for _, opt := range opts {
		opt(server)
	}

	// Logging middlewares
	app.Use(logger.New())
	app.Use(middlewares.DecodeURL(l, nil))

	// Authentication middlewares
	app.Use(middlewares.VerifyV4Signature(root, iam, l, nil, region, false))
	app.Use(middlewares.VerifyMD5Body(l))

	// Admin role checker
	app.Use(middlewares.IsAdmin(l))

	server.router.Init(app, be, iam, l)

	return server
}

type AdminOpt func(s *S3AdminServer)

func WithAdminSrvTLS(cert tls.Certificate) AdminOpt {
	return func(s *S3AdminServer) { s.cert = &cert }
}

func (sa *S3AdminServer) Serve() (err error) {
	if sa.cert != nil {
		return sa.app.ListenTLSWithCertificate(sa.port, *sa.cert)
	}
	return sa.app.Listen(sa.port)
}
