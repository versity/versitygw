package s3api

import (
	"crypto/tls"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/versity/versitygw/backend"
)

type S3ApiServer struct {
	app     *fiber.App
	backend backend.Backend
	router  *S3ApiRouter
	port    string
	cert    *tls.Certificate
}

func New(app *fiber.App, be backend.Backend, port string, opts ...Option) (*S3ApiServer, error) {
	server := &S3ApiServer{
		app:     app,
		backend: be,
		router:  new(S3ApiRouter),
		port:    port,
	}

	for _, opt := range opts {
		opt(server)
	}

	app.Use(logger.New())
	server.router.Init(app, be)
	return server, nil
}

// Option sets various options for New()
type Option func(*S3ApiServer)

// WithTLS sets TLS Credentials
func WithTLS(cert tls.Certificate) Option {
	return func(s *S3ApiServer) { s.cert = &cert }
}

func (sa *S3ApiServer) Serve() (err error) {
	if sa.cert != nil {
		return sa.app.ListenTLSWithCertificate(sa.port, *sa.cert)
	}
	return sa.app.Listen(sa.port)
}
