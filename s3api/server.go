package s3api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3api/middlewares"
	"github.com/versity/scoutgw/s3api/utils"
)

type S3ApiServer struct {
	app     *fiber.App
	backend backend.Backend
	router  *S3ApiRouter
	port    string
}

func New(app *fiber.App, be backend.Backend, port string, rootUser utils.RootUser) (s3ApiServer *S3ApiServer, err error) {
	s3ApiServer = &S3ApiServer{app, be, new(S3ApiRouter), port}
	utils.GetRootUserCreds()

	app.Use(middlewares.CheckUserCreds(rootUser))
	app.Use(logger.New())
	s3ApiServer.router.Init(app, be)
	return
}

func (sa *S3ApiServer) Serve() (err error) {
	return sa.app.Listen(sa.port)
}
