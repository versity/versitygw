package s3api

import (
	"encoding/xml"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3response"
)

type S3ApiServer struct {
	app     *fiber.App
	backend backend.Backend
	router  *S3ApiRouter
	port    string
}

func New(app *fiber.App, be backend.Backend, port string) (s3ApiServer *S3ApiServer, err error) {
	s3ApiServer = &S3ApiServer{app, be, new(S3ApiRouter), port}

	app.Use(logger.New())

	s3ApiServer.router.Init(app, be)
	app.All("/*", func(ctx *fiber.Ctx) error {

		fmt.Println(ctx.Method())
		listBucket := new(s3response.ListBucket)
		if b, err := xml.Marshal(listBucket); err != nil {
			return err
		} else {
			return ctx.Send(b)
		}
	})
	return
}

func (sa *S3ApiServer) Serve() (err error) {
	return sa.app.Listen(sa.port)
}
