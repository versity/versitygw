package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3api"
	"github.com/versity/scoutgw/s3api/utils"
)

func main() {
	app := fiber.New(fiber.Config{})
	back := backend.New()
	rootUser := utils.GetRootUserCreds()
	if api, err := s3api.New(app, back, ":7070", rootUser); err != nil {
		log.Fatalln(err)
	} else if err = api.Serve(); err != nil {
		log.Fatalln(err)
	}
}
