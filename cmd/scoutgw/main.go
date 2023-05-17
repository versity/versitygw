package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3api"
	"log"
)

func main() {
	app := fiber.New(fiber.Config{})
	back := backend.New()
	if api, err := s3api.New(app, back, ":7070"); err != nil {
		log.Fatalln(err)
	} else if err = api.Serve(); err != nil {
		log.Fatalln(err)
	}
}
