package middlewares

import (
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/s3api/utils"
)

func CheckUserCreds(user utils.RootUser) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		return ctx.Next()
	}
}
