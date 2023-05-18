package s3api

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
)

func TestS3ApiRouter_Init(t *testing.T) {
	type args struct {
		app *fiber.App
		be  backend.Backend
	}
	tests := []struct {
		name string
		sa   *S3ApiRouter
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.sa.Init(tt.args.app, tt.args.be)
		})
	}
}
