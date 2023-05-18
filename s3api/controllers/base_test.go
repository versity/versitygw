package controllers

import (
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3err"
)

func TestNew(t *testing.T) {
	type args struct {
		be backend.Backend
	}
	tests := []struct {
		name string
		args args
		want S3ApiController
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.be); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestS3ApiController_ListBuckets(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.ListBuckets(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.ListBuckets() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_GetActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.GetActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.GetActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_ListActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.ListActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.ListActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_PutBucketActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.PutBucketActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.PutBucketActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_PutActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.PutActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.PutActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_DeleteBucket(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteBucket(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.DeleteBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_DeleteObjects(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteObjects(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.DeleteObjects() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_DeleteActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.DeleteActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_HeadBucket(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.HeadBucket(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.HeadBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_HeadObject(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.HeadObject(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.HeadObject() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_CreateActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.CreateActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.CreateActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_responce(t *testing.T) {
	type args struct {
		ctx  *fiber.Ctx
		resp any
		code s3err.ErrorCode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := responce(tt.args.ctx, tt.args.resp, tt.args.code); (err != nil) != tt.wantErr {
				t.Errorf("responce() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
