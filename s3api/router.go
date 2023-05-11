package s3api

import (
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/internal"
	"github.com/versity/scoutgw/s3err"
	"github.com/versity/scoutgw/s3response"
	"strings"
)

type S3ApiRouter struct {
	app *fiber.App
	api fiber.Router
}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend) {
	// ListBuckets action
	app.Get("/", func(ctx *fiber.Ctx) error {
		res, code := be.ListBuckets()
		return responce[internal.Any](ctx, res, code)
	})

	// PutBucket action
	app.Put("/:bucket", func(ctx *fiber.Ctx) error {
		code := be.PutBucket(ctx.Params("bucket"))
		return responce[internal.Any](ctx, nil, code)
	})
	// DeleteBucket action
	app.Delete("/:bucket", func(ctx *fiber.Ctx) error {
		code := be.DeleteBucket(ctx.Params("bucket"))
		return responce[internal.Any](ctx, nil, code)
	})

	// ListObjects action
	// ListObjectsV2 action
	app.Get("/:bucket", func(ctx *fiber.Ctx) error {
		listType := ctx.QueryInt("list-type")

		if listType == 2 {
			res, code := be.ListObjectsV2(ctx.Params("bucket"), "", "", "", 1)
			return responce[*s3response.ListBucketResultV2](ctx, res, code)
		} else {
			res, code := be.ListObjects(ctx.Params("bucket"), "", "", "", 1)
			return responce[*s3response.ListBucketResult](ctx, res, code)
		}
	})
	// DeleteObject action
	app.Delete("/:bucket/:key", func(ctx *fiber.Ctx) error {
		code := be.DeleteObject(ctx.Params("bucket"), ctx.Params("key"))
		return responce[internal.Any](ctx, nil, code)
	})
	// DeleteObjects action
	app.Post("/:bucket", func(ctx *fiber.Ctx) error {
		body := ctx.Body()

		fmt.Println(string(body))
		//todo: create type for body and pass to function parsed structure
		code := be.DeleteObjects(ctx.Params("bucket"), []string{})
		return responce[internal.Any](ctx, nil, code)
	})
	// CopyObject action
	app.Put("/:dstBucket/:dstKey/*", func(ctx *fiber.Ctx) error {
		copySource := strings.Split(ctx.Get("X-Amz-Copy-Source"), "/")
		if len(copySource) < 2 {
			return errors.New("wrong api call")
		}
		srcBucket, srcObject := copySource[0], copySource[1:]
		dstBucket, dstKeyStart, dstKeyEnd := ctx.Params("dstBucket"), ctx.Params("dstKey"), ctx.Params("*1")
		if dstKeyEnd != "" {
			dstKeyStart = strings.Join([]string{dstKeyStart, dstKeyEnd}, "/")
		}
		res, code := be.CopyObject(srcBucket, strings.Join(srcObject, "/"), dstBucket, dstKeyStart)
		return responce[*s3response.CopyObjectResponse](ctx, res, code)
	})
}

func responce[R comparable](ctx *fiber.Ctx, resp R, code s3err.ErrorCode) error {
	if code != 0 {
		err := s3err.GetAPIError(code)
		ctx.Status(err.HTTPStatusCode)
		return ctx.Send(s3err.GetAPIErrorResponse(err, "", "", ""))
	} else if b, err := xml.Marshal(resp); err != nil {
		return err
	} else {
		return ctx.Send(b)
	}
}
