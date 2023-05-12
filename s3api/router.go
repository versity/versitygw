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
	"strconv"
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

	// HeadBucket
	app.Head("/:bucket", func(ctx *fiber.Ctx) error {
		res, code := be.HeadBucket(ctx.Params("bucket"))
		return responce[*s3response.HeadBucketResponse](ctx, res, code)
	})
	// GetBucketAcl action
	// ListObjects action
	// ListObjectsV2 action
	app.Get("/:bucket", func(ctx *fiber.Ctx) error {
		if ctx.Request().URI().QueryArgs().Has("acl") {
			res, code := be.GetBucketAcl(ctx.Params("bucket"))
			return responce[*s3response.GetBucketAclResponse](ctx, res, code)
		}

		if ctx.QueryInt("list-type") == 2 {
			res, code := be.ListObjectsV2(ctx.Params("bucket"), "", "", "", 1)
			return responce[*s3response.ListBucketResultV2](ctx, res, code)
		}

		res, code := be.ListObjects(ctx.Params("bucket"), "", "", "", 1)
		return responce[*s3response.ListBucketResult](ctx, res, code)
	})
	// GetObjectAcl action
	// GetObject action
	//todo: will continue HeadObject implementation
	app.Get("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		if ctx.Request().URI().QueryArgs().Has("acl") {
			res, code := be.GetObjectAcl(ctx.Params("bucket"), ctx.Params("key"))
			return responce[*s3response.GetObjectAccessControlPolicyResponse](ctx, res, code)
		}

		if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
			res, code := be.GetObjectAttributes(ctx.Params("bucket"), ctx.Params("key"), strings.Split(ctx.Get("key"), ","))
			return responce[*s3response.GetObjectAttributesResponse](ctx, res, code)
		}

		bucket, key, keyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		bRangeSl := strings.Split(ctx.Get("Range"), "=")
		if len(bRangeSl) < 2 {
			return errors.New("wrong api call")
		}

		bRange := strings.Split(bRangeSl[1], "-")
		if len(bRange) < 2 {
			return errors.New("wrong api call")
		}

		startOffset, err := strconv.Atoi(bRange[0])
		if err != nil {
			return errors.New("wrong api call")
		}

		length, err := strconv.Atoi(bRange[1])
		if err != nil {
			return errors.New("wrong api call")
		}

		res, code := be.GetObject(bucket, key, int64(startOffset), int64(length), ctx.Response().BodyWriter(), "")
		return responce[*s3response.GetObjectResponse](ctx, res, code)
	})
	// DeleteObject action
	app.Delete("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		code := be.DeleteObject(bucket, key)
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
