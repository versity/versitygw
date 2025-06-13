package controllers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) (*Response, error) {
	cToken := ctx.Query("continuation-token")
	prefix := ctx.Query("prefix")
	maxBucketsStr := ctx.Query("max-buckets")

	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)

	var maxBuckets int32 = 10000
	if maxBucketsStr != "" {
		maxBucketsParsed, err := strconv.ParseInt(maxBucketsStr, 10, 32)
		if err != nil || maxBucketsParsed < 0 || maxBucketsParsed > 10000 {
			debuglogger.Logf("error parsing max-buckets %q: %v", maxBucketsStr, err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action: metrics.ActionListAllMyBuckets,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidMaxBuckets)
		}
		maxBuckets = int32(maxBucketsParsed)
	}

	res, err := c.be.ListBuckets(ctx.Context(),
		s3response.ListBucketsInput{
			Owner:             acct.Access,
			IsAdmin:           acct.Role == auth.RoleAdmin,
			MaxBuckets:        int32(maxBuckets),
			ContinuationToken: cToken,
			Prefix:            prefix,
		})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			Action: metrics.ActionListAllMyBuckets,
		},
	}, err
}
