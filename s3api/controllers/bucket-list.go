// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package controllers

import (
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) ListBuckets(ctx fiber.Ctx) (*Response, error) {
	cToken := ctx.Query("continuation-token")
	prefix := ctx.Query("prefix")
	maxBucketsStr := ctx.Query("max-buckets")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	region, ok := utils.ContextKeyRegion.Get(ctx).(string)
	if !ok {
		region = defaultRegion
	}

	maxBuckets, err := utils.ParseMaxLimiter(maxBucketsStr, utils.LimiterTypeMaxBuckets)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	res, err := c.be.ListBuckets(ctx.RequestCtx(),
		s3response.ListBucketsInput{
			Owner:             acct.Access,
			IsAdmin:           acct.Role == auth.RoleAdmin,
			MaxBuckets:        maxBuckets,
			ContinuationToken: cToken,
			Prefix:            prefix,
		})
	if err != nil {
		return &Response{}, err
	}

	for i := range res.Buckets.Bucket {
		res.Buckets.Bucket[i].BucketRegion = region
	}

	return &Response{
		Data: res,
	}, nil
}
