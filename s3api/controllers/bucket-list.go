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
	isRoot, _ := utils.ContextKeyIsRoot.Get(ctx).(bool)

	if err := auth.VerifyListAllMyBucketsAccess(ctx, c.iam, isRoot, acct); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	owner, listAll := acct.Access, acct.Role == auth.RoleAdmin
	// A backend that fixes bucket ownership leaves no per-caller subset to
	// narrow the listing to, so every caller lists every bucket, the way an
	// AWS account's users do. What they may then do with one stays an IAM
	// policy decision, made per request.
	if fixedOwner, fixed := auth.ResolveFixedBucketOwner(c.iam); fixed {
		owner, listAll = fixedOwner.Access, true
	}

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

	// IsAdmin is the backends' "return every bucket, unfiltered" flag.
	res, err := c.be.ListBuckets(ctx.RequestCtx(),
		s3response.ListBucketsInput{
			Owner:             owner,
			IsAdmin:           listAll,
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
