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
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) ListBuckets(ctx fiber.Ctx) (*Response, error) {
	cToken := ctx.Query("continuation-token")
	prefix := ctx.Query("prefix")
	maxBucketsStr := ctx.Query("max-buckets")
	bucketRegion := ctx.Query("bucket-region")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot, _ := utils.ContextKeyIsRoot.Get(ctx).(bool)

	if err := auth.VerifyListAllMyBucketsAccess(ctx, c.iam, isRoot, acct); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	owner, listAll := acct.Access, acct.Role == auth.RoleAdmin
	var isVisible func(context.Context, string, []byte) (bool, error)
	// A backend that fixes bucket ownership leaves no per-caller subset to
	// narrow the listing to, so every caller lists every bucket, the way an
	// AWS account's users do. What they may then do with one stays an IAM
	// policy decision, made per request.
	if fixedOwner, fixed := auth.ResolveFixedBucketOwner(c.iam); fixed {
		owner, listAll = fixedOwner.Access, true
	} else if !listAll {
		// Without identity policies each account lists only the buckets
		// it owns, as an AWS account does, unless the gateway's scope
		// widens that. Startup rejects every scope but owned for an IAM
		// backend that evaluates identity policies.
		switch c.listBucketsScope {
		case auth.ListBucketsScopeAll:
			listAll = true
		case auth.ListBucketsScopeAccessible:
			isVisible = c.bucketVisibility(acct, auth.ListBucketsConditionContext(ctx))
		}
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

	// an empty bucket-region= is checked too, so look for the argument itself
	if ctx.Request().URI().QueryArgs().Has("bucket-region") {
		if err := utils.ValidateBucketRegion(bucketRegion, region); err != nil {
			debuglogger.Logf("invalid bucket region: %q", bucketRegion)
			return &Response{
				MetaOpts: &MetaOptions{},
			}, err
		}
	}

	// IsAdmin is the backends' "return every bucket, unfiltered" flag.
	res, err := c.be.ListBuckets(ctx.RequestCtx(),
		s3response.ListBucketsInput{
			Owner:             owner,
			IsAdmin:           listAll,
			MaxBuckets:        maxBuckets,
			ContinuationToken: cToken,
			Prefix:            prefix,
			IsVisible:         isVisible,
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

// bucketVisibility returns the ListBucketsInput.IsVisible callback for
// auth.ListBucketsScopeAccessible: a bucket acct doesn't own is listed when
// auth.BucketVisibleTo says so, given the bucket's ACL and policy and
// condCtx, the ListBuckets request's condition keys. A bucket deleted
// since the backend listed it is skipped, and a bucket without a policy is
// decided by its ACL alone.
func (c S3ApiController) bucketVisibility(acct auth.Account, condCtx map[string][]string) func(context.Context, string, []byte) (bool, error) {
	return func(ctx context.Context, bucket string, aclJSON []byte) (bool, error) {
		acl, err := auth.ParseACL(aclJSON)
		if err != nil {
			return false, err
		}

		policy, err := c.be.GetBucketPolicy(ctx, bucket)
		switch {
		case errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)):
			return false, nil
		case errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)):
			policy = nil
		case err != nil:
			return false, err
		}

		return auth.BucketVisibleTo(acct, bucket, acl, policy, condCtx, c.disableACL), nil
	}
}
