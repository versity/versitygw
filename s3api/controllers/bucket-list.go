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
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
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

	maxBuckets := defaultMaxBuckets
	if maxBucketsStr != "" {
		maxBucketsParsed, err := strconv.ParseInt(maxBucketsStr, 10, 32)
		if err != nil || maxBucketsParsed < 0 || maxBucketsParsed > int64(defaultMaxBuckets) {
			debuglogger.Logf("error parsing max-buckets %q: %v", maxBucketsStr, err)
			return &Response{
				MetaOpts: &MetaOptions{},
			}, s3err.GetAPIError(s3err.ErrInvalidMaxBuckets)
		}
		maxBuckets = int32(maxBucketsParsed)
	}

	res, err := c.be.ListBuckets(ctx.Context(),
		s3response.ListBucketsInput{
			Owner:             acct.Access,
			IsAdmin:           acct.Role == auth.RoleAdmin,
			MaxBuckets:        maxBuckets,
			ContinuationToken: cToken,
			Prefix:            prefix,
		})
	return &Response{
		Data:     res,
		MetaOpts: &MetaOptions{},
	}, err
}
