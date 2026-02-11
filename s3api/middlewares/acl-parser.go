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

package middlewares

import (
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// ParseAcl retreives the bucket acl and stores in the context locals
// if no bucket is found, it returns 'NoSuchBucket'
func ParseAcl(be backend.Backend) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		bucket := ctx.Params("bucket")
		data, err := be.GetBucketAcl(ctx.RequestCtx(), &s3.GetBucketAclInput{Bucket: &bucket})
		if err != nil {
			return err
		}

		parsedAcl, err := auth.ParseACL(data)
		if err != nil {
			return err
		}

		// if owner is not set, set default owner to root account
		if parsedAcl.Owner == "" {
			parsedAcl.Owner = utils.ContextKeyRootAccessKey.Get(ctx).(string)
		}

		// if expected bucket owner doesn't match the bucket owner
		// the gateway should return AccessDenied.
		// This header appears in all actions except 'CreateBucket' and 'ListBuckets'.
		// 'ParseACL' is also applied to all actions except for 'CreateBucket' and 'ListBuckets',
		// so it's a perfect place to check the expected bucket owner
		bucketOwner := ctx.Get("X-Amz-Expected-Bucket-Owner")
		if bucketOwner != "" && bucketOwner != parsedAcl.Owner {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}

		utils.ContextKeyParsedAcl.Set(ctx, parsedAcl)
		return nil
	}
}
