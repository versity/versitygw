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
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
)

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	region := utils.ContextKeyRegion.Get(ctx).(string)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:        c.readonly,
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionRead,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Action:          auth.ListBucketAction,
			IsPublicRequest: isPublicBucket,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	_, err = c.be.HeadBucket(ctx.Context(),
		&s3.HeadBucketInput{
			Bucket: &bucket,
		})

	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	return &Response{
		Headers: map[string]*string{
			"x-amz-access-point-alias": utils.GetStringPtr("false"),
			"x-amz-bucket-region":      utils.GetStringPtr(region),
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}
