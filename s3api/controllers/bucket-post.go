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
	"encoding/xml"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	bypass := strings.EqualFold(ctx.Get("X-Amz-Bypass-Governance-Retention"), "true")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:        c.readonly,
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Action:          auth.DeleteObjectAction,
			IsPublicRequest: IsBucketPublic,
			DisableACL:      c.disableACL,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var dObj s3response.DeleteObjects
	err = xml.Unmarshal(ctx.Body(), &dObj)
	if err != nil {
		debuglogger.Logf("error unmarshalling delete objects: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, dObj.Objects, bypass, IsBucketPublic, c.be, false)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.DeleteObjects(ctx.Context(),
		&s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: dObj.Objects,
			},
		})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			ObjectCount: int64(len(dObj.Objects)),
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRemovedDeleteObjects,
		},
	}, err
}
