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
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3event"
)

func (c S3ApiController) DeleteObjectTagging(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.DeleteObjectTaggingAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.DeleteObjectTagging(ctx.Context(), bucket, key)
	return &Response{
		MetaOpts: &MetaOptions{
			Status:      http.StatusNoContent,
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectTaggingDelete,
		},
	}, err
}

func (c S3ApiController) AbortMultipartUpload(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	uploadId := ctx.Query("uploadId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.AbortMultipartUploadAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.AbortMultipartUpload(ctx.Context(),
		&s3.AbortMultipartUploadInput{
			UploadId: &uploadId,
			Bucket:   &bucket,
			Key:      &key,
		})
	return &Response{
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
			Status:      http.StatusNoContent,
		},
	}, err
}

func (c S3ApiController) DeleteObject(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	bypass := strings.EqualFold(ctx.Get("X-Amz-Bypass-Governance-Retention"), "true")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	//TODO: check s3:DeleteObjectVersion policy in case a use tries to delete a version of an object

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.DeleteObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.CheckObjectAccess(
		ctx.Context(),
		bucket,
		acct.Access,
		[]types.ObjectIdentifier{
			{
				Key:       &key,
				VersionId: &versionId,
			},
		},
		bypass,
		IsBucketPublic,
		c.be,
	)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.DeleteObject(ctx.Context(),
		&s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: &versionId,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectRemovedDelete,
				Status:      http.StatusNoContent,
			},
		}, err
	}

	headers := map[string]*string{
		"x-amz-version-id": res.VersionId,
	}

	if res.DeleteMarker != nil && *res.DeleteMarker {
		headers["x-amz-delete-marker"] = utils.GetStringPtr("true")
	}

	return &Response{
		Headers: headers,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRemovedDelete,
			Status:      http.StatusNoContent,
		},
	}, nil
}
