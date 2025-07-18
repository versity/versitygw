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
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) RestoreObject(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	var restoreRequest types.RestoreRequest
	if err := xml.Unmarshal(ctx.Body(), &restoreRequest); err != nil {
		debuglogger.Logf("failed to parse the request body: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionRestoreObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}
	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.RestoreObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionRestoreObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.RestoreObject(ctx.Context(), &s3.RestoreObjectInput{
		Bucket:         &bucket,
		Key:            &key,
		RestoreRequest: &restoreRequest,
	})
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionRestoreObject,
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRestoreCompleted,
		},
	}, err
}

func (c S3ApiController) SelectObjectContent(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	var payload s3response.SelectObjectContentPayload

	err := xml.Unmarshal(ctx.Body(), &payload)
	if err != nil {
		debuglogger.Logf("error unmarshalling select object content: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionSelectObjectContent,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	err = auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionSelectObjectContent,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	sw := c.be.SelectObjectContent(ctx.Context(),
		&s3.SelectObjectContentInput{
			Bucket:              &bucket,
			Key:                 &key,
			Expression:          payload.Expression,
			ExpressionType:      payload.ExpressionType,
			InputSerialization:  payload.InputSerialization,
			OutputSerialization: payload.OutputSerialization,
			RequestProgress:     payload.RequestProgress,
			ScanRange:           payload.ScanRange,
		})

	ctx.Context().SetBodyStreamWriter(sw)

	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionSelectObjectContent,
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}

func (c S3ApiController) CreateMultipartUpload(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	contentType := ctx.Get("Content-Type")
	contentDisposition := ctx.Get("Content-Disposition")
	contentLanguage := ctx.Get("Content-Language")
	cacheControl := ctx.Get("Cache-Control")
	contentEncoding := ctx.Get("Content-Encoding")
	tagging := ctx.Get("X-Amz-Tagging")
	expires := ctx.Get("Expires")
	metadata := utils.GetUserMetaData(&ctx.Request().Header)
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.PutObjectAction,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCreateMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	objLockState, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCreateMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	checksumAlgorithm, checksumType, err := utils.ParseCreateMpChecksumHeaders(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCreateMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.CreateMultipartUpload(ctx.Context(),
		s3response.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &key,
			Tagging:                   &tagging,
			ContentType:               &contentType,
			ContentEncoding:           &contentEncoding,
			ContentDisposition:        &contentDisposition,
			ContentLanguage:           &contentLanguage,
			CacheControl:              &cacheControl,
			Expires:                   &expires,
			ObjectLockRetainUntilDate: &objLockState.RetainUntilDate,
			ObjectLockMode:            objLockState.ObjectLockMode,
			ObjectLockLegalHoldStatus: objLockState.LegalHoldStatus,
			Metadata:                  metadata,
			ChecksumAlgorithm:         checksumAlgorithm,
			ChecksumType:              checksumType,
		})
	var headers map[string]*string
	if err == nil {
		headers = map[string]*string{
			"x-amz-checksum-algorithm": utils.ConvertToStringPtr(checksumAlgorithm),
		}
	}
	return &Response{
		Headers: headers,
		Data:    res,
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionCreateMultipartUpload,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) CompleteMultipartUpload(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	uploadId := ctx.Query("uploadId")
	mpuObjSizeHdr := ctx.Get("X-Amz-Mp-Object-Size")
	checksumType := types.ChecksumType(ctx.Get("x-amz-checksum-type"))
	// context locals
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
			Action:         auth.PutObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCompleteMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data := struct {
		Parts []types.CompletedPart `xml:"Part"`
	}{}

	err = xml.Unmarshal(ctx.Body(), &data)
	if err != nil {
		debuglogger.Logf("error unmarshalling complete multipart upload: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCompleteMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if len(data.Parts) == 0 {
		debuglogger.Logf("empty parts provided for complete multipart upload")
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCompleteMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrEmptyParts)
	}

	var mpuObjectSize *int64
	if mpuObjSizeHdr != "" {
		val, err := strconv.ParseInt(mpuObjSizeHdr, 10, 64)
		//TODO: Not sure if invalid request should be returned
		if err != nil {
			debuglogger.Logf("invalid value for 'x-amz-mp-objects-size' header: %v", err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}

		if val < 0 {
			debuglogger.Logf("value for 'x-amz-mp-objects-size' header is less than 0: %v", val)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetInvalidMpObjectSizeErr(val)
		}

		mpuObjectSize = &val
	}

	_, checksums, err := utils.ParseChecksumHeaders(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCompleteMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = utils.IsChecksumTypeValid(checksumType)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCompleteMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, versid, err := c.be.CompleteMultipartUpload(ctx.Context(),
		&s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: data.Parts,
			},
			MpuObjectSize:     mpuObjectSize,
			ChecksumCRC32:     utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32]),
			ChecksumCRC32C:    utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32c]),
			ChecksumSHA1:      utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha1]),
			ChecksumSHA256:    utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha256]),
			ChecksumCRC64NVME: utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc64nvme]),
			ChecksumType:      checksumType,
		})
	return &Response{
		Data: res,
		Headers: map[string]*string{
			"x-amz-version-id": &versid,
		},
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionCompleteMultipartUpload,
			BucketOwner: parsedAcl.Owner,
			ObjectETag:  res.ETag,
			EventName:   s3event.EventCompleteMultipartUpload,
			VersionId:   &versid,
		},
	}, err
}
