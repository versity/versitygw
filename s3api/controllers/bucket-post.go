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
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/middlewares"
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
			Actions:         []auth.Action{auth.DeleteObjectAction},
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

func (c S3ApiController) POSTObject(ctx *fiber.Ctx) (*Response, error) {
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)

	parsed := utils.ContextKeyObjectPostResult.Get(ctx).(middlewares.PostObjectResult)
	bucket := ctx.Params("bucket")
	contentType := parsed.Fields["content-type"]
	contentEncoding := parsed.Fields["content-encoding"]
	contentDisposition := parsed.Fields["content-disposition"]
	contentLanguage := parsed.Fields["content-language"]
	cacheControl := parsed.Fields["cache-control"]
	expires := parsed.Fields["expires"]

	key, ok := parsed.Fields["key"]
	if !ok || key == "" {
		debuglogger.Logf("missing object key")
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.PostAuth.MissingField("key")
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:        c.readonly,
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Actions:         []auth.Action{auth.PutObjectAction},
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

	// parse POST policy — absent for anonymous uploads to public buckets
	if !IsBucketPublic {
		policyBase64 := parsed.Fields["policy"]
		policy, err := auth.ParsePOSTPolicyBase64(policyBase64)
		if err != nil {
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, err
		}

		// Evaluate post policy
		err = policy.Evaluate(auth.PostPolicyEvalInput{
			Bucket:        bucket,
			Key:           key,
			ContentLength: parsed.ContentLength,
			Fields:        parsed.Fields,
		})
		if err != nil {
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, err
		}
	}

	// convert object tagging from raw XML to Query string
	// to pass PutObject, which expects the tagging to be a query string
	var tagging string
	if taggingXML, ok := parsed.Fields["tagging"]; ok {
		tagging, err = utils.ConvertTaggingXMLToQueryString([]byte(taggingXML))
		if err != nil {
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, err
		}
	}

	// parse checksum headers
	checksums, err := utils.ParseCalculatedChecksumFields(parsed.Fields)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// extract metadata
	metadata, err := utils.ExtractMetadataFromFields(parsed.Fields)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.PutObject(ctx.Context(), s3response.PutObjectInput{
		Bucket:             &bucket,
		Key:                &key,
		ContentType:        &contentType,
		ContentEncoding:    &contentEncoding,
		ContentDisposition: &contentDisposition,
		ContentLanguage:    &contentLanguage,
		CacheControl:       &cacheControl,
		Expires:            &expires,
		Body:               parsed.FileRdr,
		ContentLength:      &parsed.ContentLength,
		Tagging:            &tagging,
		Metadata:           metadata,
		ChecksumCRC32:      utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32]),
		ChecksumCRC32C:     utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32c]),
		ChecksumSHA1:       utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha1]),
		ChecksumSHA256:     utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha256]),
		ChecksumCRC64NVME:  utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc64nvme]),
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	if successActionRedirect, ok := parsed.Fields["success_action_redirect"]; ok {
		u, err := url.Parse(successActionRedirect)
		if err == nil {
			q := u.Query()
			q.Set("bucket", bucket)
			q.Set("key", key)
			q.Set("etag", res.ETag)
			u.RawQuery = q.Encode()
			redirectURI := u.String()

			return &Response{
				Headers: map[string]*string{
					"Location": &redirectURI,
				},
				MetaOpts: &MetaOptions{
					ContentLength: parsed.FileRdr.Length(),
					BucketOwner:   parsedAcl.Owner,
					ObjectETag:    &res.ETag,
					ObjectSize:    parsed.FileRdr.Length(),
					EventName:     s3event.EventObjectCreatedPost,
					Status:        http.StatusSeeOther,
				},
			}, nil
		}
	}

	respStatus := http.StatusNoContent
	var respBody any
	location := utils.GenerateObjectLocation(ctx, c.virtualDomain, bucket, key)

	if successStatus, ok := parsed.Fields["success_action_status"]; ok {
		switch successStatus {
		case "200":
			respStatus = http.StatusOK
		case "201":
			respStatus = http.StatusCreated
			respBody = &s3response.PostResponse{
				Bucket:   bucket,
				Key:      key,
				ETag:     res.ETag,
				Location: location,
			}
		}
	}

	return &Response{
		Headers: map[string]*string{
			"Etag":                     &res.ETag,
			"Location":                 &location,
			"x-amz-checksum-crc32":     res.ChecksumCRC32,
			"x-amz-checksum-crc32c":    res.ChecksumCRC32C,
			"x-amz-checksum-crc64nvme": res.ChecksumCRC64NVME,
			"x-amz-checksum-sha1":      res.ChecksumSHA1,
			"x-amz-checksum-sha256":    res.ChecksumSHA256,
			"x-amz-checksum-type":      utils.ConvertToStringPtr(res.ChecksumType),
			"x-amz-version-id":         utils.GetStringPtr(res.VersionID),
		},
		Data: respBody,
		MetaOpts: &MetaOptions{
			ContentLength: parsed.FileRdr.Length(),
			BucketOwner:   parsedAcl.Owner,
			ObjectETag:    &res.ETag,
			ObjectSize:    parsed.FileRdr.Length(),
			EventName:     s3event.EventObjectCreatedPost,
			Status:        respStatus,
		},
	}, nil
}
