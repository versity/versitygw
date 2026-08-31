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
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) DeleteObjects(ctx fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	bypass := auth.BypassModeForRequest(strings.EqualFold(ctx.Get("X-Amz-Bypass-Governance-Retention"), "true"))
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)

	// The body has to be parsed before authorization, not after: real AWS
	// authorizes s3:DeleteObject against each object's own ARN, so the keys
	// are part of what is being authorized. The parsed objects go straight
	// to VerifyObjectsAccess, which checks policy and object locks for all
	// of them in one pass.
	var dObj s3response.DeleteObjects
	err := xml.Unmarshal(ctx.BodyRaw(), &dObj)
	if err != nil {
		debuglogger.Logf("error unmarshalling delete objects: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	// checkErrs holds one entry per requested object — nil where it may
	// proceed to the backend, an AWS-shaped denial otherwise. DeleteObjects
	// supports partial success, so a denial on one object (policy or object
	// lock) must not fail any other: only the objects that clear this check
	// are sent to the backend, and the rest are reported as per-object
	// errors directly from checkErrs. err here is a whole-request failure
	// (readonly mode, or an error resolving policy/lock state), not about
	// any one object.
	checkErrs, err := c.verifyObjectsAccess(ctx,
		auth.AccessOptions{
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			IsPublicRequest: IsBucketPublic,
		}, dObj.Objects, bypass)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	toDelete := make([]types.ObjectIdentifier, 0, len(dObj.Objects))
	for i, obj := range dObj.Objects {
		if checkErrs[i] == nil {
			toDelete = append(toDelete, obj)
		}
	}

	var backendResult s3response.DeleteResult
	if len(toDelete) > 0 {
		backendResult, err = c.be.DeleteObjects(ctx.RequestCtx(),
			&s3.DeleteObjectsInput{
				Bucket: &bucket,
				Delete: &types.Delete{
					Objects: toDelete,
				},
			})
	}

	return &Response{
		Data: utils.MergeDeleteObjectsResult(dObj.Objects, checkErrs, backendResult),
		MetaOpts: &MetaOptions{
			ObjectCount: int64(len(dObj.Objects)),
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRemovedDeleteObjects,
		},
	}, err
}

func (c S3ApiController) POSTObject(ctx fiber.Ctx) (*Response, error) {
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)

	parsed := utils.ContextKeyObjectPostResult.Get(ctx).(middlewares.PostObjectResult)
	bucket := ctx.Params("bucket")
	contentType := parsed.Fields["content-type"]
	if contentType == "" {
		contentType = defaultContentType
	}
	contentEncoding := parsed.Fields["content-encoding"]
	contentDisposition := parsed.Fields["content-disposition"]
	contentLanguage := parsed.Fields["content-language"]
	cacheControl := parsed.Fields["cache-control"]
	expires := parsed.Fields["expires"]
	websiteRedirectLocation := parsed.Fields["x-amz-website-redirect-location"]

	key := parsed.Fields["key"]

	err := c.verifyAccess(ctx,
		auth.AccessOptions{
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Actions:         []auth.Action{auth.PutObjectAction},
			IsPublicRequest: IsBucketPublic,
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

	err = utils.ValidateWebsiteRedirectLocation(websiteRedirectLocation)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.PutObject(ctx.RequestCtx(), s3response.PutObjectInput{
		Bucket:                  &bucket,
		Key:                     &key,
		ContentType:             &contentType,
		ContentEncoding:         &contentEncoding,
		ContentDisposition:      &contentDisposition,
		ContentLanguage:         &contentLanguage,
		CacheControl:            &cacheControl,
		Expires:                 &expires,
		WebsiteRedirectLocation: &websiteRedirectLocation,
		Body:                    parsed.FileRdr,
		ContentLength:           &parsed.ContentLength,
		Tagging:                 &tagging,
		Metadata:                metadata,
		ChecksumCRC32:           utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32]),
		ChecksumCRC32C:          utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32c]),
		ChecksumSHA1:            utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha1]),
		ChecksumSHA256:          utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha256]),
		ChecksumCRC64NVME:       utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc64nvme]),
		ChecksumSHA512:          utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha512]),
		ChecksumMD5:             utils.GetStringPtr(checksums[types.ChecksumAlgorithmMd5]),
		ChecksumXXHASH64:        utils.GetStringPtr(checksums[types.ChecksumAlgorithmXxhash64]),
		ChecksumXXHASH3:         utils.GetStringPtr(checksums[types.ChecksumAlgorithmXxhash3]),
		ChecksumXXHASH128:       utils.GetStringPtr(checksums[types.ChecksumAlgorithmXxhash128]),
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
			"x-amz-checksum-sha512":    res.ChecksumSHA512,
			"x-amz-checksum-md5":       res.ChecksumMD5,
			"x-amz-checksum-xxhash64":  res.ChecksumXXHASH64,
			"x-amz-checksum-xxhash3":   res.ChecksumXXHASH3,
			"x-amz-checksum-xxhash128": res.ChecksumXXHASH128,
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
