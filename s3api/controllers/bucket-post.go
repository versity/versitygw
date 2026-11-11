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
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
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
		// The decoder returns an S3 error for a body that is well-formed
		// XML but carries an invalid value.
		var s3Err s3err.S3Error
		if !errors.As(err, &s3Err) {
			s3Err = s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3Err
	}

	// S3 requires at least one object in a DeleteObjects request and
	// rejects an empty delete list as malformed.
	if len(dObj.Objects) == 0 {
		debuglogger.Logf("delete objects: no keys in the request")
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	// S3 caps a single DeleteObjects request at 1000 keys. Reject an
	// over-limit request before authorization and before anything reaches
	// the backend, so a too-large batch can't be applied partially.
	if len(dObj.Objects) > maxDeleteObjects {
		debuglogger.Logf("delete objects: %d keys exceeds the limit of %d",
			len(dObj.Objects), maxDeleteObjects)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	// The keys come from the body, so they skip the object name check the
	// request path gets. On a filesystem backend a key holding ".." segments
	// ("../key") names a path outside the bucket, so the whole request is
	// rejected before any key is authorized or deleted.
	for _, obj := range dObj.Objects {
		if obj.Key == nil || !utils.IsObjectNameValid(*obj.Key, c.be) {
			debuglogger.Logf("delete objects: invalid object key: %q",
				backend.GetStringFromPtr(obj.Key))
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrBadRequest)
		}
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
		// The ETag condition of an object is validated ahead of its
		// authorization. It only applies to the current version, so it
		// can't be combined with a version id.
		if obj.ETag != nil {
			switch {
			case *obj.ETag == "":
				checkErrs[i] = s3err.GetInvalidArgumentErr(s3err.InvalidArgEmptyETag, "")
			case backend.GetStringFromPtr(obj.VersionId) != "":
				checkErrs[i] = s3err.GetAPIError(s3err.ErrNotImplementedFormField)
			}
		}
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

	result := utils.MergeDeleteObjectsResult(dObj.Objects, checkErrs, backendResult)
	// In quiet mode the response lists only the objects that could not be
	// deleted.
	if dObj.Quiet {
		result.Deleted = nil
	}

	return &Response{
		Data: result,
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
	storageClass := parsed.Fields["x-amz-storage-class"]

	key := parsed.Fields["key"]

	// The sizes the file may have: any, for an anonymous upload to a public
	// bucket, which has no policy.
	minSize, maxSize := int64(0), int64(math.MaxInt64)

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

		// Evaluate post policy. The size of the file is checked as it is
		// read, right before the backend gets it.
		err = policy.Evaluate(auth.PostPolicyEvalInput{
			Bucket: bucket,
			Key:    key,
			Fields: parsed.Fields,
		})
		if err != nil {
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, err
		}

		minSize, maxSize = policy.ContentLengthRange()
	}

	// convert object tagging from raw XML to Query string
	// to pass PutObject, which expects the tagging to be a query string
	var tagging string
	if taggingXML, ok := parsed.Fields["tagging"]; ok {
		var err error
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

	objLock, err := utils.ParseObjectLockFields(parsed.Fields)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// A POST upload is an s3:PutObject on the object named by the form's
	// key field, so it is authorized against that object's ARN — the same
	// resource PutObject is — not the bucket's. Tagging the object also
	// takes s3:PutObjectTagging, but only for a non-empty tag set, and its
	// Object Lock fields the lock actions. A POST upload denied several of
	// them is reported as denied the retention, the legal hold, the
	// tagging, then s3:PutObject itself.
	actions := auth.ObjectUploadActions(tagging, string(objLock.LegalHoldStatus), string(objLock.ObjectLockMode), "")
	slices.Reverse(actions)

	err = c.verifyAccess(ctx,
		auth.AccessOptions{
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Object:          key,
			Actions:         actions,
			IsPublicRequest: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// lock fields need a bucket with Object Lock
	if objLock.LegalHoldStatus != "" || objLock.ObjectLockMode != "" {
		if _, err := auth.VerifyWriteObjectLock(ctx.RequestCtx(), c.be, bucket, true); err != nil {
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, err
		}
	}

	ssec, err := c.parseSSECFields(ctx, parsed.Fields)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.CheckObjectAccess(ctx, bucket, acct, []types.ObjectIdentifier{{Key: &key}}, auth.BypassOverwrite, IsBucketPublic, c.be, c.iam, true)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// The file is read as the backend takes it, and refused if its size is out
	// of the range the policy allows.
	file := utils.NewContentLengthRangeReader(parsed.FileRdr, minSize, maxSize, parsed.ProposedSize)
	contentLength := file.ContentLength()

	// A file as long as a length under the min is under the min, and a
	// backend must not store it before the reader refuses it. The S3 proxy
	// sends the file with that length, and the upstream stores it when the
	// body is complete. For a length of 0 it does not read the file at all.
	// The reader reads the file here instead and fails at its end, or at the
	// max. The file is not kept.
	if contentLength < minSize {
		_, err := io.Copy(io.Discard, file)
		if err == nil {
			// The request proposes less than the file has, as for a body
			// without the final CRLF, and the file is in the range. It is
			// read, so the backend cannot get it.
			err = s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.PutObject(ctx.RequestCtx(), s3response.PutObjectInput{
		SSECustomerAlgorithm:      ssec.Algorithm,
		SSECustomerKey:            ssec.Key,
		SSECustomerKeyMD5:         ssec.KeyMD5,
		Bucket:                    &bucket,
		Key:                       &key,
		ContentType:               &contentType,
		ContentEncoding:           &contentEncoding,
		ContentDisposition:        &contentDisposition,
		ContentLanguage:           &contentLanguage,
		CacheControl:              &cacheControl,
		Expires:                   &expires,
		WebsiteRedirectLocation:   &websiteRedirectLocation,
		Body:                      file,
		ContentLength:             &contentLength,
		Tagging:                   &tagging,
		ObjectLockRetainUntilDate: &objLock.RetainUntilDate,
		ObjectLockMode:            objLock.ObjectLockMode,
		ObjectLockLegalHoldStatus: objLock.LegalHoldStatus,
		Metadata:                  metadata,
		StorageClass:              types.StorageClass(storageClass),
		ChecksumCRC32:             utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32]),
		ChecksumCRC32C:            utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32c]),
		ChecksumSHA1:              utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha1]),
		ChecksumSHA256:            utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha256]),
		ChecksumCRC64NVME:         utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc64nvme]),
		ChecksumSHA512:            utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha512]),
		ChecksumMD5:               utils.GetStringPtr(checksums[types.ChecksumAlgorithmMd5]),
		ChecksumXXHASH64:          utils.GetStringPtr(checksums[types.ChecksumAlgorithmXxhash64]),
		ChecksumXXHASH3:           utils.GetStringPtr(checksums[types.ChecksumAlgorithmXxhash3]),
		ChecksumXXHASH128:         utils.GetStringPtr(checksums[types.ChecksumAlgorithmXxhash128]),
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, postObjectPutErr(file, contentLength, err)
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

// postObjectPutErr returns the error to report for a file that the backend
// failed to put with err.
func postObjectPutErr(file *utils.ContentLengthRangeReader, contentLength int64, err error) error {
	// The error the reader failed the file with is the one to report: the S3
	// proxy and Azure backends wrap it, which makes it an internal error.
	if readErr := file.Err(); readErr != nil {
		return readErr
	}

	// The backend got contentLength as the length of the file, which is more
	// than the file has when the form has data after it. S3 takes such a form,
	// but a backend that sends the length it is given, as the S3 proxy does as
	// the Content-Length, fails on a body that ends before it, with an error
	// that is not an S3 error, so an internal one. An S3 error is the answer of
	// the backend, and goes out as it is.
	if _, ok := err.(s3err.S3Error); !ok && file.EndedBefore(contentLength) {
		debuglogger.Logf("backend failed a file that ends before the %d bytes it was given: %v", contentLength, err)
		return s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}

	return err
}
