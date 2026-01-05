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
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) GetBucketTagging(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketTaggingAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	tags, err := c.be.GetBucketTagging(ctx.Context(), bucket)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	resp := s3response.Tagging{
		TagSet: s3response.TagSet{
			Tags: make([]s3response.Tag, 0, len(tags)),
		},
	}

	for key, val := range tags {
		resp.TagSet.Tags = append(resp.TagSet.Tags,
			s3response.Tag{Key: key, Value: val})
	}

	return &Response{
		Data: resp,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetBucketOwnershipControls(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketOwnershipControlsAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data, err := c.be.GetBucketOwnershipControls(ctx.Context(), bucket)
	return &Response{
		Data: s3response.OwnershipControls{
			Rules: []types.OwnershipControlsRule{
				{
					ObjectOwnership: data,
				},
			},
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetBucketVersioning(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketVersioningAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	// Only admin users and the bucket owner are allowed to get the versioning state of a bucket.
	if err := auth.IsAdminOrOwner(acct, isRoot, parsedAcl); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data, err := c.be.GetBucketVersioning(ctx.Context(), bucket)
	return &Response{
		Data: data,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetBucketCors(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketCorsAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data, err := c.be.GetBucketCors(ctx.Context(), bucket)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	output, err := auth.ParseCORSOutput(data)
	return &Response{
		Data: output,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetBucketPolicy(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketPolicyAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data, err := c.be.GetBucketPolicy(ctx.Context(), bucket)
	return &Response{
		Data: data,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetBucketPolicyStatus(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketPolicyStatusAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	policyRaw, err := c.be.GetBucketPolicy(ctx.Context(), bucket)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	policy, err := auth.ParsePolicyDocument(policyRaw)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	isPublic := policy.IsPublic()

	return &Response{
		Data: types.PolicyStatus{
			IsPublic: &isPublic,
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}

func (c S3ApiController) ListObjectVersions(ctx *fiber.Ctx) (*Response, error) {
	// url values
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	delimiter := ctx.Query("delimiter")
	maxkeysStr := ctx.Query("max-keys")
	keyMarker := ctx.Query("key-marker")
	versionIdMarker := ctx.Query("version-id-marker")
	// context keys
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.ListBucketVersionsAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	maxkeys, err := utils.ParseUint(maxkeysStr)
	if err != nil {
		debuglogger.Logf("error parsing max keys %q: %v",
			maxkeysStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)
	}

	data, err := c.be.ListObjectVersions(ctx.Context(),
		&s3.ListObjectVersionsInput{
			Bucket:          &bucket,
			Delimiter:       &delimiter,
			KeyMarker:       &keyMarker,
			MaxKeys:         &maxkeys,
			Prefix:          &prefix,
			VersionIdMarker: &versionIdMarker,
		})
	return &Response{
		Data: data,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetObjectLockConfiguration(ctx *fiber.Ctx) (*Response, error) {
	// url values
	bucket := ctx.Params("bucket")
	// context keys
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketObjectLockConfigurationAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data, err := c.be.GetObjectLockConfiguration(ctx.Context(), bucket)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	resp, err := auth.ParseBucketLockConfigurationOutput(data)
	return &Response{
		Data: resp,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetBucketAcl(ctx *fiber.Ctx) (*Response, error) {
	// url values
	bucket := ctx.Params("bucket")
	// context keys
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionReadAcp,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketAclAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	data, err := c.be.GetBucketAcl(ctx.Context(),
		&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := auth.ParseACLOutput(data, parsedAcl.Owner)
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) ListMultipartUploads(ctx *fiber.Ctx) (*Response, error) {
	// url values
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	delimiter := ctx.Query("delimiter")
	keyMarker := ctx.Query("key-marker")
	maxUploadsStr := ctx.Query("max-uploads")
	uploadIdMarker := ctx.Query("upload-id-marker")
	// context keys
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.ListBucketMultipartUploadsAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	maxUploads, err := utils.ParseUint(maxUploadsStr)
	if err != nil {
		debuglogger.Logf("error parsing max uploads %q: %v",
			maxUploadsStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMaxUploads)
	}
	res, err := c.be.ListMultipartUploads(ctx.Context(),
		&s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			Delimiter:      &delimiter,
			Prefix:         &prefix,
			UploadIdMarker: &uploadIdMarker,
			MaxUploads:     &maxUploads,
			KeyMarker:      &keyMarker,
		})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) ListObjectsV2(ctx *fiber.Ctx) (*Response, error) {
	// url values
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	cToken := ctx.Query("continuation-token")
	sAfter := ctx.Query("start-after")
	delimiter := ctx.Query("delimiter")
	maxkeysStr := ctx.Query("max-keys")
	fetchOwner := strings.EqualFold(ctx.Query("fetch-owner"), "true")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
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
	maxkeys, err := utils.ParseUint(maxkeysStr)
	if err != nil {
		debuglogger.Logf("error parsing max keys %q: %v",
			maxkeysStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)
	}

	res, err := c.be.ListObjectsV2(ctx.Context(),
		&s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: &cToken,
			Delimiter:         &delimiter,
			MaxKeys:           &maxkeys,
			StartAfter:        &sAfter,
			FetchOwner:        &fetchOwner,
		})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) ListObjects(ctx *fiber.Ctx) (*Response, error) {
	// url values
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	marker := ctx.Query("marker")
	delimiter := ctx.Query("delimiter")
	maxkeysStr := ctx.Query("max-keys")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
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

	maxkeys, err := utils.ParseUint(maxkeysStr)
	if err != nil {
		debuglogger.Logf("error parsing max keys %q: %v",
			maxkeysStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)
	}

	res, err := c.be.ListObjects(ctx.Context(),
		&s3.ListObjectsInput{
			Bucket:    &bucket,
			Prefix:    &prefix,
			Marker:    &marker,
			Delimiter: &delimiter,
			MaxKeys:   &maxkeys,
		})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

// GetBucketLocation handles GET /:bucket?location
func (c S3ApiController) GetBucketLocation(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Action:          auth.GetBucketLocationAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// verify bucket existence/access via backend HeadBucket
	_, err = c.be.HeadBucket(ctx.Context(), &s3.HeadBucketInput{Bucket: &bucket})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// pick up configured region from locals (set by router middleware)
	region, _ := ctx.Locals("region").(string)
	value := &region
	if region == "us-east-1" {
		value = nil
	}

	return &Response{
		Data: s3response.LocationConstraint{
			Value: value,
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}
