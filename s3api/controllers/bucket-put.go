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
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) PutBucketTagging(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Action:         auth.PutBucketTaggingAction,
		IsBucketPublic: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketTagging,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	tagging, err := utils.ParseTagging(ctx.Body(), utils.TagLimitBucket)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketTagging,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutBucketTagging(ctx.Context(), bucket, tagging)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutBucketTagging,
			BucketOwner: parsedAcl.Owner,
			Status:      http.StatusNoContent,
		},
	}, err
}

func (c S3ApiController) PutBucketOwnershipControls(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)

	if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:      c.readonly,
		Acl:           parsedAcl,
		AclPermission: auth.PermissionWrite,
		IsRoot:        isRoot,
		Acc:           acct,
		Bucket:        bucket,
		Action:        auth.PutBucketOwnershipControlsAction,
	}); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketOwnershipControls,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var ownershipControls s3response.OwnershipControls
	if err := xml.Unmarshal(ctx.Body(), &ownershipControls); err != nil {
		debuglogger.Logf("failed to unmarshal request body: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketOwnershipControls,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	rulesCount := len(ownershipControls.Rules)
	isValidOwnership := utils.IsValidOwnership(ownershipControls.Rules[0].ObjectOwnership)
	if rulesCount != 1 || !isValidOwnership {
		if rulesCount != 1 {
			debuglogger.Logf("ownership control rules should be 1, got %v", rulesCount)
		}
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketOwnershipControls,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	err := c.be.PutBucketOwnershipControls(ctx.Context(), bucket, ownershipControls.Rules[0].ObjectOwnership)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutBucketOwnershipControls,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutBucketVersioning(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Action:         auth.PutBucketVersioningAction,
		IsBucketPublic: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketVersioning,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var versioningConf types.VersioningConfiguration
	err = xml.Unmarshal(ctx.Body(), &versioningConf)
	if err != nil {
		debuglogger.Logf("error unmarshalling versioning configuration: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketVersioning,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	if versioningConf.Status != types.BucketVersioningStatusEnabled &&
		versioningConf.Status != types.BucketVersioningStatusSuspended {
		debuglogger.Logf("invalid versioning configuration status: %v", versioningConf.Status)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketVersioning,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	err = c.be.PutBucketVersioning(ctx.Context(), bucket, versioningConf.Status)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutBucketVersioning,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutObjectLockConfiguration(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Action:         auth.PutBucketObjectLockConfigurationAction,
		IsBucketPublic: isPublicBucket,
	}); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectLockConfiguration,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	config, err := auth.ParseBucketLockConfigurationInput(ctx.Body())
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectLockConfiguration,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutObjectLockConfiguration(ctx.Context(), bucket, config)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutObjectLockConfiguration,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutBucketCors(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Action:         auth.PutBucketCorsAction,
		IsBucketPublic: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketCors,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutBucketCors(ctx.Context(), []byte{})
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutBucketCors,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutBucketPolicy(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:      c.readonly,
		Acl:           parsedAcl,
		AclPermission: auth.PermissionWrite,
		IsRoot:        isRoot,
		Acc:           acct,
		Bucket:        bucket,
		Action:        auth.PutBucketPolicyAction,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketPolicy,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.ValidatePolicyDocument(ctx.Body(), bucket, c.iam)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketPolicy,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutBucketPolicy(ctx.Context(), bucket, ctx.Body())
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutBucketPolicy,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutBucketAcl(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")
	// context locals
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP
	var input *auth.PutBucketAclInput

	ownership, err := c.be.GetBucketOwnershipControls(ctx.Context(), bucket)
	if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrOwnershipControlsNotFound)) {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketAcl,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	if ownership == types.ObjectOwnershipBucketOwnerEnforced {
		debuglogger.Logf("bucket acls are disabled")
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketAcl,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrAclNotSupported)
	}

	err = auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWriteAcp,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.PutBucketAclAction,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketAcl,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	if len(ctx.Body()) > 0 {
		var accessControlPolicy auth.AccessControlPolicy
		err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
		if err != nil {
			debuglogger.Logf("error unmarshalling access control policy: %v", err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrMalformedACL)
		}

		err = accessControlPolicy.Validate()
		if err != nil {
			debuglogger.Logf("invalid access control policy: %v", err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, err
		}

		if *accessControlPolicy.Owner.ID != parsedAcl.Owner {
			debuglogger.Logf("invalid access control policy owner id: %v, expected %v", *accessControlPolicy.Owner.ID, parsedAcl.Owner)
			return &Response{
					MetaOpts: &MetaOptions{
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					},
				}, s3err.APIError{
					Code:           "InvalidArgument",
					Description:    "Invalid id",
					HTTPStatusCode: http.StatusBadRequest,
				}
		}

		if grants+acl != "" {
			debuglogger.Logf("invalid request: %q (grants) %q (acl)",
				grants, acl)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrUnexpectedContent)
		}

		input = &auth.PutBucketAclInput{
			Bucket:              &bucket,
			AccessControlPolicy: &accessControlPolicy,
		}
	} else if acl != "" {
		if acl != "private" && acl != "public-read" && acl != "public-read-write" {
			debuglogger.Logf("invalid acl: %q", acl)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		if grants != "" {
			debuglogger.Logf("invalid request: %q (grants) %q (acl)",
				grants, acl)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants)
		}

		input = &auth.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACL(acl),
		}
	} else if grants != "" {
		input = &auth.PutBucketAclInput{
			Bucket:           &bucket,
			GrantFullControl: &grantFullControl,
			GrantRead:        &grantRead,
			GrantReadACP:     &grantReadACP,
			GrantWrite:       &granWrite,
			GrantWriteACP:    &grantWriteACP,
		}
	} else {
		debuglogger.Logf("none of the bucket acl options has been specified: canned, req headers, req body")
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketAcl,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMissingSecurityHeader)
	}

	updAcl, err := auth.UpdateACL(input, parsedAcl, c.iam, acct.Role == auth.RoleAdmin)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutBucketAcl,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutBucketAcl(ctx.Context(), bucket, updAcl)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutBucketAcl,
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) CreateBucket(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")
	lockEnabled := strings.EqualFold(ctx.Get("X-Amz-Bucket-Object-Lock-Enabled"), "true")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP
	objectOwnership := types.ObjectOwnership(
		ctx.Get("X-Amz-Object-Ownership", string(types.ObjectOwnershipBucketOwnerEnforced)),
	)

	// validate the bucket name
	if ok := utils.IsValidBucketName(bucket); !ok {
		return &Response{
			MetaOpts: &MetaOptions{
				Action: metrics.ActionCreateBucket,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

	// validate the object ownership value
	if ok := utils.IsValidOwnership(objectOwnership); !ok {
		return &Response{
				MetaOpts: &MetaOptions{
					Action: metrics.ActionCreateBucket,
				},
			}, s3err.APIError{
				Code:           "InvalidArgument",
				Description:    fmt.Sprintf("Invalid x-amz-object-ownership header: %v", objectOwnership),
				HTTPStatusCode: http.StatusBadRequest,
			}
	}

	if acl+grants != "" && objectOwnership == types.ObjectOwnershipBucketOwnerEnforced {
		debuglogger.Logf("bucket acls are disabled for %v object ownership", objectOwnership)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidBucketAclWithObjectOwnership)
	}

	if acl != "" && grants != "" {
		debuglogger.Logf("invalid request: %q (grants) %q (acl)", grants, acl)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			},
		}, s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants)
	}

	defACL := auth.ACL{
		Owner: acct.Access,
	}

	updAcl, err := auth.UpdateACL(&auth.PutBucketAclInput{
		GrantFullControl: &grantFullControl,
		GrantRead:        &grantRead,
		GrantReadACP:     &grantReadACP,
		GrantWrite:       &granWrite,
		GrantWriteACP:    &grantWriteACP,
		AccessControlPolicy: &auth.AccessControlPolicy{
			Owner: &types.Owner{
				ID: &acct.Access,
			}},
		ACL: types.BucketCannedACL(acl),
	}, defACL, c.iam, acct.Role == auth.RoleAdmin)
	if err != nil {
		debuglogger.Logf("failed to update bucket acl: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			},
		}, err
	}

	err = c.be.CreateBucket(ctx.Context(), &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectOwnership:            objectOwnership,
		ObjectLockEnabledForBucket: &lockEnabled,
	}, updAcl)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionCreateBucket,
			BucketOwner: acct.Access,
		},
	}, err
}
