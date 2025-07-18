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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

func VerifyObjectCopyAccess(ctx context.Context, be backend.Backend, copySource string, opts AccessOptions) error {
	if opts.IsRoot {
		return nil
	}
	if opts.Acc.Role == RoleAdmin {
		return nil
	}

	// Verify destination bucket access
	if err := VerifyAccess(ctx, be, opts); err != nil {
		return err
	}
	// Verify source bucket access
	srcBucket, srcObject, found := strings.Cut(copySource, "/")
	if !found {
		return s3err.GetAPIError(s3err.ErrInvalidCopySource)
	}

	// Get source bucket ACL
	srcBucketACLBytes, err := be.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &srcBucket})
	if err != nil {
		return err
	}

	var srcBucketAcl ACL
	if err := json.Unmarshal(srcBucketACLBytes, &srcBucketAcl); err != nil {
		return err
	}

	if err := VerifyAccess(ctx, be, AccessOptions{
		Acl:           srcBucketAcl,
		AclPermission: PermissionRead,
		IsRoot:        opts.IsRoot,
		Acc:           opts.Acc,
		Bucket:        srcBucket,
		Object:        srcObject,
		Action:        GetObjectAction,
	}); err != nil {
		return err
	}

	return nil
}

type AccessOptions struct {
	Acl            ACL
	AclPermission  Permission
	IsRoot         bool
	Acc            Account
	Bucket         string
	Object         string
	Action         Action
	Readonly       bool
	IsBucketPublic bool
}

func VerifyAccess(ctx context.Context, be backend.Backend, opts AccessOptions) error {
	// Skip the access check for public buckets
	if opts.IsBucketPublic {
		return nil
	}
	if opts.Readonly {
		if opts.AclPermission == PermissionWrite || opts.AclPermission == PermissionWriteAcp {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}
	if opts.IsRoot {
		return nil
	}
	if opts.Acc.Role == RoleAdmin {
		return nil
	}

	policy, policyErr := be.GetBucketPolicy(ctx, opts.Bucket)
	if policyErr != nil {
		if !errors.Is(policyErr, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
			return policyErr
		}
	} else {
		return VerifyBucketPolicy(policy, opts.Acc.Access, opts.Bucket, opts.Object, opts.Action)
	}

	if err := verifyACL(opts.Acl, opts.Acc.Access, opts.AclPermission); err != nil {
		return err
	}

	return nil
}

// Detects if the action is policy related
// e.g.
// 'GetBucketPolicy', 'PutBucketPolicy'
func isPolicyAction(action Action) bool {
	return action == GetBucketPolicyAction || action == PutBucketPolicyAction
}

// VerifyPublicAccess checks if the bucket is publically accessible by ACL or Policy
func VerifyPublicAccess(ctx context.Context, be backend.Backend, action Action, permission Permission, bucket, object string) error {
	// ACL disabled
	policy, err := be.GetBucketPolicy(ctx, bucket)
	if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
		return err
	}
	if err == nil {
		err = VerifyPublicBucketPolicy(policy, bucket, object, action)
		if err == nil {
			// if ACLs are disabled, and the bucket grants public access,
			// policy actions should return 'MethodNotAllowed'
			if isPolicyAction(action) {
				return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
			}

			return nil
		}
	}

	// if the action is not in the ACL whitelist the access is denied
	_, ok := publicACLAllowedActions[action]
	if !ok {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	err = VerifyPublicBucketACL(ctx, be, bucket, action, permission)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}

func IsAdminOrOwner(acct Account, isRoot bool, acl ACL) error {
	// Owner check
	if acct.Access == acl.Owner {
		return nil
	}

	// Root user has access over almost everything
	if isRoot {
		return nil
	}

	// Admin user case
	if acct.Role == RoleAdmin {
		return nil
	}

	// Return access denied in all other cases
	return s3err.GetAPIError(s3err.ErrAccessDenied)
}

type PublicACLAllowedActions map[Action]struct{}

var publicACLAllowedActions PublicACLAllowedActions = PublicACLAllowedActions{
	ListBucketAction:                 struct{}{},
	PutObjectAction:                  struct{}{},
	ListBucketMultipartUploadsAction: struct{}{},
	DeleteObjectAction:               struct{}{},
	ListBucketVersionsAction:         struct{}{},
	GetObjectAction:                  struct{}{},
	GetObjectAttributesAction:        struct{}{},
	GetObjectAclAction:               struct{}{},
}
