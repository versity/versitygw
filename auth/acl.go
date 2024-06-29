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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

type ACL struct {
	Owner    string
	Grantees []Grantee
}

type Grantee struct {
	Permission types.Permission
	Access     string
}

type GetBucketAclOutput struct {
	Owner             *types.Owner
	AccessControlList AccessControlList
}

type AccessControlList struct {
	Grants []types.Grant `xml:"Grant"`
}
type AccessControlPolicy struct {
	AccessControlList AccessControlList `xml:"AccessControlList"`
	Owner             types.Owner
}

func ParseACL(data []byte) (ACL, error) {
	if len(data) == 0 {
		return ACL{}, nil
	}

	var acl ACL
	if err := json.Unmarshal(data, &acl); err != nil {
		return acl, fmt.Errorf("parse acl: %w", err)
	}
	return acl, nil
}

func ParseACLOutput(data []byte) (GetBucketAclOutput, error) {
	var acl ACL
	if err := json.Unmarshal(data, &acl); err != nil {
		return GetBucketAclOutput{}, fmt.Errorf("parse acl: %w", err)
	}

	grants := []types.Grant{}

	for _, elem := range acl.Grantees {
		acs := elem.Access
		grants = append(grants, types.Grant{Grantee: &types.Grantee{ID: &acs}, Permission: elem.Permission})
	}

	return GetBucketAclOutput{
		Owner: &types.Owner{
			ID: &acl.Owner,
		},
		AccessControlList: AccessControlList{
			Grants: grants,
		},
	}, nil
}

func UpdateACL(input *s3.PutBucketAclInput, acl ACL, iam IAMService) ([]byte, error) {
	if input == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if acl.Owner != *input.AccessControlPolicy.Owner.ID {
		return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	defaultGrantees := []Grantee{
		{
			Permission: types.PermissionFullControl,
			Access:     acl.Owner,
		},
	}

	// if the ACL is specified, set the ACL, else replace the grantees
	if input.ACL != "" {
		switch input.ACL {
		case types.BucketCannedACLPublicRead:
			defaultGrantees = append(defaultGrantees, Grantee{
				Permission: types.PermissionRead,
				Access:     "all-users",
			})
		case types.BucketCannedACLPublicReadWrite:
			defaultGrantees = append(defaultGrantees, []Grantee{
				{
					Permission: types.PermissionRead,
					Access:     "all-users",
				},
				{
					Permission: types.PermissionWrite,
					Access:     "all-users",
				},
			}...)
		}
	} else {
		accs := []string{}

		if input.GrantRead != nil || input.GrantReadACP != nil || input.GrantFullControl != nil || input.GrantWrite != nil || input.GrantWriteACP != nil {
			fullControlList, readList, readACPList, writeList, writeACPList := []string{}, []string{}, []string{}, []string{}, []string{}

			if input.GrantFullControl != nil && *input.GrantFullControl != "" {
				fullControlList = splitUnique(*input.GrantFullControl, ",")
				for _, str := range fullControlList {
					defaultGrantees = append(defaultGrantees, Grantee{Access: str, Permission: "FULL_CONTROL"})
				}
			}
			if input.GrantRead != nil && *input.GrantRead != "" {
				readList = splitUnique(*input.GrantRead, ",")
				for _, str := range readList {
					defaultGrantees = append(defaultGrantees, Grantee{Access: str, Permission: "READ"})
				}
			}
			if input.GrantReadACP != nil && *input.GrantReadACP != "" {
				readACPList = splitUnique(*input.GrantReadACP, ",")
				for _, str := range readACPList {
					defaultGrantees = append(defaultGrantees, Grantee{Access: str, Permission: "READ_ACP"})
				}
			}
			if input.GrantWrite != nil && *input.GrantWrite != "" {
				writeList = splitUnique(*input.GrantWrite, ",")
				for _, str := range writeList {
					defaultGrantees = append(defaultGrantees, Grantee{Access: str, Permission: "WRITE"})
				}
			}
			if input.GrantWriteACP != nil && *input.GrantWriteACP != "" {
				writeACPList = splitUnique(*input.GrantWriteACP, ",")
				for _, str := range writeACPList {
					defaultGrantees = append(defaultGrantees, Grantee{Access: str, Permission: "WRITE_ACP"})
				}
			}

			accs = append(append(append(append(fullControlList, readList...), writeACPList...), readACPList...), writeList...)
		} else {
			cache := make(map[string]bool)
			for _, grt := range input.AccessControlPolicy.Grants {
				if grt.Grantee == nil || grt.Grantee.ID == nil || grt.Permission == "" {
					return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
				}
				defaultGrantees = append(defaultGrantees, Grantee{Access: *grt.Grantee.ID, Permission: grt.Permission})
				if _, ok := cache[*grt.Grantee.ID]; !ok {
					cache[*grt.Grantee.ID] = true
					accs = append(accs, *grt.Grantee.ID)
				}
			}
		}

		// Check if the specified accounts exist
		accList, err := CheckIfAccountsExist(accs, iam)
		if err != nil {
			return nil, err
		}
		if len(accList) > 0 {
			return nil, fmt.Errorf("accounts does not exist: %s", strings.Join(accList, ", "))
		}
	}

	acl.Grantees = defaultGrantees

	result, err := json.Marshal(acl)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func CheckIfAccountsExist(accs []string, iam IAMService) ([]string, error) {
	result := []string{}

	for _, acc := range accs {
		_, err := iam.GetUserAccount(acc)
		if err != nil {
			if err == ErrNoSuchUser {
				result = append(result, acc)
				continue
			}
			if err == ErrNotSupported {
				return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
			}
			return nil, fmt.Errorf("check user account: %w", err)
		}
	}
	return result, nil
}

func splitUnique(s, divider string) []string {
	elements := strings.Split(s, divider)
	uniqueElements := make(map[string]bool)
	result := make([]string, 0, len(elements))

	for _, element := range elements {
		if _, ok := uniqueElements[element]; !ok {
			result = append(result, element)
			uniqueElements[element] = true
		}
	}

	return result
}

func verifyACL(acl ACL, access string, permission types.Permission) error {
	grantee := Grantee{Access: access, Permission: permission}
	granteeFullCtrl := Grantee{Access: access, Permission: "FULL_CONTROL"}
	granteeAllUsers := Grantee{Access: "all-users", Permission: permission}

	isFound := false

	for _, grt := range acl.Grantees {
		if grt == grantee || grt == granteeFullCtrl || grt == granteeAllUsers {
			isFound = true
			break
		}
	}

	if isFound {
		return nil
	}

	return s3err.GetAPIError(s3err.ErrAccessDenied)
}

func MayCreateBucket(acct Account, isRoot bool) error {
	if isRoot {
		return nil
	}

	if acct.Role == RoleUser {
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

type AccessOptions struct {
	Acl           ACL
	AclPermission types.Permission
	IsRoot        bool
	Acc           Account
	Bucket        string
	Object        string
	Action        Action
	Readonly      bool
}

func VerifyAccess(ctx context.Context, be backend.Backend, opts AccessOptions) error {
	if opts.Readonly {
		if opts.AclPermission == types.PermissionWrite || opts.AclPermission == types.PermissionWriteAcp {
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
		AclPermission: types.PermissionRead,
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
