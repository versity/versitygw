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
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/xattr"
	"github.com/versity/versitygw/s3err"
)

type ACL struct {
	ACL      types.BucketCannedACL
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
	Grants []types.Grant
}

type ACLService interface {
	VerifyACL(bucket, access string, permission types.Permission, isRoot bool) error
	IsAdmin(access string, isRoot bool) error
}

type ACLServiceUnsupported struct{}

var _ ACLService = &ACLServiceUnsupported{}

func (ACLServiceUnsupported) VerifyACL(bucket, access string, permission types.Permission, isRoot bool) error {
	var ACL ACL

	if isRoot {
		return nil
	}

	acl, err := xattr.Get(bucket, "user.acl")
	if err != nil {
		return fmt.Errorf("get acl: %w", err)
	}

	if err := json.Unmarshal(acl, &ACL); err != nil {
		return fmt.Errorf("parse acl: %w", err)
	}
	if ACL.Owner == access {
		return nil
	}

	if ACL.ACL != "" {
		if (permission == "READ" || permission == "READ_ACP") && (ACL.ACL != "public-read" && ACL.ACL != "public-read-write") {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
		if (permission == "WRITE" || permission == "WRITE_ACP") && ACL.ACL != "public-read-write" {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}

		return nil
	} else {
		grantee := Grantee{Access: access, Permission: permission}
		granteeFullCtrl := Grantee{Access: access, Permission: "FULL_CONTROL"}

		isFound := false

		for _, grt := range ACL.Grantees {
			if grt == grantee || grt == granteeFullCtrl {
				isFound = true
				break
			}
		}

		if isFound {
			return nil
		}
	}

	return s3err.GetAPIError(s3err.ErrAccessDenied)
}

func (ACLServiceUnsupported) IsAdmin(access string, isRoot bool) error {
	var data IAMConfig

	if isRoot {
		return nil
	}

	file, err := os.ReadFile("users.json")
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if err := json.Unmarshal(file, &data); err != nil {
		return err
	}

	acc, ok := data.AccessAccounts[access]
	if !ok {
		return fmt.Errorf("user does not exist")
	}

	if acc.Role == "admin" {
		return nil
	}
	return fmt.Errorf("only admin users have access to this resource")
}
