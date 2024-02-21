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
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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

	// if the ACL is specified, set the ACL, else replace the grantees
	if input.ACL != "" {
		acl.ACL = input.ACL
		acl.Grantees = []Grantee{}
	} else {
		grantees := []Grantee{}
		accs := []string{}

		if input.GrantRead != nil {
			fullControlList, readList, readACPList, writeList, writeACPList := []string{}, []string{}, []string{}, []string{}, []string{}

			if *input.GrantFullControl != "" {
				fullControlList = splitUnique(*input.GrantFullControl, ",")
				for _, str := range fullControlList {
					grantees = append(grantees, Grantee{Access: str, Permission: "FULL_CONTROL"})
				}
			}
			if *input.GrantRead != "" {
				readList = splitUnique(*input.GrantRead, ",")
				for _, str := range readList {
					grantees = append(grantees, Grantee{Access: str, Permission: "READ"})
				}
			}
			if *input.GrantReadACP != "" {
				readACPList = splitUnique(*input.GrantReadACP, ",")
				for _, str := range readACPList {
					grantees = append(grantees, Grantee{Access: str, Permission: "READ_ACP"})
				}
			}
			if *input.GrantWrite != "" {
				writeList = splitUnique(*input.GrantWrite, ",")
				for _, str := range writeList {
					grantees = append(grantees, Grantee{Access: str, Permission: "WRITE"})
				}
			}
			if *input.GrantWriteACP != "" {
				writeACPList = splitUnique(*input.GrantWriteACP, ",")
				for _, str := range writeACPList {
					grantees = append(grantees, Grantee{Access: str, Permission: "WRITE_ACP"})
				}
			}

			accs = append(append(append(append(fullControlList, readList...), writeACPList...), readACPList...), writeList...)
		} else {
			cache := make(map[string]bool)
			for _, grt := range input.AccessControlPolicy.Grants {
				grantees = append(grantees, Grantee{Access: *grt.Grantee.ID, Permission: grt.Permission})
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

		acl.Grantees = grantees
		acl.ACL = ""
	}

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

func VerifyACL(acl ACL, access string, permission types.Permission, isRoot bool) error {
	if isRoot {
		return nil
	}

	if acl.Owner == access {
		return nil
	}

	if acl.ACL != "" {
		if (permission == "READ" || permission == "READ_ACP") && (acl.ACL != "public-read" && acl.ACL != "public-read-write") {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
		if (permission == "WRITE" || permission == "WRITE_ACP") && acl.ACL != "public-read-write" {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}

		return nil
	} else {
		grantee := Grantee{Access: access, Permission: permission}
		granteeFullCtrl := Grantee{Access: access, Permission: "FULL_CONTROL"}

		isFound := false

		for _, grt := range acl.Grantees {
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

func MayCreateBucket(acct Account, isRoot bool) error {
	if isRoot {
		return nil
	}

	if acct.Role == RoleUser {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}
