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
	"encoding/xml"
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

// IsPublic specifies if the acl grants public read access
func (acl *ACL) IsPublic(permission Permission) bool {
	for _, grt := range acl.Grantees {
		if grt.Permission == permission && grt.Type == types.TypeGroup && grt.Access == "all-users" {
			return true
		}
	}

	return false
}

type Grantee struct {
	Permission Permission
	Access     string
	Type       types.Type
}

type GetBucketAclOutput struct {
	XMLName           xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy"`
	Owner             *types.Owner
	AccessControlList AccessControlList
}

type PutBucketAclInput struct {
	Bucket              *string
	ACL                 types.BucketCannedACL
	AccessControlPolicy *AccessControlPolicy
	GrantFullControl    *string
	GrantRead           *string
	GrantReadACP        *string
	GrantWrite          *string
	GrantWriteACP       *string
}

type AccessControlPolicy struct {
	AccessControlList AccessControlList `xml:"AccessControlList"`
	Owner             *types.Owner
}

func (acp *AccessControlPolicy) Validate() error {
	if !acp.AccessControlList.isValid() {
		return s3err.GetAPIError(s3err.ErrMalformedACL)
	}

	// The Owner can't be nil
	if acp.Owner == nil {
		return s3err.GetAPIError(s3err.ErrMalformedACL)
	}

	// The Owner ID can't be empty
	if acp.Owner.ID == nil || *acp.Owner.ID == "" {
		return s3err.GetAPIError(s3err.ErrMalformedACL)
	}

	return nil
}

type AccessControlList struct {
	Grants []Grant `xml:"Grant"`
}

// Validates the AccessControlList
func (acl *AccessControlList) isValid() bool {
	for _, el := range acl.Grants {
		if !el.isValid() {
			return false
		}
	}

	return true
}

type Permission string

const (
	PermissionFullControl Permission = "FULL_CONTROL"
	PermissionWrite       Permission = "WRITE"
	PermissionWriteAcp    Permission = "WRITE_ACP"
	PermissionRead        Permission = "READ"
	PermissionReadAcp     Permission = "READ_ACP"
)

// Check if the permission is valid
func (p Permission) isValid() bool {
	return p == PermissionFullControl ||
		p == PermissionRead ||
		p == PermissionReadAcp ||
		p == PermissionWrite ||
		p == PermissionWriteAcp
}

type Grant struct {
	Grantee    *Grt       `xml:"Grantee"`
	Permission Permission `xml:"Permission"`
}

// Checks if Grant is valid
func (g *Grant) isValid() bool {
	return g.Permission.isValid() && g.Grantee.isValid()
}

type Grt struct {
	XMLNS string     `xml:"xmlns:xsi,attr"`
	Type  types.Type `xml:"xsi:type,attr"`
	ID    string     `xml:"ID"`
}

// Custom Unmarshalling for Grt to parse xsi:type properly
func (g *Grt) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Iterate through the XML tokens to process the attributes
	for _, attr := range start.Attr {
		// Check if the attribute is xsi:type and belongs to the xsi namespace
		if attr.Name.Space == "http://www.w3.org/2001/XMLSchema-instance" && attr.Name.Local == "type" {
			g.Type = types.Type(attr.Value)
		}
		// Handle xmlns:xsi
		if attr.Name.Local == "xmlns:xsi" {
			g.XMLNS = attr.Value
		}
	}

	// Decode the inner XML elements like ID
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "ID" {
				if err := d.DecodeElement(&g.ID, &se); err != nil {
					return err
				}
			}
		case xml.EndElement:
			if se.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}

// Validates Grt
func (g *Grt) isValid() bool {
	// Validate the Type
	// Only these 2 types are supported in the gateway
	if g.Type != types.TypeCanonicalUser && g.Type != types.TypeGroup {
		return false
	}

	// The ID prop shouldn't be empty
	if g.ID == "" {
		return false
	}

	return true
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

func ParseACLOutput(data []byte, owner string) (GetBucketAclOutput, error) {
	grants := []Grant{}

	if len(data) == 0 {
		return GetBucketAclOutput{
			Owner: &types.Owner{
				ID: &owner,
			},
			AccessControlList: AccessControlList{
				Grants: grants,
			},
		}, nil
	}

	var acl ACL
	if err := json.Unmarshal(data, &acl); err != nil {
		return GetBucketAclOutput{}, fmt.Errorf("parse acl: %w", err)
	}

	for _, elem := range acl.Grantees {
		acs := elem.Access
		grants = append(grants, Grant{
			Grantee: &Grt{
				XMLNS: "http://www.w3.org/2001/XMLSchema-instance",
				ID:    acs,
				Type:  elem.Type,
			},
			Permission: elem.Permission,
		})
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

func UpdateACL(input *PutBucketAclInput, acl ACL, iam IAMService, isAdmin bool) ([]byte, error) {
	if input == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	defaultGrantees := []Grantee{
		{
			Permission: PermissionFullControl,
			Access:     acl.Owner,
			Type:       types.TypeCanonicalUser,
		},
	}

	// if the ACL is specified, set the ACL, else replace the grantees
	if input.ACL != "" {
		switch input.ACL {
		case types.BucketCannedACLPublicRead:
			defaultGrantees = append(defaultGrantees, Grantee{
				Permission: PermissionRead,
				Access:     "all-users",
				Type:       types.TypeGroup,
			})
		case types.BucketCannedACLPublicReadWrite:
			defaultGrantees = append(defaultGrantees, []Grantee{
				{
					Permission: PermissionRead,
					Access:     "all-users",
					Type:       types.TypeGroup,
				},
				{
					Permission: PermissionWrite,
					Access:     "all-users",
					Type:       types.TypeGroup,
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
					defaultGrantees = append(defaultGrantees, Grantee{
						Access:     str,
						Permission: PermissionFullControl,
						Type:       types.TypeCanonicalUser,
					})
				}
			}
			if input.GrantRead != nil && *input.GrantRead != "" {
				readList = splitUnique(*input.GrantRead, ",")
				for _, str := range readList {
					defaultGrantees = append(defaultGrantees, Grantee{
						Access:     str,
						Permission: PermissionRead,
						Type:       types.TypeCanonicalUser,
					})
				}
			}
			if input.GrantReadACP != nil && *input.GrantReadACP != "" {
				readACPList = splitUnique(*input.GrantReadACP, ",")
				for _, str := range readACPList {
					defaultGrantees = append(defaultGrantees, Grantee{
						Access:     str,
						Permission: PermissionReadAcp,
						Type:       types.TypeCanonicalUser,
					})
				}
			}
			if input.GrantWrite != nil && *input.GrantWrite != "" {
				writeList = splitUnique(*input.GrantWrite, ",")
				for _, str := range writeList {
					defaultGrantees = append(defaultGrantees, Grantee{
						Access:     str,
						Permission: PermissionWrite,
						Type:       types.TypeCanonicalUser,
					})
				}
			}
			if input.GrantWriteACP != nil && *input.GrantWriteACP != "" {
				writeACPList = splitUnique(*input.GrantWriteACP, ",")
				for _, str := range writeACPList {
					defaultGrantees = append(defaultGrantees, Grantee{
						Access:     str,
						Permission: PermissionWriteAcp,
						Type:       types.TypeCanonicalUser,
					})
				}
			}

			accs = append(append(append(append(fullControlList, readList...), writeACPList...), readACPList...), writeList...)
		} else {
			cache := make(map[string]bool)
			for _, grt := range input.AccessControlPolicy.AccessControlList.Grants {
				if grt.Grantee == nil || grt.Grantee.ID == "" || grt.Permission == "" {
					return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
				}

				access := grt.Grantee.ID
				defaultGrantees = append(defaultGrantees, Grantee{
					Access:     access,
					Permission: grt.Permission,
					Type:       types.TypeCanonicalUser,
				})
				if _, ok := cache[access]; !ok {
					cache[access] = true
					accs = append(accs, access)
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
			if errors.Is(err, s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)) {
				return nil, err
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

func verifyACL(acl ACL, access string, permission Permission) error {
	grantee := Grantee{
		Access:     access,
		Permission: permission,
		Type:       types.TypeCanonicalUser,
	}
	granteeFullCtrl := Grantee{
		Access:     access,
		Permission: PermissionFullControl,
		Type:       types.TypeCanonicalUser,
	}
	granteeAllUsers := Grantee{
		Access:     "all-users",
		Permission: permission,
		Type:       types.TypeGroup,
	}

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

// Verifies if the bucket acl grants public access
func VerifyPublicBucketACL(ctx context.Context, be backend.Backend, bucket string, action Action, permission Permission) error {
	aclBytes, err := be.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: &bucket,
	})
	if err != nil {
		return err
	}

	acl, err := ParseACL(aclBytes)
	if err != nil {
		return err
	}

	if !acl.IsPublic(permission) {
		return ErrAccessDenied
	}

	return nil
}

// UpdateBucketACLOwner sets default ACL with new owner and removes
// any previous bucket policy that was in place
func UpdateBucketACLOwner(ctx context.Context, be backend.Backend, bucket, newOwner string) error {
	acl := ACL{
		Owner: newOwner,
		Grantees: []Grantee{
			{
				Permission: PermissionFullControl,
				Access:     newOwner,
				Type:       types.TypeCanonicalUser,
			},
		},
	}

	result, err := json.Marshal(acl)
	if err != nil {
		return fmt.Errorf("marshal ACL: %w", err)
	}

	err = be.PutBucketAcl(ctx, bucket, result)
	if err != nil {
		return err
	}

	return be.DeleteBucketPolicy(ctx, bucket)
}
