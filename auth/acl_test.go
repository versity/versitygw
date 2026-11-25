// Copyright 2026 Versity Software
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
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
)

// existingAccountsIAM resolves every access key id it is asked about, so
// UpdateACL accepts any grantee.
type existingAccountsIAM struct {
	IAMService
}

func (existingAccountsIAM) ResolveAccounts([]string) ([]string, error) {
	return nil, nil
}

// TestUpdateACL checks which grants end up in the bucket ACL. Grant headers
// and an AccessControlPolicy body replace the ACL, as on AWS, so the owner
// gets a FULL_CONTROL grant only from a canned ACL, from the default ACL of
// a bucket created without grants, or when the request names it.
func TestUpdateACL(t *testing.T) {
	empty := ""
	userGrantee := "user1"
	ownerGrantee := "owner"

	ownerFullControl := Grantee{
		Permission: PermissionFullControl,
		Access:     "owner",
		Type:       types.TypeCanonicalUser,
	}

	tests := []struct {
		name  string
		input *PutBucketAclInput
		want  []Grantee
	}{
		{
			name: "grant header",
			input: &PutBucketAclInput{
				GrantReadACP: &userGrantee,
			},
			want: []Grantee{
				{
					Permission: PermissionReadAcp,
					Access:     "user1",
					Type:       types.TypeCanonicalUser,
				},
			},
		},
		{
			name: "grant header naming the owner",
			input: &PutBucketAclInput{
				GrantFullControl: &ownerGrantee,
			},
			want: []Grantee{ownerFullControl},
		},
		{
			name: "grant headers naming the owner and another user",
			input: &PutBucketAclInput{
				GrantFullControl: &ownerGrantee,
				GrantRead:        &userGrantee,
			},
			want: []Grantee{
				ownerFullControl,
				{
					Permission: PermissionRead,
					Access:     "user1",
					Type:       types.TypeCanonicalUser,
				},
			},
		},
		{
			name: "same grantee in two grant headers",
			input: &PutBucketAclInput{
				GrantRead:     &userGrantee,
				GrantWriteACP: &userGrantee,
			},
			want: []Grantee{
				{
					Permission: PermissionRead,
					Access:     "user1",
					Type:       types.TypeCanonicalUser,
				},
				{
					Permission: PermissionWriteAcp,
					Access:     "user1",
					Type:       types.TypeCanonicalUser,
				},
			},
		},
		{
			name: "access control policy without the owner",
			input: &PutBucketAclInput{
				AccessControlPolicy: &AccessControlPolicy{
					Owner: &types.Owner{ID: &ownerGrantee},
					AccessControlList: AccessControlList{
						Grants: []Grant{
							{
								Grantee:    &Grt{ID: "user1", Type: types.TypeCanonicalUser},
								Permission: PermissionRead,
							},
							{
								Grantee:    &Grt{ID: "user2", Type: types.TypeCanonicalUser},
								Permission: PermissionWrite,
							},
						},
					},
				},
			},
			want: []Grantee{
				{
					Permission: PermissionRead,
					Access:     "user1",
					Type:       types.TypeCanonicalUser,
				},
				{
					Permission: PermissionWrite,
					Access:     "user2",
					Type:       types.TypeCanonicalUser,
				},
			},
		},
		{
			name: "access control policy with no grants",
			input: &PutBucketAclInput{
				AccessControlPolicy: &AccessControlPolicy{
					Owner: &types.Owner{ID: &ownerGrantee},
				},
			},
			want: []Grantee{},
		},
		{
			name: "create bucket without grants",
			input: &PutBucketAclInput{
				GrantFullControl:    &empty,
				GrantRead:           &empty,
				GrantReadACP:        &empty,
				GrantWrite:          &empty,
				GrantWriteACP:       &empty,
				AccessControlPolicy: &AccessControlPolicy{},
			},
			want: []Grantee{ownerFullControl},
		},
		{
			name: "canned acl",
			input: &PutBucketAclInput{
				ACL: types.BucketCannedACLPublicRead,
			},
			want: []Grantee{
				ownerFullControl,
				{
					Permission: PermissionRead,
					Access:     "all-users",
					Type:       types.TypeGroup,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aclJSON, err := UpdateACL(tt.input, ACL{Owner: "owner"}, existingAccountsIAM{})
			assert.NoError(t, err)

			acl, err := ParseACL(aclJSON)
			assert.NoError(t, err)
			assert.Equal(t, "owner", acl.Owner)
			assert.Equal(t, tt.want, acl.Grantees)
		})
	}
}
