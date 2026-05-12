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
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

// noBucketPolicyBackend is a test stub that returns ErrNoSuchBucketPolicy for
// GetBucketPolicy and serves a configurable ACL for GetBucketAcl.
type noBucketPolicyBackend struct {
	backend.BackendUnsupported
	srcAcl ACL
}

func (b noBucketPolicyBackend) GetBucketPolicy(_ context.Context, _ string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
}

func (b noBucketPolicyBackend) GetBucketAcl(_ context.Context, _ *s3.GetBucketAclInput) ([]byte, error) {
	return json.Marshal(b.srcAcl)
}

func TestVerifyObjectCopyAccess_URLEncodedSlashSeparator(t *testing.T) {
	const testUser = "testuser"

	// Source bucket ACL: grants READ to testUser.
	srcAcl := ACL{
		Owner: "owner",
		Grantees: []Grantee{
			{
				Access:     testUser,
				Permission: PermissionRead,
				Type:       types.TypeCanonicalUser,
			},
		},
	}

	be := noBucketPolicyBackend{srcAcl: srcAcl}

	// Destination bucket ACL: testUser is the owner (DisableACL=true path).
	opts := AccessOptions{
		Acl:           ACL{Owner: testUser},
		AclPermission: PermissionWrite,
		IsRoot:        false,
		Acc:           Account{Access: testUser, Role: RoleUser},
		Bucket:        "dst-bucket",
		Object:        "dst-key",
		Actions:       []Action{PutObjectAction},
		DisableACL:    true,
	}

	tests := []struct {
		name       string
		copySource string
	}{
		{
			name:       "percent-encoded slash (%2F) as bucket/key separator",
			copySource: "my-namespace-test-container%2Ftest-blob",
		},
		{
			name:       "%2F separator with encoded chars in key",
			copySource: "src-bucket%2Fmy%20folder%2Fmy-key",
		},
		{
			name:       "%2F separator with versionId",
			copySource: "src-bucket%2Fsrc-key?versionId=abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyObjectCopyAccess(context.Background(), be, tt.copySource, opts)
			assert.NoError(t, err,
				"should accept %%2F as the bucket/key separator in x-amz-copy-source")
		})
	}
}

func TestVerifyObjectCopyAccess_LiteralSlashSeparator(t *testing.T) {
	const testUser = "testuser"

	srcAcl := ACL{
		Owner: "owner",
		Grantees: []Grantee{
			{
				Access:     testUser,
				Permission: PermissionRead,
				Type:       types.TypeCanonicalUser,
			},
		},
	}

	be := noBucketPolicyBackend{srcAcl: srcAcl}

	opts := AccessOptions{
		Acl:           ACL{Owner: testUser},
		AclPermission: PermissionWrite,
		IsRoot:        false,
		Acc:           Account{Access: testUser, Role: RoleUser},
		Bucket:        "dst-bucket",
		Object:        "dst-key",
		Actions:       []Action{PutObjectAction},
		DisableACL:    true,
	}

	err := VerifyObjectCopyAccess(context.Background(), be, "src-bucket/src-key", opts)
	assert.NoError(t, err, "literal slash separator should work")
}
