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

package s3api

import (
	"testing"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
)

// fixedOwnerIAM stands in for an IAM service that fixes bucket ownership,
// as the standalone IAM service does.
type fixedOwnerIAM struct{ auth.IAMService }

func (fixedOwnerIAM) BucketOwner() auth.Account { return auth.Account{Access: "owner"} }

// TestNewValidatesListBucketsScope checks that a server built without
// embedgw still refuses a wider list buckets scope with an IAM service that
// lists buckets as S3 does.
func TestNewValidatesListBucketsScope(t *testing.T) {
	tests := []struct {
		name    string
		iam     auth.IAMService
		scope   auth.ListBucketsScope
		wantErr bool
	}{
		{name: "accessible without identity policies", iam: testAdminIAM(), scope: auth.ListBucketsScopeAccessible},
		{name: "owned with a fixed owner", iam: fixedOwnerIAM{testAdminIAM()}, scope: auth.ListBucketsScopeOwned},
		{name: "accessible with a fixed owner", iam: fixedOwnerIAM{testAdminIAM()}, scope: auth.ListBucketsScopeAccessible, wantErr: true},
		{name: "all with a fixed owner", iam: fixedOwnerIAM{testAdminIAM()}, scope: auth.ListBucketsScopeAll, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(backend.BackendUnsupported{}, testAdminRoot, "us-east-1", tt.iam, nil, nil, nil, nil,
				WithConcurrencyLimiter(10, 10),
				WithQuiet(),
				WithListBucketsScope(tt.scope),
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
