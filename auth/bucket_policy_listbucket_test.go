// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyGrantsListBucket(t *testing.T) {
	const bucket = "my-bucket"
	const account = "alice"

	// policyStmt builds a single-statement bucket policy JSON document.
	policyStmt := func(effect, principal, action, resource string) []byte {
		return []byte(fmt.Sprintf(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "%s",
				"Principal": %s,
				"Action": %s,
				"Resource": %s
			}]
		}`, effect, principal, action, resource))
	}

	// multiStmt builds a two-statement policy (e.g. Allow + Deny).
	multiStmt := func(stmts ...string) []byte {
		stmtsJSON := ""
		for i, s := range stmts {
			if i > 0 {
				stmtsJSON += ","
			}
			stmtsJSON += s
		}
		return []byte(fmt.Sprintf(`{
			"Version": "2012-10-17",
			"Statement": [%s]
		}`, stmtsJSON))
	}

	stmt := func(effect, principal, action, resource string) string {
		return fmt.Sprintf(`{
			"Effect": "%s",
			"Principal": %s,
			"Action": %s,
			"Resource": %s
		}`, effect, principal, action, resource)
	}

	bucketARN := fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket)
	bucketObjARN := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)

	tests := []struct {
		name   string
		policy []byte
		want   bool
	}{
		{
			name:   "nil policy",
			policy: nil,
			want:   false,
		},
		{
			name:   "empty policy",
			policy: []byte{},
			want:   false,
		},
		{
			name:   "grants ListBucket to account",
			policy: policyStmt("Allow", `["alice"]`, `["s3:ListBucket"]`, fmt.Sprintf(`[%s, %s]`, bucketARN, bucketObjARN)),
			want:   true,
		},
		{
			name:   "grants ListBucket to different account",
			policy: policyStmt("Allow", `["bob"]`, `["s3:ListBucket"]`, fmt.Sprintf(`[%s, %s]`, bucketARN, bucketObjARN)),
			want:   false,
		},
		{
			name:   "grants only GetObject not ListBucket",
			policy: policyStmt("Allow", `["alice"]`, `["s3:GetObject"]`, fmt.Sprintf(`[%s, %s]`, bucketARN, bucketObjARN)),
			want:   false,
		},
		{
			name:   "grants s3 wildcard action",
			policy: policyStmt("Allow", `["alice"]`, `["s3:*"]`, fmt.Sprintf(`[%s, %s]`, bucketARN, bucketObjARN)),
			want:   true,
		},
		{
			name:   "public principal grants ListBucket",
			policy: policyStmt("Allow", `"*"`, `["s3:ListBucket"]`, bucketARN),
			want:   true,
		},
		{
			name: "explicit deny overrides allow",
			policy: multiStmt(
				stmt("Allow", `["alice"]`, `["s3:ListBucket"]`, bucketARN),
				stmt("Deny", `["alice"]`, `["s3:ListBucket"]`, bucketARN),
			),
			want: false,
		},
		{
			name:   "resource mismatch (different bucket)",
			policy: policyStmt("Allow", `["alice"]`, `["s3:ListBucket"]`, `"arn:aws:s3:::other-bucket"`),
			want:   false,
		},
		{
			name:   "malformed policy JSON",
			policy: []byte(`{not valid json`),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyGrantsListBucket(tt.policy, account, bucket)
			assert.Equal(t, tt.want, got)
		})
	}
}
