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

	"github.com/stretchr/testify/assert"
)

func actionSet(actions ...Action) Actions {
	a := make(Actions, len(actions))
	for _, act := range actions {
		a[act] = struct{}{}
	}
	return a
}

func TestValidateBucketPolicyCondition(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		actions Actions
		// wantErr is compared by message text, not type: unrecognized-operator
		// errors carry a dynamic operator name via fmt.Errorf rather than a
		// policyErr constant.
		wantErr error
	}{
		{
			name:    "no condition is valid",
			raw:     ``,
			actions: actionSet(GetObjectAction),
		},
		{
			name:    "recognized generic key with any action",
			raw:     `{"StringEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/foo"}}`,
			actions: actionSet(GetObjectAction),
		},
		{
			// AWS: "AWS:SourceIp" (uppercase prefix) is accepted the same
			// as "aws:SourceIp" - key names are case-insensitive.
			name:    "condition key recognized case-insensitively",
			raw:     `{"IpAddress":{"AWS:SourceIp":"10.0.0.0/8"}}`,
			actions: actionSet(GetObjectAction),
		},
		{
			name:    "unrecognized operator",
			raw:     `{"NotARealOperator":{"aws:SourceIp":"1.2.3.4/32"}}`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErr("Invalid Condition type : NotARealOperator"),
		},
		{
			// AWS is case-sensitive about operator names specifically,
			// unlike condition keys.
			name:    "operator name is case-sensitive",
			raw:     `{"stringequals":{"s3:prefix":"foo"}}`,
			actions: actionSet(ListBucketAction),
			wantErr: policyErr("Invalid Condition type : stringequals"),
		},
		{
			name:    "unrecognized condition key",
			raw:     `{"StringEquals":{"s3:FakeKeyDoesNotExist":"foo"}}`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErrInvalidConditionKey,
		},
		{
			name:    "s3-specific key rejected for an unsupported action",
			raw:     `{"StringEquals":{"s3:prefix":"foo"}}`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErrConditionActionMismatch,
		},
		{
			name:    "s3-specific key accepted for its supported action",
			raw:     `{"StringEquals":{"s3:prefix":"foo"}}`,
			actions: actionSet(ListBucketAction),
		},
		{
			// s3:prefix/delimiter/max-keys apply to
			// ListBucket/ListBucketVersions only, NOT
			// ListBucketMultipartUploads.
			name:    "s3:prefix rejected for ListBucketMultipartUploads",
			raw:     `{"StringEquals":{"s3:prefix":"foo"}}`,
			actions: actionSet(ListBucketMultipartUploadsAction),
			wantErr: policyErrConditionActionMismatch,
		},
		{
			name:    "s3:x-amz-acl accepted for PutObject",
			raw:     `{"StringEquals":{"s3:x-amz-acl":"public-read"}}`,
			actions: actionSet(PutObjectAction),
		},
		{
			name:    "s3:x-amz-acl accepted for PutBucketAcl",
			raw:     `{"StringEquals":{"s3:x-amz-acl":"public-read"}}`,
			actions: actionSet(PutBucketAclAction),
		},
		{
			name:    "s3:x-amz-acl accepted for PutObjectAcl",
			raw:     `{"StringEquals":{"s3:x-amz-acl":"public-read"}}`,
			actions: actionSet(PutObjectAclAction),
		},
		{
			name:    "s3:VersionId accepted for GetObjectVersion",
			raw:     `{"StringEquals":{"s3:VersionId":"abc123"}}`,
			actions: actionSet(GetObjectVersionAction),
		},
		{
			name:    "s3:VersionId rejected for plain GetObject",
			raw:     `{"StringEquals":{"s3:VersionId":"abc123"}}`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErrConditionActionMismatch,
		},
		{
			// Every action in an explicit multi-action list must support
			// the key, even though PutObject alone would.
			name:    "multi-action statement requires every action to support the key",
			raw:     `{"StringEquals":{"s3:x-amz-acl":"public-read"}}`,
			actions: actionSet(GetObjectAction, PutObjectAction),
			wantErr: policyErrConditionActionMismatch,
		},
		{
			// A wildcard action ("s3:*", "s3:PutObject*", …) is exempt from
			// the per-action applicability check entirely, even though it
			// covers actions the key doesn't support.
			name:    "wildcard action is exempt from the action-applicability check",
			raw:     `{"StringEquals":{"s3:x-amz-acl":"public-read"}}`,
			actions: actionSet(AllActions),
		},
		{
			name:    "aws:SourceIp with a valid CIDR",
			raw:     `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
			actions: actionSet(GetObjectAction),
		},
		{
			name:    "aws:SourceIp with a bare valid address",
			raw:     `{"IpAddress":{"aws:SourceIp":"203.0.113.5"}}`,
			actions: actionSet(GetObjectAction),
		},
		{
			name:    "aws:SourceIp with an invalid value",
			raw:     `{"IpAddress":{"aws:SourceIp":"not-an-ip"}}`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErrInvalidIPCondition,
		},
		{
			// The IP-format check is keyed by condition-key identity, not
			// by operator - it fires even under an operator that has
			// nothing to do with IP semantics.
			name:    "aws:SourceIp invalid value rejected regardless of operator",
			raw:     `{"Null":{"aws:SourceIp":"true"}}`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErrInvalidIPCondition,
		},
		{
			// A non-IP key under IpAddress is not itself validated as an
			// IP - only recognized IP-semantic keys are.
			name:    "non-IP key under IpAddress operator is not IP-validated",
			raw:     `{"IpAddress":{"aws:Referer":"not-an-ip"}}`,
			actions: actionSet(GetObjectAction),
		},
		{
			name:    "malformed condition JSON",
			raw:     `not json`,
			actions: actionSet(GetObjectAction),
			wantErr: policyErrInvalidPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBucketPolicyCondition([]byte(tt.raw), tt.actions)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.wantErr.Error())
		})
	}
}
