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

func TestBucketPolicyDecision_Condition(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		action  Action
		object  string
		condCtx map[string][]string
		want    policyDecision
	}{
		{
			name: "Allow with matching Condition grants access",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
				"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				"Condition":{"StringEquals":{"aws:UserAgent":"good-agent"}}}]}`,
			action:  GetObjectAction,
			object:  "key",
			condCtx: map[string][]string{"aws:UserAgent": {"good-agent"}},
			want:    policyDecisionAllow,
		},
		{
			name: "Allow with non-matching Condition does not grant access",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
				"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				"Condition":{"StringEquals":{"aws:UserAgent":"good-agent"}}}]}`,
			action:  GetObjectAction,
			object:  "key",
			condCtx: map[string][]string{"aws:UserAgent": {"bad-agent"}},
			want:    policyDecisionNoMatch,
		},
		{
			name: "Allow with no matching context key does not grant access",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
				"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				"Condition":{"StringEquals":{"aws:UserAgent":"good-agent"}}}]}`,
			action:  GetObjectAction,
			object:  "key",
			condCtx: nil,
			want:    policyDecisionNoMatch,
		},
		{
			name: "Deny with matching Condition wins over an unconditional Allow",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"},
				{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			action:  GetObjectAction,
			object:  "key",
			condCtx: map[string][]string{"aws:SourceIp": {"10.1.2.3"}},
			want:    policyDecisionDeny,
		},
		{
			name: "Deny with non-matching Condition leaves the unconditional Allow standing",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"},
				{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			action:  GetObjectAction,
			object:  "key",
			condCtx: map[string][]string{"aws:SourceIp": {"203.0.113.5"}},
			want:    policyDecisionAllow,
		},
		{
			// s3:prefix, wired up from the request's "prefix" query param by
			// the S3 auth middleware, is exercised end to end against a
			// ListBucket-shaped policy.
			name: "s3:prefix condition key matches against ListBucket",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
				"Action":"s3:ListBucket","Resource":"arn:aws:s3:::mybucket",
				"Condition":{"StringEquals":{"s3:prefix":"photos/"}}}]}`,
			action:  ListBucketAction,
			object:  "",
			condCtx: map[string][]string{"s3:prefix": {"photos/"}},
			want:    policyDecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, _, err := verifyBucketPolicy([]byte(tt.policy), Account{Access: "someaccess"}, "mybucket", tt.object, tt.condCtx, nil, tt.action)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, decision)
		})
	}
}

func TestBucketPolicyDecision_UnevaluableConditionFailsClosed(t *testing.T) {
	// This shape (an unrecognized operator) can no longer be written via
	// PutBucketPolicy once write-time validation rejects it - this test
	// exercises the defense-in-depth fallback for a document that reached
	// storage some other way (a legacy write, a migration, ...), the same
	// scenario iamapi/policy.EvaluateIdentityPolicies guards against.
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
		"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
		"Condition":{"SomeFutureOperator":{"aws:UserAgent":"good-agent"}}}]}`

	decision, _, err := verifyBucketPolicy([]byte(policy), Account{Access: "someaccess"}, "mybucket", "key", nil, nil, GetObjectAction)
	assert.NoError(t, err)
	assert.Equal(t, policyDecisionDeny, decision)
}

func TestVerifyPublicBucketPolicy_Condition(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		condCtx map[string][]string
		wantErr error
	}{
		{
			name: "public Allow with matching Condition grants access",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
				"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				"Condition":{"StringEquals":{"aws:UserAgent":"good-agent"}}}]}`,
			condCtx: map[string][]string{"aws:UserAgent": {"good-agent"}},
			wantErr: nil,
		},
		{
			name: "public Allow with non-matching Condition denies access",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
				"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*",
				"Condition":{"StringEquals":{"aws:UserAgent":"good-agent"}}}]}`,
			condCtx: map[string][]string{"aws:UserAgent": {"bad-agent"}},
			wantErr: errAccessDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPublicBucketPolicy([]byte(tt.policy), "mybucket", "key", tt.condCtx, nil, GetObjectAction)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.Equal(t, tt.wantErr, err)
		})
	}
}
