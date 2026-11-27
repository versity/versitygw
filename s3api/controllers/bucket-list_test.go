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

package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_ListBuckets(t *testing.T) {
	validRes := s3response.ListAllMyBucketsResult{
		Owner: s3response.CanonicalUser{
			ID: "root",
		},
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: []s3response.ListAllMyBucketsEntry{
				{Name: "test"},
			},
		},
	}

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "negative max buckets",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-buckets": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgumentErr(s3err.InvalidArgMaxBuckets, "-1"),
			},
		},
		{
			name: "max buckets exceeds upper limit",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-buckets": "10001",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgumentErr(s3err.InvalidArgMaxBuckets, "10001"),
			},
		},
		{
			name: "max buckets 0",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-buckets": "0",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgumentErr(s3err.InvalidArgMaxBuckets, "0"),
			},
		},
		{
			name: "invalid max buckets",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-buckets": "bla",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgMaxLimiter("max-buckets", "bla"),
			},
		},
		{
			name: "invalid bucket region",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"bucket-region": "abc",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgBucketRegion("abc"),
			},
		},
		{
			name: "bucket region of another region",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"bucket-region": "us-west-2",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgumentErr(s3err.InvalidArgBucketRegionEndpoint, ""),
			},
		},
		{
			name: "empty bucket region",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"bucket-region": "",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetInvalidArgBucketRegion(""),
			},
		},
		{
			name: "bucket region of the gateway region in uppercase",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"bucket-region": "US-EAST-1",
				},
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
				},
			},
		},
		{
			name: "bucket region of the gateway region",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"bucket-region": "us-east-1",
				},
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
				},
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:  s3response.ListAllMyBucketsResult{},
			},
			output: testOutput{
				response: &Response{},
				err:      s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"max-buckets": "3",
				},
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				ListBucketsFunc: func(contextMoqParam context.Context, listBucketsInput s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
					return tt.input.beRes.(s3response.ListAllMyBucketsResult), tt.input.beErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.ListBuckets,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					queries: tt.input.queries,
				})
		})
	}
}

// fixedOwnerIAM stands in for an IAM backend that fixes bucket ownership,
// such as the standalone IAM service.
type fixedOwnerIAM struct {
	*IAMServiceMock
}

func (fixedOwnerIAM) BucketOwner() auth.Account {
	return auth.Account{Access: "fixed-owner"}
}

func TestS3ApiController_ListBucketsScope(t *testing.T) {
	userLocals := func(access string, role auth.Role, isRoot bool) map[utils.ContextKey]any {
		return map[utils.ContextKey]any{
			utils.ContextKeyIsRoot:  isRoot,
			utils.ContextKeyAccount: auth.Account{Access: access, Role: role},
			utils.ContextKeyRegion:  "us-east-1",
		}
	}
	user := userLocals("user", auth.RoleUser, false)
	userPlus := userLocals("userplus", auth.RoleUserPlus, false)
	admin := userLocals("admin", auth.RoleAdmin, false)
	root := userLocals("root", auth.RoleAdmin, true)

	tests := []struct {
		name        string
		scope       auth.ListBucketsScope
		iam         auth.IAMService
		locals      map[utils.ContextKey]any
		wantOwner   string
		wantAll     bool
		wantVisible bool
	}{
		{name: "zero scope lists owned buckets", scope: "", locals: user, wantOwner: "user"},
		{name: "owned scope lists owned buckets", scope: auth.ListBucketsScopeOwned, locals: user, wantOwner: "user"},
		{name: "accessible scope asks about other buckets", scope: auth.ListBucketsScopeAccessible, locals: user, wantOwner: "user", wantVisible: true},
		{name: "accessible scope for userplus", scope: auth.ListBucketsScopeAccessible, locals: userPlus, wantOwner: "userplus", wantVisible: true},
		{name: "all scope lists every bucket", scope: auth.ListBucketsScopeAll, locals: user, wantOwner: "user", wantAll: true},
		{name: "admin with owned scope", scope: auth.ListBucketsScopeOwned, locals: admin, wantOwner: "admin", wantAll: true},
		{name: "admin with accessible scope", scope: auth.ListBucketsScopeAccessible, locals: admin, wantOwner: "admin", wantAll: true},
		{name: "root with owned scope", scope: auth.ListBucketsScopeOwned, locals: root, wantOwner: "root", wantAll: true},
		{name: "root with accessible scope", scope: auth.ListBucketsScopeAccessible, locals: root, wantOwner: "root", wantAll: true},
		{
			name: "fixed owner ignores the accessible scope", scope: auth.ListBucketsScopeAccessible,
			iam: fixedOwnerIAM{&IAMServiceMock{}}, locals: user, wantOwner: "fixed-owner", wantAll: true,
		},
		{
			name: "fixed owner with owned scope", scope: auth.ListBucketsScopeOwned,
			iam: fixedOwnerIAM{&IAMServiceMock{}}, locals: user, wantOwner: "fixed-owner", wantAll: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got s3response.ListBucketsInput
			be := &BackendMock{
				ListBucketsFunc: func(_ context.Context, input s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
					got = input
					return s3response.ListAllMyBucketsResult{}, nil
				},
			}
			ctrl := S3ApiController{be: be, iam: tt.iam, listBucketsScope: tt.scope}

			testController(t, ctrl.ListBuckets, &Response{Data: s3response.ListAllMyBucketsResult{}}, nil, ctxInputs{
				locals:  tt.locals,
				queries: map[string]string{"prefix": "b", "max-buckets": "5", "continuation-token": "a"},
			})

			assert.Equal(t, tt.wantOwner, got.Owner)
			assert.Equal(t, tt.wantAll, got.IsAdmin)
			assert.Equal(t, tt.wantVisible, got.IsVisible != nil, "IsVisible set")
			assert.Equal(t, "b", got.Prefix)
			assert.Equal(t, int32(5), got.MaxBuckets)
			assert.Equal(t, "a", got.ContinuationToken)
		})
	}
}

func TestS3ApiController_bucketVisibility(t *testing.T) {
	const bucket = "shared"
	caller := auth.Account{Access: "reader", Role: auth.RoleUser}
	readGrant := []byte(`{"Owner":"root","Grantees":[{"Permission":"READ","Access":"reader","Type":"CanonicalUser"}]}`)
	rootOnly := []byte(`{"Owner":"root","Grantees":[{"Permission":"FULL_CONTROL","Access":"root","Type":"CanonicalUser"}]}`)
	allowReader := []byte(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"reader"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared"}]}`)
	denyAll := []byte(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared"}]}`)
	backendErr := errors.New("backend down")

	tests := []struct {
		name       string
		acl        []byte
		policy     []byte
		policyErr  error
		disableACL bool
		want       bool
		wantErr    error
	}{
		{name: "ACL grant without a policy", acl: readGrant, policyErr: s3err.GetBucketErr(s3err.ErrNoSuchBucketPolicy, bucket), want: true},
		{name: "no grant without a policy", acl: rootOnly, policyErr: s3err.GetBucketErr(s3err.ErrNoSuchBucketPolicy, bucket), want: false},
		{name: "ACL grant with ACLs disabled", acl: readGrant, policyErr: s3err.GetBucketErr(s3err.ErrNoSuchBucketPolicy, bucket), disableACL: true, want: false},
		{name: "policy grant", acl: rootOnly, policy: allowReader, want: true},
		{name: "policy grant with ACLs disabled", acl: rootOnly, policy: allowReader, disableACL: true, want: true},
		{name: "policy deny hides an ACL grant", acl: readGrant, policy: denyAll, want: false},
		{name: "empty ACL", acl: nil, policy: allowReader, want: true},
		{name: "deleted bucket is skipped", acl: readGrant, policyErr: s3err.GetBucketErr(s3err.ErrNoSuchBucket, bucket), want: false},
		{name: "unparsable policy hides the bucket", acl: readGrant, policy: []byte(`{`), want: false},
		{name: "backend error is returned", acl: readGrant, policyErr: backendErr, wantErr: backendErr},
		{name: "unparsable ACL is an error", acl: []byte(`{`), policy: allowReader, wantErr: errors.New("parse acl")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				GetBucketPolicyFunc: func(_ context.Context, b string) ([]byte, error) {
					assert.Equal(t, bucket, b)
					return tt.policy, tt.policyErr
				},
			}
			ctrl := S3ApiController{be: be, disableACL: tt.disableACL, listBucketsScope: auth.ListBucketsScopeAccessible}

			got, err := ctrl.bucketVisibility(caller, nil)(context.Background(), bucket, tt.acl)
			if tt.wantErr != nil {
				assert.ErrorContains(t, err, tt.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestS3ApiController_bucketVisibility_conditionContext checks that the
// callback evaluates conditions against the ListBuckets request itself: the
// test request is plain HTTP, so aws:SecureTransport is false.
func TestS3ApiController_bucketVisibility_conditionContext(t *testing.T) {
	for _, tt := range []struct {
		secureTransport string
		want            bool
	}{
		{secureTransport: "false", want: true},
		{secureTransport: "true", want: false},
	} {
		t.Run("aws:SecureTransport "+tt.secureTransport, func(t *testing.T) {
			policy := []byte(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"user"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared",` +
				`"Condition":{"StringLike":{"s3:prefix":"team-a/*"},"Bool":{"aws:SecureTransport":"` + tt.secureTransport + `"}}}]}`)

			var visible bool
			be := &BackendMock{
				ListBucketsFunc: func(ctx context.Context, input s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
					var err error
					visible, err = input.IsVisible(ctx, "shared", []byte(`{"Owner":"root"}`))
					return s3response.ListAllMyBucketsResult{}, err
				},
				GetBucketPolicyFunc: func(context.Context, string) ([]byte, error) {
					return policy, nil
				},
			}
			ctrl := S3ApiController{be: be, listBucketsScope: auth.ListBucketsScopeAccessible}

			testController(t, ctrl.ListBuckets, &Response{Data: s3response.ListAllMyBucketsResult{}}, nil, ctxInputs{
				locals:  accessDeniedLocals,
				queries: map[string]string{"prefix": "b"},
			})
			assert.Equal(t, tt.want, visible, "bucket visible")
		})
	}
}
