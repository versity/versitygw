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
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

// testFiberCtx returns a fiber.Ctx for tests to pass to functions that read
// request-derived data (e.g. the condition context) off it, released
// automatically when the test ends.
func testFiberCtx(t *testing.T) fiber.Ctx {
	t.Helper()
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	t.Cleanup(func() {
		app.ReleaseCtx(ctx)
	})
	return ctx
}

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

type publicBucketPolicyBackend struct {
	backend.BackendUnsupported
	policy      []byte
	acl         ACL
	aclCalls    int
	normalizeFn objectKeyNormalizer
}

func (b *publicBucketPolicyBackend) GetBucketPolicy(_ context.Context, _ string) ([]byte, error) {
	return b.policy, nil
}

func (b *publicBucketPolicyBackend) GetBucketAcl(_ context.Context, _ *s3.GetBucketAclInput) ([]byte, error) {
	b.aclCalls++
	return json.Marshal(b.acl)
}

func (b *publicBucketPolicyBackend) NormalizeObjectKey(bucket, key string) string {
	if b.normalizeFn == nil {
		return b.BackendUnsupported.NormalizeObjectKey(bucket, key)
	}

	return b.normalizeFn(bucket, key)
}

func testNormalizeObjectKey(bucket, key string) string {
	fullPath := filepath.Join(bucket, key)
	normalizedKey, err := filepath.Rel(filepath.Clean(bucket), fullPath)
	if err != nil {
		return fullPath
	}
	if normalizedKey == "." {
		return ""
	}

	return normalizedKey
}

func publicReadACL() ACL {
	return ACL{
		Owner: "owner",
		Grantees: []Grantee{
			{
				Permission: PermissionRead,
				Access:     "all-users",
				Type:       types.TypeGroup,
			},
		},
	}
}

// mockPolicyEvaluator implements IAMService (via the embedded
// IAMServiceSingle, whose methods are never exercised here) and
// PolicyEvaluator, recording every EvaluatePolicy call so tests can assert
// both the outcome and exactly what VerifyAccess asked it to evaluate.
type mockPolicyEvaluator struct {
	IAMService
	decision     policyDecision
	principalArn string
	err          error
	calls        []evaluatePolicyCall
}

type evaluatePolicyCall struct {
	access, sessionToken string
	resources            []string
	actions              []Action
	condition            map[string][]string
}

func (m *mockPolicyEvaluator) EvaluatePolicy(access, sessionToken string, actions []Action, resources []string, condition map[string][]string) (PolicyEvaluation, error) {
	m.calls = append(m.calls, evaluatePolicyCall{
		access:       access,
		sessionToken: sessionToken,
		actions:      actions,
		resources:    resources,
		condition:    condition,
	})
	decisions := make([][]policyDecision, len(resources))
	for i := range resources {
		decisions[i] = make([]policyDecision, len(actions))
		for j := range actions {
			decisions[i][j] = m.decision
		}
	}
	return PolicyEvaluation{Decisions: decisions, PrincipalArn: m.principalArn}, m.err
}

func newMockPolicyEvaluator(decision policyDecision) *mockPolicyEvaluator {
	return &mockPolicyEvaluator{IAMService: NewIAMServiceSingle(Account{}), decision: decision}
}

// requireAccessDeniedAPIError asserts err is an s3err.APIError with the AWS
// AccessDenied shape (Code, HTTP 403) and returns it for the caller to
// inspect the dynamic Description text further.
func requireAccessDeniedAPIError(t *testing.T, err error) s3err.APIError {
	t.Helper()
	apiErr, ok := err.(s3err.APIError)
	if !ok {
		t.Fatalf("err = %#v (%T), want s3err.APIError", err, err)
	}
	assert.Equal(t, "AccessDenied", apiErr.Code)
	assert.Equal(t, http.StatusForbidden, apiErr.HTTPStatusCode)
	return apiErr
}

// TestVerifyAccess_ResourceAllowStillChecksIdentityForExplicitDeny confirms
// the fix for the core bug: a bucket policy Allow used to short-circuit
// before the identity-policy layer was ever consulted, so an identity
// policy's explicit Deny was silently ignored whenever the bucket policy
// already allowed. Now the identity policy is always consulted too — here
// it has no opinion (NoMatch), so the bucket policy's Allow still stands,
// but EvaluatePolicy must actually have been called for that to be a real
// verdict rather than a skipped check.
func TestVerifyAccess_ResourceAllowStillChecksIdentityForExplicitDeny(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     Account{Access: "testuser", Role: RoleUser},
		Bucket:  "bucket",
		Object:  "key.txt",
		Actions: []Action{GetObjectAction},
		Iam:     pe,
	})

	assert.NoError(t, err)
	assert.Len(t, pe.calls, 1, "EvaluatePolicy must now be called even when the resource-level check already allows, so an explicit identity-policy Deny can still override it")
}

// TestVerifyAccess_IdentityExplicitDenyOverridesResourceAllow is the
// explicit-deny-wins fix: a bucket policy Allow does not save a request the
// caller's own identity policy explicitly denies. The Message names the
// resolved principal ARN and calls out "an identity-based policy" —
// matching what real AWS returns for this case.
func TestVerifyAccess_IdentityExplicitDenyOverridesResourceAllow(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	pe := newMockPolicyEvaluator(policyDecisionDeny)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     Account{Access: "testuser", Role: RoleUser},
		Bucket:  "bucket",
		Object:  "key.txt",
		Actions: []Action{GetObjectAction},
		Iam:     pe,
	})

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "s3:GetObject")
	assert.Contains(t, apiErr.Description, "with an explicit deny in an identity-based policy")
}

// TestVerifyAccess_ResourceExplicitDenyOverridesIdentityAllow is the
// reverse case: an identity policy Allow does not save a request the
// bucket policy explicitly denies. The resource-level Deny short-circuits
// before the identity policy is even consulted (it can't change the
// outcome, and it saves the standalone IAM service round trip), and the
// Message calls out "a resource-based policy".
func TestVerifyAccess_ResourceExplicitDenyOverridesIdentityAllow(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Deny",
				"Principal": "testuser",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     Account{Access: "testuser", Role: RoleUser},
		Bucket:  "bucket",
		Object:  "key.txt",
		Actions: []Action{GetObjectAction},
		Iam:     pe,
	})

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "testuser")
	assert.Contains(t, apiErr.Description, "with an explicit deny in a resource-based policy")
	assert.Empty(t, pe.calls, "a resource-level explicit deny should short-circuit before consulting the identity policy")
}

// TestVerifyAccess_IdentityPolicyAllowsWhenResourceDenies is the core
// same-account fix: a private bucket with no ACL grant and no bucket policy
// still allows access when the caller's IAM identity policy grants it —
// matching real AWS, where a bucket policy is only *required* for
// cross-account access; within the same account (this gateway is always
// single-account) an identity-based Allow alone is sufficient.
func TestVerifyAccess_IdentityPolicyAllowsWhenResourceDenies(t *testing.T) {
	be := noBucketPolicyBackend{srcAcl: ACL{Owner: "someone-else"}}
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		Object:        "key.txt",
		Actions:       []Action{GetObjectAction},
		AclPermission: PermissionRead,
		Iam:           pe,
	})

	assert.NoError(t, err)
	assert.Len(t, pe.calls, 1)
	assert.Equal(t, []string{"arn:aws:s3:::bucket/key.txt"}, pe.calls[0].resources)
	assert.Equal(t, []Action{GetObjectAction}, pe.calls[0].actions)
	assert.Equal(t, "testuser", pe.calls[0].access)
}

// TestVerifyAccess_DeniedWhenNeitherResourceNorIdentityPolicyAllows confirms
// access is denied — with the AWS-shaped implicit-deny message, since a
// PolicyEvaluator is configured — when neither the resource-level check
// (ACL owned by someone else, no bucket policy) nor the identity policy has
// any opinion at all (NoMatch, not an explicit Deny from either side). It
// also pins that the message names the resolved principal ARN, not the
// access key — matching real AWS's implicit-deny message shape (previously
// this fell back to the access key even when the PolicyEvaluator resolved
// an ARN, since identityPolicyDecision only threaded PrincipalArn through
// on its Deny branch).
func TestVerifyAccess_DeniedWhenNeitherResourceNorIdentityPolicyAllows(t *testing.T) {
	be := noBucketPolicyBackend{srcAcl: ACL{Owner: "someone-else"}}
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		Object:        "key.txt",
		Actions:       []Action{GetObjectAction},
		AclPermission: PermissionRead,
		Iam:           pe,
	})

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "because no identity-based policy allows the s3:GetObject action")
	assert.Len(t, pe.calls, 1)
}

// TestVerifyAccess_NoPolicyEvaluatorIsANoOp confirms backends that don't
// implement PolicyEvaluator (every backend except the standalone IAM
// client) are entirely unaffected by this layer — backward compatibility
// via the type assertion, not a config flag.
func TestVerifyAccess_NoPolicyEvaluatorIsANoOp(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     Account{Access: "testuser", Role: RoleUser},
		Bucket:  "bucket",
		Object:  "key.txt",
		Actions: []Action{GetObjectAction},
		Iam:     NewIAMServiceSingle(Account{}),
	})

	assert.NoError(t, err)
}

// TestVerifyAccess_NoPolicyEvaluatorDeniedKeepsGenericMessage pins that,
// with no PolicyEvaluator configured, a denied request's error stays
// byte-for-byte today's generic message — the dynamic AWS-shaped messages
// above only ever appear once a PolicyEvaluator is actually in play, so
// every internal/LDAP/Vault/IPA/S3-IAM deployment sees no message change
// from this fix at all.
func TestVerifyAccess_NoPolicyEvaluatorDeniedKeepsGenericMessage(t *testing.T) {
	be := noBucketPolicyBackend{srcAcl: ACL{Owner: "someone-else"}}

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		Object:        "key.txt",
		Actions:       []Action{GetObjectAction},
		AclPermission: PermissionRead,
		Iam:           NewIAMServiceSingle(Account{}),
	})

	assert.Equal(t, s3err.GetAPIError(s3err.ErrAccessDenied), err)
}

func TestVerifyAccess_NormalizesObjectKeyBeforePolicyMatch(t *testing.T) {
	be := &publicBucketPolicyBackend{
		normalizeFn: testNormalizeObjectKey,
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/public/*"
			}]
		}`),
	}

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     Account{Access: "testuser", Role: RoleUser},
		Bucket:  "bucket",
		Object:  "public/../private.txt",
		Actions: []Action{GetObjectAction},
	})

	assert.Error(t, err)
	assert.True(t, errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)))
}

func TestVerifyAccess_NormalizesPolicyResourceBeforeMatch(t *testing.T) {
	be := &publicBucketPolicyBackend{
		normalizeFn: testNormalizeObjectKey,
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/public/../private.txt"
			}]
		}`),
	}

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     Account{Access: "testuser", Role: RoleUser},
		Bucket:  "bucket",
		Object:  "private.txt",
		Actions: []Action{GetObjectAction},
	})

	assert.NoError(t, err)
}

func TestVerifyPublicAccess_PublicPolicyDenyStopsACLFallback(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/private/*"
			}]
		}`),
		acl: publicReadACL(),
	}

	err := VerifyPublicAccess(testFiberCtx(t), be, GetObjectAction, PermissionRead, "bucket", "private/secret.txt")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)))
	assert.Equal(t, 0, be.aclCalls)
}

func TestVerifyPublicAccess_PublicPolicyNoMatchFallsBackToACL(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/private/*"
			}]
		}`),
		acl: publicReadACL(),
	}

	err := VerifyPublicAccess(testFiberCtx(t), be, GetObjectAction, PermissionRead, "bucket", "public/object.txt")

	assert.NoError(t, err)
	assert.Equal(t, 1, be.aclCalls)
}

func TestVerifyPublicAccess_NormalizedDenyStopsACLFallback(t *testing.T) {
	be := &publicBucketPolicyBackend{
		normalizeFn: testNormalizeObjectKey,
		policy: []byte(`{
			"Statement": [{
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/private/*"
			}]
		}`),
		acl: publicReadACL(),
	}

	err := VerifyPublicAccess(testFiberCtx(t), be, GetObjectAction, PermissionRead, "bucket", "public/../private/secret.txt")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)))
	assert.Equal(t, 0, be.aclCalls)
}

func TestVerifyObjectCopyAccess_URLEncodedSlashSeparator(t *testing.T) {
	const testUser = "testuser"

	// Source and destination bucket ACLs: testUser owns both. opts sets
	// DisableACL, which now applies uniformly to the source-bucket check
	// VerifyObjectCopyAccess performs internally as well as the
	// destination's, collapsing both to an owner-only check — a grantee
	// entry alone (without ownership) would no longer be sufficient.
	srcAcl := ACL{Owner: testUser}

	be := noBucketPolicyBackend{srcAcl: srcAcl}

	opts := AccessOptions{
		Acl:           ACL{Owner: testUser},
		AclPermission: PermissionWrite,
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
			err := VerifyObjectCopyAccess(testFiberCtx(t), be, tt.copySource, opts)
			assert.NoError(t, err,
				"should accept %%2F as the bucket/key separator in x-amz-copy-source")
		})
	}
}

func TestVerifyObjectCopyAccess_LiteralSlashSeparator(t *testing.T) {
	const testUser = "testuser"

	// testUser owns both source and destination buckets — see the comment
	// in TestVerifyObjectCopyAccess_URLEncodedSlashSeparator on why
	// DisableACL requires ownership here rather than a grantee entry.
	srcAcl := ACL{Owner: testUser}

	be := noBucketPolicyBackend{srcAcl: srcAcl}

	opts := AccessOptions{
		Acl:           ACL{Owner: testUser},
		AclPermission: PermissionWrite,
		Acc:           Account{Access: testUser, Role: RoleUser},
		Bucket:        "dst-bucket",
		Object:        "dst-key",
		Actions:       []Action{PutObjectAction},
		DisableACL:    true,
	}

	err := VerifyObjectCopyAccess(testFiberCtx(t), be, "src-bucket/src-key", opts)
	assert.NoError(t, err, "literal slash separator should work")
}

// TestVerifyCreateBucketAccess_RootAndAdminBypass confirms root and admin
// accounts may always create a bucket, with no iam backend consulted at
// all — CreateBucket has no existing bucket to check a policy or ACL
// against, so this bypass (unlike VerifyAccess's, which still runs the
// resource-policy check first) is the entire decision.
func TestVerifyCreateBucketAccess_RootAndAdminBypass(t *testing.T) {
	err := VerifyCreateBucketAccess(testFiberCtx(t), NewIAMServiceSingle(Account{}), true, Account{Access: "testuser", Role: RoleUser}, "bucket")
	assert.NoError(t, err)

	err = VerifyCreateBucketAccess(testFiberCtx(t), NewIAMServiceSingle(Account{}), false, Account{Access: "testuser", Role: RoleAdmin}, "bucket")
	assert.NoError(t, err)
}

// TestVerifyCreateBucketAccess_NoPolicyEvaluatorUsesLegacyRoleGate confirms
// that for every backend without an identity-policy layer (internal, LDAP,
// Vault, IPA, S3-IAM) bucket creation keeps working exactly as it always
// has: userplus is allowed, a plain user is denied with the generic
// AccessDenied error, and EvaluatePolicy is never a factor since these
// backends don't implement PolicyEvaluator at all.
func TestVerifyCreateBucketAccess_NoPolicyEvaluatorUsesLegacyRoleGate(t *testing.T) {
	iam := NewIAMServiceSingle(Account{})

	err := VerifyCreateBucketAccess(testFiberCtx(t), iam, false, Account{Access: "testuser", Role: RoleUserPlus}, "bucket")
	assert.NoError(t, err)

	err = VerifyCreateBucketAccess(testFiberCtx(t), iam, false, Account{Access: "testuser", Role: RoleUser}, "bucket")
	assert.Equal(t, s3err.GetAPIError(s3err.ErrAccessDenied), err)
}

// TestVerifyCreateBucketAccess_PolicyEvaluatorAllow confirms the core fix:
// a standalone-IAM-service user, who is always Role RoleUser regardless of
// their attached IAM policy, can create a bucket when that policy grants
// s3:CreateBucket — the identity-policy Allow is what grants access, not
// the role.
func TestVerifyCreateBucketAccess_PolicyEvaluatorAllow(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := VerifyCreateBucketAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUser}, "bucket")

	assert.NoError(t, err)
	assert.Len(t, pe.calls, 1)
	assert.Equal(t, "testuser", pe.calls[0].access)
	assert.Equal(t, []string{"arn:aws:s3:::bucket"}, pe.calls[0].resources)
	assert.Equal(t, []Action{CreateBucketAction}, pe.calls[0].actions)
}

// TestVerifyCreateBucketAccess_PolicyEvaluatorNoMatchDenies confirms a
// standalone-IAM-service user with no policy granting s3:CreateBucket is
// denied — with the AWS-shaped implicit-deny message — even though the
// legacy role gate alone would have denied them anyway; this pins that the
// policy layer, not the role, is now what's actually being asked.
func TestVerifyCreateBucketAccess_PolicyEvaluatorNoMatchDenies(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := VerifyCreateBucketAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUser}, "bucket")

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "s3:CreateBucket")
	assert.Contains(t, apiErr.Description, "because no identity-based policy allows the s3:CreateBucket action")
}

// TestVerifyCreateBucketAccess_PolicyEvaluatorExplicitDenyWins confirms an
// explicit Deny in the identity policy is reported with the AWS-shaped
// explicit-deny message, naming the resolved principal ARN when the
// PolicyEvaluator reports one.
func TestVerifyCreateBucketAccess_PolicyEvaluatorExplicitDenyWins(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionDeny)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := VerifyCreateBucketAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUser}, "bucket")

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "s3:CreateBucket")
	assert.Contains(t, apiErr.Description, "with an explicit deny in an identity-based policy")
}

// TestVerifyCreateBucketAccess_PolicyEvaluatorIgnoresUserPlus confirms the
// legacy userplus bypass does not leak into the PolicyEvaluator path: once
// a backend implements identity-policy evaluation, that policy is the sole
// gate for non-admin accounts, matching the standalone IAM service's real
// behavior (its accounts are always Role RoleUser, never RoleUserPlus, so
// this also documents why the bypass would be a no-op there in practice).
func TestVerifyCreateBucketAccess_PolicyEvaluatorIgnoresUserPlus(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)

	err := VerifyCreateBucketAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUserPlus}, "bucket")

	assert.Error(t, err)
	assert.Len(t, pe.calls, 1, "EvaluatePolicy must be consulted even for a userplus account once a PolicyEvaluator is configured")
}

// Root and admin always list buckets, with no iam backend consulted.
func TestVerifyListAllMyBucketsAccess_RootAndAdminBypass(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionDeny)

	err := VerifyListAllMyBucketsAccess(testFiberCtx(t), pe, true, Account{Access: "testuser", Role: RoleUser})
	assert.NoError(t, err)

	err = VerifyListAllMyBucketsAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleAdmin})
	assert.NoError(t, err)

	assert.Empty(t, pe.calls, "root/admin bypass before any policy evaluation")
}

// Backends without an identity-policy layer keep listing buckets as before:
// the listing is already narrowed to the caller's own buckets.
func TestVerifyListAllMyBucketsAccess_NoPolicyEvaluatorIsUnrestricted(t *testing.T) {
	err := VerifyListAllMyBucketsAccess(testFiberCtx(t), NewIAMServiceSingle(Account{}), false, Account{Access: "testuser", Role: RoleUser})

	assert.NoError(t, err)
}

// A policy granting s3:ListAllMyBuckets allows the listing, evaluated
// against "arn:aws:s3:::*".
func TestVerifyListAllMyBucketsAccess_PolicyEvaluatorAllow(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := VerifyListAllMyBucketsAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUser})

	assert.NoError(t, err)
	assert.Len(t, pe.calls, 1)
	assert.Equal(t, "testuser", pe.calls[0].access)
	assert.Equal(t, []string{"arn:aws:s3:::*"}, pe.calls[0].resources)
	assert.Equal(t, []Action{ListAllMyBucketsAction}, pe.calls[0].actions)
}

// No matching policy denies with the AWS-shaped implicit-deny message.
func TestVerifyListAllMyBucketsAccess_PolicyEvaluatorNoMatchDenies(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := VerifyListAllMyBucketsAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUser})

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "because no identity-based policy allows the s3:ListAllMyBuckets action")
}

// An explicit Deny is reported with the AWS-shaped explicit-deny message.
func TestVerifyListAllMyBucketsAccess_PolicyEvaluatorExplicitDenyWins(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionDeny)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := VerifyListAllMyBucketsAccess(testFiberCtx(t), pe, false, Account{Access: "testuser", Role: RoleUser})

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "s3:ListAllMyBuckets")
	assert.Contains(t, apiErr.Description, "with an explicit deny in an identity-based policy")
}

// noObjectLockBackend answers "no lock configuration" for
// GetObjectLockConfiguration, so VerifyObjectsAccess's lock check is a no-op
// and only the policy/ACL half of the result is under test — matching what
// loadObjectLockState treats as "object lock was never configured on this
// bucket", not the BackendUnsupported stub's ErrNotImplemented, which would
// otherwise fail the whole request before either object was authorized.
type noObjectLockBackend struct {
	noBucketPolicyBackend
}

func (b noObjectLockBackend) GetObjectLockConfiguration(_ context.Context, _ string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
}

// actionSplitPolicyEvaluator denies exactly one action and allows every
// other, recording each EvaluatePolicy call it receives — for asserting not
// just the outcome but that DeleteObjects' mixed batch was split into one
// call per action rather than evaluated as a single undifferentiated batch.
type actionSplitPolicyEvaluator struct {
	IAMService
	denyAction Action
	calls      []evaluatePolicyCall
}

func (m *actionSplitPolicyEvaluator) EvaluatePolicy(access, sessionToken string, actions []Action, resources []string, condition map[string][]string) (PolicyEvaluation, error) {
	m.calls = append(m.calls, evaluatePolicyCall{
		access:       access,
		sessionToken: sessionToken,
		actions:      actions,
		resources:    resources,
		condition:    condition,
	})
	decisions := make([][]policyDecision, len(resources))
	for i := range resources {
		decisions[i] = make([]policyDecision, len(actions))
		for j, a := range actions {
			if a == m.denyAction {
				decisions[i][j] = policyDecisionNoMatch
			} else {
				decisions[i][j] = policyDecisionAllow
			}
		}
	}
	return PolicyEvaluation{Decisions: decisions}, nil
}

func TestVerifyObjectsAccess_VersionedDeleteNeedsSeparatePermission(t *testing.T) {
	be := noObjectLockBackend{noBucketPolicyBackend{srcAcl: ACL{Owner: "someone-else"}}}
	pe := &actionSplitPolicyEvaluator{denyAction: DeleteObjectVersionAction}

	objects := []types.ObjectIdentifier{
		{Key: strPtr("plain.txt")},
		{Key: strPtr("versioned.txt"), VersionId: strPtr("v1")},
	}

	errs, err := VerifyObjectsAccess(testFiberCtx(t), be, AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		AclPermission: PermissionWrite,
		Iam:           pe,
	}, objects, BypassNone)

	assert.NoError(t, err)
	if assert.Len(t, errs, 2) {
		assert.NoError(t, errs[0], "the keyed delete should be authorized against s3:DeleteObject, which is allowed")
		apiErr := requireAccessDeniedAPIError(t, errs[1])
		assert.Contains(t, apiErr.Description, "s3:DeleteObjectVersion")
		assert.Contains(t, apiErr.Description, "because no identity-based policy allows the s3:DeleteObjectVersion action")
	}

	if assert.Len(t, pe.calls, 2, "the batch should split into one EvaluatePolicy call per distinct action") {
		assert.Equal(t, []Action{DeleteObjectAction}, pe.calls[0].actions)
		assert.Equal(t, []string{"arn:aws:s3:::bucket/plain.txt"}, pe.calls[0].resources)
		assert.Equal(t, []Action{DeleteObjectVersionAction}, pe.calls[1].actions)
		assert.Equal(t, []string{"arn:aws:s3:::bucket/versioned.txt"}, pe.calls[1].resources)
	}
}

// bucketPolicyNoLockBackend serves a fixed bucket policy and answers "no
// lock configuration", so VerifyObjectsAccess' lock check is a no-op and
// only the policy half of the per-object result is under test.
type bucketPolicyNoLockBackend struct {
	backend.BackendUnsupported
	policy []byte
}

func (b bucketPolicyNoLockBackend) GetBucketPolicy(_ context.Context, _ string) ([]byte, error) {
	return b.policy, nil
}

func (b bucketPolicyNoLockBackend) GetObjectLockConfiguration(_ context.Context, _ string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
}

// denyProtectedPrefixBackend is a bucket policy denying s3:DeleteObject on
// one prefix and saying nothing about anything else, so a batch can mix
// explicitly denied keys with keys the bucket policy leaves undecided.
func denyProtectedPrefixBackend() bucketPolicyNoLockBackend {
	return bucketPolicyNoLockBackend{policy: []byte(`{
		"Statement": [{
			"Effect": "Deny",
			"Principal": "testuser",
			"Action": "s3:DeleteObject",
			"Resource": "arn:aws:s3:::bucket/protected/*"
		}]
	}`)}
}

func deleteObjectIdentifiers(keys ...string) []types.ObjectIdentifier {
	objects := make([]types.ObjectIdentifier, len(keys))
	for i, key := range keys {
		objects[i] = types.ObjectIdentifier{Key: strPtr(key)}
	}
	return objects
}

// TestVerifyObjectsAccess_ResourceDenyDoesNotAuthorizeLaterKeys is the
// authorization-bypass regression: a bucket-policy Deny used to end the
// whole batch's evaluation at the first denied key, leaving every later key
// with a nil result — which VerifyObjectsAccess' caller reads as
// "authorized" and sends straight to the backend. Every key must be settled
// on its own instead: the denied one explicitly, the rest by the identity
// policy, which here allows neither.
func TestVerifyObjectsAccess_ResourceDenyDoesNotAuthorizeLaterKeys(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	errs, err := VerifyObjectsAccess(testFiberCtx(t), denyProtectedPrefixBackend(), AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		AclPermission: PermissionWrite,
		Iam:           pe,
	}, deleteObjectIdentifiers("protected/x", "secret/y"), BypassNone)

	assert.NoError(t, err)
	if assert.Len(t, errs, 2) {
		denied := requireAccessDeniedAPIError(t, errs[0])
		assert.Contains(t, denied.Description, "with an explicit deny in a resource-based policy")

		later := requireAccessDeniedAPIError(t, errs[1])
		assert.Contains(t, later.Description, "because no identity-based policy allows the s3:DeleteObject action")
	}
	assert.Len(t, pe.calls, 1, "a key the bucket policy left undecided still needs the identity policy consulted for it")
}

// TestVerifyObjectsAccess_ResourceDenyKeptOverIdentityAllow confirms an
// explicit deny still wins per key once every key is evaluated: the denied
// key keeps its resource-based denial even though the identity policy
// allows it, while the key the bucket policy said nothing about is
// authorized by that same identity Allow.
func TestVerifyObjectsAccess_ResourceDenyKeptOverIdentityAllow(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	errs, err := VerifyObjectsAccess(testFiberCtx(t), denyProtectedPrefixBackend(), AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		AclPermission: PermissionWrite,
		Iam:           pe,
	}, deleteObjectIdentifiers("protected/x", "allowed/y"), BypassNone)

	assert.NoError(t, err)
	if assert.Len(t, errs, 2) {
		denied := requireAccessDeniedAPIError(t, errs[0])
		assert.Contains(t, denied.Description, "with an explicit deny in a resource-based policy")
		assert.NoError(t, errs[1], "the identity policy's Allow stands for the key the bucket policy didn't deny")
	}
}

// TestVerifyObjectsAccess_AllKeysResourceDeniedSkipsIdentityPolicy covers
// the round trip the short-circuit was there to save: it is still skipped,
// but only when the bucket policy denied every key in the batch, since then
// no identity-policy answer could change any result.
func TestVerifyObjectsAccess_AllKeysResourceDeniedSkipsIdentityPolicy(t *testing.T) {
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	errs, err := VerifyObjectsAccess(testFiberCtx(t), denyProtectedPrefixBackend(), AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		AclPermission: PermissionWrite,
		Iam:           pe,
	}, deleteObjectIdentifiers("protected/x", "protected/y"), BypassNone)

	assert.NoError(t, err)
	if assert.Len(t, errs, 2) {
		for i, e := range errs {
			denied := requireAccessDeniedAPIError(t, e)
			assert.Containsf(t, denied.Description, "with an explicit deny in a resource-based policy", "key %d", i)
		}
	}
	assert.Empty(t, pe.calls, "with every key already explicitly denied there is nothing left for the identity policy to decide")
}

// TestVerifyObjectsAccess_ResourceDenyNoPolicyEvaluator covers the same
// bypass for the IAM backends with no identity-policy layer at all
// (internal, LDAP, Vault, IPA): the denied key keeps its specific message
// and every other key falls to the generic AccessDenied those backends have
// always returned — none of them silently authorized.
func TestVerifyObjectsAccess_ResourceDenyNoPolicyEvaluator(t *testing.T) {
	errs, err := VerifyObjectsAccess(testFiberCtx(t), denyProtectedPrefixBackend(), AccessOptions{
		Acc:           Account{Access: "testuser", Role: RoleUser},
		Bucket:        "bucket",
		AclPermission: PermissionWrite,
		Iam:           NewIAMServiceSingle(Account{}),
	}, deleteObjectIdentifiers("protected/x", "secret/y"), BypassNone)

	assert.NoError(t, err)
	if assert.Len(t, errs, 2) {
		denied := requireAccessDeniedAPIError(t, errs[0])
		assert.Contains(t, denied.Description, "with an explicit deny in a resource-based policy")

		later := requireAccessDeniedAPIError(t, errs[1])
		assert.Equal(t, s3err.GetAPIError(s3err.ErrAccessDenied).Description, later.Description,
			"backends with no identity-policy layer keep their generic message")
	}
}

func strPtr(s string) *string { return &s }

// arnPolicyBackend serves one bucket policy, for the ARN-principal tests
// below. It is publicBucketPolicyBackend without the ACL half, which none of
// them reach.
type arnPolicyBackend struct {
	backend.BackendUnsupported
	policy string
}

func (b arnPolicyBackend) GetBucketPolicy(_ context.Context, _ string) ([]byte, error) {
	return []byte(b.policy), nil
}

// arnPolicy builds a one-statement bucket policy granting or denying
// s3:GetObject on the test bucket to principal.
func arnPolicy(effect, principal string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect + `","Principal":{"AWS":` +
		principal + `},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`
}

const (
	acPolicyUserArn    = `"arn:aws:iam::000000000000:user/alice"`
	acPolicyRoleArn    = `"arn:aws:iam::000000000000:role/reader"`
	acPolicySessionArn = `"arn:aws:sts::000000000000:assumed-role/reader/sess1"`
	acPolicyRootArn    = `"arn:aws:iam::000000000000:root"`
)

func acUser() Account {
	return Account{Access: "AKIAALICE", Role: RoleUser, Arn: "arn:aws:iam::000000000000:user/alice"}
}

func acSession() Account {
	return Account{
		Access:    "ASIASESSION",
		Role:      RoleUser,
		IsSession: true,
		Arn:       "arn:aws:sts::000000000000:assumed-role/reader/sess1",
		RoleArn:   "arn:aws:iam::000000000000:role/reader",
	}
}

// TestVerifyAccess_ArnPrincipalMatching walks every combination of principal
// form and caller that a bucket policy can express under an IAM backend
// whose identities have ARNs, with the identity policy silent throughout so
// that what each case measures is the Principal element alone.
func TestVerifyAccess_ArnPrincipalMatching(t *testing.T) {
	tests := []struct {
		name       string
		effect     string
		principal  string
		acc        Account
		wantAllow  bool
		wantDenyBy string
	}{
		{
			name: "user named by its own arn", effect: "Allow", principal: acPolicyUserArn,
			acc: acUser(), wantAllow: true,
		},
		{
			name: "user not named", effect: "Allow", principal: acPolicyRoleArn,
			acc: acUser(), wantDenyBy: "because no identity-based policy allows",
		},
		{
			name: "access key id is no longer a principal", effect: "Allow", principal: `"AKIAALICE"`,
			acc: acUser(), wantDenyBy: "because no identity-based policy allows",
		},
		{
			name: "session named by its role arn", effect: "Allow", principal: acPolicyRoleArn,
			acc: acSession(), wantAllow: true,
		},
		{
			name: "session named by its own arn", effect: "Allow", principal: acPolicySessionArn,
			acc: acSession(), wantAllow: true,
		},
		{
			name: "another session of the same role", effect: "Allow",
			principal: `"arn:aws:sts::000000000000:assumed-role/reader/sess2"`,
			acc:       acSession(), wantDenyBy: "because no identity-based policy allows",
		},
		{
			name: "a user is not covered by a role arn", effect: "Allow", principal: acPolicyRoleArn,
			acc: acUser(), wantDenyBy: "because no identity-based policy allows",
		},
		{
			// The account principal delegates to the account's own IAM
			// rather than granting, and the identity policy is silent here.
			name: "account root arn allows nothing on its own", effect: "Allow", principal: acPolicyRootArn,
			acc: acUser(), wantDenyBy: "because no identity-based policy allows",
		},
		{
			name: "bare account id allows nothing on its own", effect: "Allow", principal: `"000000000000"`,
			acc: acUser(), wantDenyBy: "because no identity-based policy allows",
		},
		{
			name: "wildcard allows everyone", effect: "Allow", principal: `"*"`,
			acc: acUser(), wantAllow: true,
		},
		{
			name: "deny naming the user", effect: "Deny", principal: acPolicyUserArn,
			acc: acUser(), wantDenyBy: "with an explicit deny in a resource-based policy",
		},
		{
			// Deny is not a delegation: naming the account denies every
			// principal in it outright.
			name: "deny naming the account", effect: "Deny", principal: acPolicyRootArn,
			acc: acUser(), wantDenyBy: "with an explicit deny in a resource-based policy",
		},
		{
			name: "deny naming the account hits a session too", effect: "Deny", principal: acPolicyRootArn,
			acc: acSession(), wantDenyBy: "with an explicit deny in a resource-based policy",
		},
		{
			name: "deny naming the role hits its session", effect: "Deny", principal: acPolicyRoleArn,
			acc: acSession(), wantDenyBy: "with an explicit deny in a resource-based policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := arnPolicyBackend{policy: arnPolicy(tt.effect, tt.principal)}
			pe := newMockPolicyEvaluator(policyDecisionNoMatch)
			pe.principalArn = tt.acc.Arn

			err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
				Acc:     tt.acc,
				Bucket:  "bucket",
				Object:  "key.txt",
				Actions: []Action{GetObjectAction},
				Iam:     pe,
			})

			if tt.wantAllow {
				assert.NoError(t, err)
				return
			}
			apiErr := requireAccessDeniedAPIError(t, err)
			assert.Contains(t, apiErr.Description, tt.wantDenyBy)
			assert.Contains(t, apiErr.Description, tt.acc.Arn,
				"a denial names the caller by its ARN once the IAM backend gives it one")
		})
	}
}

// TestVerifyAccess_AccountPrincipalDelegatesToIdentityPolicy is the other
// half of the account-principal rule: what it delegates to is the identity
// policy, so the same policy that granted nothing above grants once the
// identity policy allows.
func TestVerifyAccess_AccountPrincipalDelegatesToIdentityPolicy(t *testing.T) {
	be := arnPolicyBackend{policy: arnPolicy("Allow", acPolicyRootArn)}
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := VerifyAccess(testFiberCtx(t), be, AccessOptions{
		Acc:     acUser(),
		Bucket:  "bucket",
		Object:  "key.txt",
		Actions: []Action{GetObjectAction},
		Iam:     pe,
	})

	assert.NoError(t, err)
}

// TestVerifyAccess_AccessKeyPrincipalsStillWorkWithoutArns pins the
// backward-compatible half: an account with no ARN — every IAM backend but
// the standalone service — is still matched by its access key id, and an ARN
// principal means nothing to it.
func TestVerifyAccess_AccessKeyPrincipalsStillWorkWithoutArns(t *testing.T) {
	acc := Account{Access: "testuser", Role: RoleUser}

	allowed := arnPolicyBackend{policy: arnPolicy("Allow", `"testuser"`)}
	err := VerifyAccess(testFiberCtx(t), allowed, AccessOptions{
		Acc: acc, Bucket: "bucket", Object: "key.txt",
		Actions: []Action{GetObjectAction}, Iam: NewIAMServiceSingle(Account{}),
	})
	assert.NoError(t, err)

	denied := arnPolicyBackend{policy: arnPolicy("Allow", acPolicyUserArn)}
	err = VerifyAccess(testFiberCtx(t), denied, AccessOptions{
		Acc: acc, Bucket: "bucket", Object: "key.txt",
		Actions: []Action{GetObjectAction}, Iam: NewIAMServiceSingle(Account{}),
	})
	assert.Equal(t, s3err.GetAPIError(s3err.ErrAccessDenied), err)
}
