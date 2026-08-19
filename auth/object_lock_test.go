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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestVerifyBypassGovernancePermission_IdentityAllowNoBucketPolicy is the
// same-account fix this function exists for: an IAM identity policy Allow
// is sufficient to use x-amz-bypass-governance-retention even when the
// bucket has no policy at all. The old bucket-policy-only check treated "no
// bucket policy" as an immediate ErrObjectLocked, never even consulting the
// identity policy.
func TestVerifyBypassGovernancePermission_IdentityAllowNoBucketPolicy(t *testing.T) {
	be := noBucketPolicyBackend{}
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := verifyBypassGovernancePermission(context.Background(), be, pe, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	assert.NoError(t, err)
}

// TestVerifyBypassGovernancePermission_ResourceAllowIdentitySilent is the
// reverse: a bucket policy Allow is sufficient when the identity policy has
// no opinion on the action, but the identity policy must still be
// consulted (not skipped) so an explicit Deny there can override it.
func TestVerifyBypassGovernancePermission_ResourceAllowIdentitySilent(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:BypassGovernanceRetention",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)

	err := verifyBypassGovernancePermission(context.Background(), be, pe, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	assert.NoError(t, err)
	assert.Len(t, pe.calls, 1, "identity policy must be consulted even though the bucket policy already allows")
}

// TestVerifyBypassGovernancePermission_IdentityExplicitDenyOverridesResourceAllow
// is the explicit-deny-wins case: a bucket policy Allow does not save a
// bypass request the caller's own identity policy explicitly denies. AWS
// reports this as a specific AccessDenied naming
// s3:BypassGovernanceRetention, not the generic "object protected by object
// lock" message.
func TestVerifyBypassGovernancePermission_IdentityExplicitDenyOverridesResourceAllow(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:BypassGovernanceRetention",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	pe := newMockPolicyEvaluator(policyDecisionDeny)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := verifyBypassGovernancePermission(context.Background(), be, pe, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "s3:BypassGovernanceRetention")
	assert.Contains(t, apiErr.Description, "with an explicit deny in an identity-based policy")
}

// TestVerifyBypassGovernancePermission_ResourceExplicitDenyOverridesIdentityAllow
// is the reverse: an identity policy Allow does not save a bypass request
// the bucket policy explicitly denies, and the resource-level Deny
// short-circuits before the identity policy is even consulted.
func TestVerifyBypassGovernancePermission_ResourceExplicitDenyOverridesIdentityAllow(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Deny",
				"Principal": "testuser",
				"Action": "s3:BypassGovernanceRetention",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	pe := newMockPolicyEvaluator(policyDecisionAllow)

	err := verifyBypassGovernancePermission(context.Background(), be, pe, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "with an explicit deny in a resource-based policy")
	assert.Empty(t, pe.calls, "a resource-level explicit deny should short-circuit before consulting the identity policy")
}

// TestVerifyBypassGovernancePermission_ImplicitDenyWhenNeitherAllows: with
// no bucket policy and no identity-policy grant, AWS denies with "because
// no identity-based policy allows the s3:BypassGovernanceRetention action"
// — the same implicit-deny shape VerifyAccess uses for ordinary actions.
func TestVerifyBypassGovernancePermission_ImplicitDenyWhenNeitherAllows(t *testing.T) {
	be := noBucketPolicyBackend{}
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)
	pe.principalArn = "arn:aws:iam::000000000000:user/testuser"

	err := verifyBypassGovernancePermission(context.Background(), be, pe, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	apiErr := requireAccessDeniedAPIError(t, err)
	assert.Contains(t, apiErr.Description, "arn:aws:iam::000000000000:user/testuser")
	assert.Contains(t, apiErr.Description, "because no identity-based policy allows the s3:BypassGovernanceRetention action")
}

// TestVerifyBypassGovernancePermission_NoPolicyEvaluatorPreservesGenericMessage
// confirms backends with no identity-policy layer (every backend except the
// standalone IAM service) are unaffected: the generic ErrObjectLocked stays
// exactly as before when there is no bucket policy to grant the bypass.
func TestVerifyBypassGovernancePermission_NoPolicyEvaluatorPreservesGenericMessage(t *testing.T) {
	be := noBucketPolicyBackend{}
	iam := NewIAMServiceSingle(Account{})

	err := verifyBypassGovernancePermission(context.Background(), be, iam, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	assert.Equal(t, s3err.GetAPIError(s3err.ErrObjectLocked), err)
}

// TestVerifyBypassGovernancePermission_NoPolicyEvaluatorBucketPolicyAllowStillWorks
// pins that, without a PolicyEvaluator, a bucket policy Allow alone is still
// sufficient — the pre-existing (bucket-policy-only) behavior.
func TestVerifyBypassGovernancePermission_NoPolicyEvaluatorBucketPolicyAllowStillWorks(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "testuser",
				"Action": "s3:BypassGovernanceRetention",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}
	iam := NewIAMServiceSingle(Account{})

	err := verifyBypassGovernancePermission(context.Background(), be, iam, Account{Access: "testuser"}, "bucket", "key.txt", BypassRequested, false, nil)

	assert.NoError(t, err)
}

// TestVerifyBypassGovernancePermission_PublicBucketAllowed and
// TestVerifyBypassGovernancePermission_PublicBucketDenied confirm the
// isBucketPublic branch (anonymous requests, evaluated only against the
// bucket's public policy grant, wrapped in the generic ErrObjectLocked) is
// unchanged by this refactor.
func TestVerifyBypassGovernancePermission_PublicBucketAllowed(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:BypassGovernanceRetention",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}

	err := verifyBypassGovernancePermission(context.Background(), be, nil, Account{}, "bucket", "key.txt", BypassRequested, true, nil)

	assert.NoError(t, err)
}

func TestVerifyBypassGovernancePermission_PublicBucketDenied(t *testing.T) {
	be := &publicBucketPolicyBackend{
		policy: []byte(`{
			"Statement": [{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
			}]
		}`),
	}

	err := verifyBypassGovernancePermission(context.Background(), be, nil, Account{}, "bucket", "key.txt", BypassRequested, true, nil)

	assert.Equal(t, s3err.GetAPIError(s3err.ErrObjectLocked), err)
}

// TestVerifyBypassGovernancePermission_RootBypassesOnlyWhenRequested pins the
// asymmetry between the two ways a governance retention can be overridden.
//
// Root bypasses unconditionally when the client actually sent
// x-amz-bypass-governance-retention, matching real AWS, where the account
// root can bypass regardless of policy. It does not get that on the
// overwrite path, where no client asked for anything and letting root
// through would mean silently replacing a locked object.
func TestVerifyBypassGovernancePermission_RootBypassesOnlyWhenRequested(t *testing.T) {
	root := Account{Access: "root", Role: RoleAdmin}

	// No bucket policy and no identity policy: the only thing that could
	// possibly permit this is root's own status.
	be := &publicBucketPolicyBackend{policy: []byte(`{"Statement":[]}`)}
	pe := newMockPolicyEvaluator(policyDecisionNoMatch)

	err := verifyBypassGovernancePermission(context.Background(), be, pe, root, "bucket", "key.txt", BypassRequested, false, nil)
	assert.NoError(t, err, "root must bypass a governance retention it explicitly asked to bypass")

	err = verifyBypassGovernancePermission(context.Background(), be, pe, root, "bucket", "key.txt", BypassOverwrite, false, nil)
	assert.Error(t, err, "root must not silently overwrite a governance-locked object: no bypass was requested")

	err = verifyBypassGovernancePermission(context.Background(), be, pe, root, "bucket", "key.txt", BypassNone, false, nil)
	assert.Error(t, err, "root must not bypass when the request did not ask to")
}

// TestVerifyBypassGovernancePermission_NonRootStillNeedsPermission confirms
// the root shortcut is exactly that, and does not leak to ordinary users.
func TestVerifyBypassGovernancePermission_NonRootStillNeedsPermission(t *testing.T) {
	user := Account{Access: "testuser", Role: RoleUser}
	be := &publicBucketPolicyBackend{policy: []byte(`{"Statement":[]}`)}

	err := verifyBypassGovernancePermission(context.Background(), be,
		newMockPolicyEvaluator(policyDecisionNoMatch), user, "bucket", "key.txt", BypassRequested, false, nil)
	assert.Error(t, err, "a plain user with no grant anywhere must not bypass")

	err = verifyBypassGovernancePermission(context.Background(), be,
		newMockPolicyEvaluator(policyDecisionAllow), user, "bucket", "key.txt", BypassRequested, false, nil)
	assert.NoError(t, err, "an identity-policy Allow grants the bypass")
}

// TestIsObjectLockRetentionPutAllowed_WeakeningRules covers which retention
// rewrites need s3:BypassGovernanceRetention and which need nothing.
//
// Extending a GOVERNANCE or COMPLIANCE retention, or rewriting it with the
// identical date, succeeds with no bypass header, while shortening either
// one without the header fails with "Access Denied because object
// protected by object lock." A COMPLIANCE retention cannot be weakened at
// all, even with the header.
func TestIsObjectLockRetentionPutAllowed_WeakeningRules(t *testing.T) {
	now := time.Now()
	stored := now.Add(time.Hour)

	tests := []struct {
		name      string
		mode      types.ObjectLockRetentionMode
		newMode   types.ObjectLockRetentionMode
		newDate   time.Time
		bypass    bool
		wantAllow bool
	}{
		{name: "governance extended", mode: types.ObjectLockRetentionModeGovernance, newMode: types.ObjectLockRetentionModeGovernance, newDate: stored.Add(time.Hour), wantAllow: true},
		{name: "governance same date", mode: types.ObjectLockRetentionModeGovernance, newMode: types.ObjectLockRetentionModeGovernance, newDate: stored, wantAllow: true},
		{name: "governance shortened without bypass", mode: types.ObjectLockRetentionModeGovernance, newMode: types.ObjectLockRetentionModeGovernance, newDate: now.Add(time.Minute)},
		{name: "governance shortened with bypass", mode: types.ObjectLockRetentionModeGovernance, newMode: types.ObjectLockRetentionModeGovernance, newDate: now.Add(time.Minute), bypass: true, wantAllow: true},
		{name: "compliance extended", mode: types.ObjectLockRetentionModeCompliance, newMode: types.ObjectLockRetentionModeCompliance, newDate: stored.Add(time.Hour), wantAllow: true},
		{name: "compliance shortened without bypass", mode: types.ObjectLockRetentionModeCompliance, newMode: types.ObjectLockRetentionModeCompliance, newDate: now.Add(time.Minute)},
		{name: "compliance shortened with bypass", mode: types.ObjectLockRetentionModeCompliance, newMode: types.ObjectLockRetentionModeCompliance, newDate: now.Add(time.Minute), bypass: true},
		{name: "compliance downgraded to governance", mode: types.ObjectLockRetentionModeCompliance, newMode: types.ObjectLockRetentionModeGovernance, newDate: stored.Add(time.Hour), bypass: true},
		{name: "governance upgraded to compliance with bypass", mode: types.ObjectLockRetentionModeGovernance, newMode: types.ObjectLockRetentionModeCompliance, newDate: stored, bypass: true, wantAllow: true},
		{name: "governance upgraded to compliance without bypass", mode: types.ObjectLockRetentionModeGovernance, newMode: types.ObjectLockRetentionModeCompliance, newDate: stored},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retention, err := json.Marshal(types.ObjectLockRetention{Mode: tt.mode, RetainUntilDate: &stored})
			assert.NoError(t, err)

			be := &objectRetentionBackend{retention: retention}
			// A permissive evaluator, so any denial below is the retention
			// rule talking rather than a missing permission.
			pe := newMockPolicyEvaluator(policyDecisionAllow)

			err = IsObjectLockRetentionPutAllowed(testFiberCtx(t), be, pe, "bucket", "key.txt", "",
				Account{Access: "testuser", Role: RoleUser},
				&s3response.PutObjectRetentionInput{Mode: tt.newMode, RetainUntilDate: s3response.AmzDate{Time: tt.newDate}},
				tt.bypass)

			if tt.wantAllow {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, s3err.GetAPIError(s3err.ErrObjectLocked), err)
			}
		})
	}
}

// objectRetentionBackend serves one canned object retention.
type objectRetentionBackend struct {
	backend.BackendUnsupported
	retention []byte
}

func (b *objectRetentionBackend) GetObjectRetention(_ context.Context, _, _, _ string) ([]byte, error) {
	return b.retention, nil
}

func (b *objectRetentionBackend) GetBucketPolicy(_ context.Context, _ string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
}
