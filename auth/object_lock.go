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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type BucketLockConfig struct {
	Enabled          bool
	DefaultRetention *types.DefaultRetention
	CreatedAt        *time.Time
}

// BypassMode says whether, and on whose authority, a request may override a
// GOVERNANCE-mode retention. It exists because the two ways that can happen
// are not equivalent, and collapsing them into one boolean previously let
// root overwrite locked objects it should not have been able to.
type BypassMode int

const (
	// BypassNone is a request that has not asked to override anything: any
	// unexpired retention blocks it outright.
	BypassNone BypassMode = iota

	// BypassRequested is a request carrying x-amz-bypass-governance-retention
	// — DeleteObject, DeleteObjects, or PutObjectRetention. Root and admin
	// may always override a GOVERNANCE retention this way, matching real
	// AWS, where the account root can bypass regardless of policy; everyone
	// else needs s3:BypassGovernanceRetention.
	BypassRequested

	// BypassOverwrite is the gateway's own extension: replacing an existing
	// governance-locked object via PutObject, CopyObject or POST Object,
	// none of which has a bypass header for a client to send. Because the
	// caller never asked to override anything, the permission is required
	// from everyone here — root included — and root's blanket bypass above
	// deliberately does not apply. (Real S3 has no analogue: it only allows
	// object lock on versioned buckets, where an overwrite creates a new
	// version rather than replacing a locked one.)
	BypassOverwrite
)

// allowsGovernanceOverride reports whether this mode permits overriding a
// GOVERNANCE retention at all, given the permission to do so.
func (b BypassMode) allowsGovernanceOverride() bool { return b != BypassNone }

// BypassModeForRequest maps the presence of the client's
// x-amz-bypass-governance-retention header onto a BypassMode.
func BypassModeForRequest(headerPresent bool) BypassMode {
	if headerPresent {
		return BypassRequested
	}
	return BypassNone
}

const (
	maxObjectLockRetentionDays  int32 = 36500
	maxObjectLockRetentionYears int32 = 100
)

func ParseBucketLockConfigurationInput(input []byte) ([]byte, error) {
	var lockConfig types.ObjectLockConfiguration
	if err := xml.Unmarshal(input, &lockConfig); err != nil {
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if lockConfig.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	config := BucketLockConfig{
		Enabled: lockConfig.ObjectLockEnabled == types.ObjectLockEnabledEnabled,
	}

	if lockConfig.Rule != nil && lockConfig.Rule.DefaultRetention != nil {
		retention := lockConfig.Rule.DefaultRetention

		if retention.Mode != types.ObjectLockRetentionModeCompliance && retention.Mode != types.ObjectLockRetentionModeGovernance {
			return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
		}
		if retention.Years != nil && retention.Days != nil {
			return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
		}

		if retention.Days != nil && *retention.Days <= 0 {
			return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockRetentionDays, fmt.Sprint(*retention.Days))
		}
		if retention.Days != nil && *retention.Days > maxObjectLockRetentionDays {
			return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockRetentionDaysTooLarge, fmt.Sprint(*retention.Days))
		}
		if retention.Years != nil && *retention.Years <= 0 {
			return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockRetentionYears, fmt.Sprint(*retention.Years))
		}
		if retention.Years != nil && *retention.Years > maxObjectLockRetentionYears {
			return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockRetentionYearsTooLarge, fmt.Sprint(*retention.Years))
		}

		config.DefaultRetention = retention
		now := time.Now()
		config.CreatedAt = &now
	}

	return json.Marshal(config)
}

func ParseBucketLockConfigurationOutput(input []byte) (*types.ObjectLockConfiguration, error) {
	var config BucketLockConfig
	if err := json.Unmarshal(input, &config); err != nil {
		return nil, fmt.Errorf("parse object lock config: %w", err)
	}

	result := &types.ObjectLockConfiguration{
		Rule: &types.ObjectLockRule{
			DefaultRetention: config.DefaultRetention,
		},
	}

	if config.Enabled {
		result.ObjectLockEnabled = types.ObjectLockEnabledEnabled
	}

	return result, nil
}

func ParseObjectLockRetentionInput(input []byte) (*s3response.PutObjectRetentionInput, error) {
	var retention s3response.PutObjectRetentionInput
	if err := xml.Unmarshal(input, &retention); err != nil {
		debuglogger.Logf("invalid object lock retention request body: %v", err)
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if retention.RetainUntilDate.Before(time.Now()) {
		debuglogger.Logf("object lock retain until date must be in the future")
		return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgPastObjectLockRetainDate, retention.RetainUntilDate.Format(time.RFC3339))
	}
	switch retention.Mode {
	case types.ObjectLockRetentionModeCompliance:
	case types.ObjectLockRetentionModeGovernance:
	default:
		debuglogger.Logf("invalid object lock retention mode: %s", retention.Mode)
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	return &retention, nil
}

func ParseObjectLockRetentionInputToJSON(input *s3response.PutObjectRetentionInput) ([]byte, error) {
	data, err := json.Marshal(input)
	if err != nil {
		debuglogger.Logf("parse object lock retention to JSON: %v", err)
		return nil, fmt.Errorf("parse object lock retention: %w", err)
	}

	return data, nil
}

// IsObjectLockRetentionPutAllowed checks if the object lock retention PUT request
// is allowed against the current state of the object lock
func IsObjectLockRetentionPutAllowed(ctx fiber.Ctx, be backend.Backend, iam IAMService, bucket, object, versionId string, acc Account, input *s3response.PutObjectRetentionInput, bypass bool) error {
	ret, err := be.GetObjectRetention(ctx.RequestCtx(), bucket, object, versionId)
	if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) {
		// if object lock configuration is not set
		// allow the retention modification without any checks
		return nil
	}
	if err != nil {
		debuglogger.Logf("failed to get object retention: %v", err)
		return err
	}

	retention, err := ParseObjectLockRetentionOutput(ret)
	if err != nil {
		return err
	}

	// Pushing the date further out only ever strengthens the lock, so it
	// needs nothing beyond s3:PutObjectRetention — in either mode. Anything
	// that weakens it, an earlier date or a mode change, does not.
	//
	// A stored retention carrying no date can't be compared, so it counts as
	// weakenable rather than being assumed an extension — the fail-closed
	// direction.
	isExtension := retention.Mode == input.Mode &&
		retention.RetainUntilDate != nil &&
		!input.RetainUntilDate.Time.Before(*retention.RetainUntilDate)
	if isExtension {
		return nil
	}

	if retention.Mode == types.ObjectLockRetentionModeCompliance {
		// COMPLIANCE is absolute until it expires: it can be extended (above)
		// but never shortened, and never downgraded to GOVERNANCE — by
		// anyone, with any permission, including the account root. That
		// immutability is the whole point of the mode, and real AWS rejects
		// a shortening PutObjectRetention on a COMPLIANCE object even with
		// the bypass header present.
		debuglogger.Logf("weakening a 'COMPLIANCE' object lock retention is not allowed")
		return s3err.GetAPIError(s3err.ErrObjectLocked)
	}

	if !bypass {
		// if x-amz-bypass-governance-retention is not provided
		// return error: object is locked
		debuglogger.Logf("weakening a 'GOVERNANCE' object lock retention is not allowed without the bypass governance header")
		return s3err.GetAPIError(s3err.ErrObjectLocked)
	}

	// What's left is weakening a GOVERNANCE retention — shortening its date,
	// or switching it to COMPLIANCE — with the bypass header. That needs
	// s3:BypassGovernanceRetention, via the bucket policy and/or (when
	// configured) the IAM identity policy.
	if err := verifyBypassGovernancePermission(ctx.RequestCtx(), be, iam, acc, bucket, object, BypassRequested, false, requestConditionContext(ctx)); err != nil {
		debuglogger.Logf("the user is missing 's3:BypassGovernanceRetention' permission: %v", err)
		return err
	}

	return nil
}

// verifyBypassGovernancePermission decides whether acc may use
// x-amz-bypass-governance-retention to override a GOVERNANCE-mode lock on
// bucket/key. For a public (anonymous) request it consults only the
// bucket's public policy grant, wrapped in the generic ErrObjectLocked. For
// an authenticated request it combines the bucket policy decision with an
// identity-policy decision from iam when it implements PolicyEvaluator
// (currently only the standalone IAM service client), using the same
// explicit-deny-wins precedence as VerifyAccess. Unlike the "no header"
// case, a failed permission check here is reported as the specific
// AccessDenied error naming s3:BypassGovernanceRetention, not the generic
// "object protected by object lock" message — that message is reserved for
// when the bypass header itself is absent, or for backends with no
// identity-policy layer at all, where it preserves the existing behavior.
func verifyBypassGovernancePermission(ctx context.Context, be backend.Backend, iam IAMService, acc Account, bucket, key string, mode BypassMode, isBucketPublic bool, condCtx map[string][]string) error {
	// Root and admin override a GOVERNANCE retention unconditionally when
	// the client actually asked to — matching real AWS, where the account
	// root can bypass whatever the policies say.
	//
	// This deliberately does not extend to BypassOverwrite: there the
	// caller never requested a bypass (no S3 write API has a header for
	// it), so there is nothing to grant root on their behalf, and letting
	// it through would mean root silently replacing locked objects. See
	// BypassMode.
	if mode == BypassRequested && acc.Role == RoleAdmin {
		return nil
	}

	if isBucketPublic {
		policy, err := be.GetBucketPolicy(ctx, bucket)
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
			return s3err.GetAPIError(s3err.ErrObjectLocked)
		}
		if err != nil {
			return err
		}
		if err := VerifyPublicBucketPolicy(policy, bucket, key, condCtx, be.NormalizeObjectKey, BypassGovernanceRetentionAction); err != nil {
			return s3err.GetAPIError(s3err.ErrObjectLocked)
		}
		return nil
	}

	var resourceDecision policyDecision
	policy, err := be.GetBucketPolicy(ctx, bucket)
	switch {
	case errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)):
		resourceDecision = policyDecisionNoMatch
	case err != nil:
		return err
	default:
		resourceDecision, _, err = verifyBucketPolicy(policy, acc, bucket, key, condCtx, be.NormalizeObjectKey, BypassGovernanceRetentionAction)
		if err != nil {
			return err
		}
	}

	resourceArn := objectPolicyArn(bucket, key, be.NormalizeObjectKey)

	if resourceDecision == policyDecisionDeny {
		return s3err.GetExplicitDenyAccessErr(principalName(acc), string(BypassGovernanceRetentionAction), resourceArn, "a resource-based policy")
	}

	pe, hasPolicyEvaluator := iam.(PolicyEvaluator)

	// Only BypassOverwrite reaches here as root — BypassRequested already
	// returned above. Root has no identity policy to evaluate: with the
	// standalone IAM backend it is not an IAM user at all, so asking that
	// service about it would fail with ErrNoSuchUser rather than return a
	// decision. It therefore falls back to the bucket-policy decision alone,
	// exactly as a backend with no identity-policy layer does, and so still
	// needs an explicit grant to replace a locked object.
	if !hasPolicyEvaluator || acc.Role == RoleAdmin {
		// No identity-policy layer for this backend: preserve today's exact
		// behavior for every internal/LDAP/Vault/IPA deployment.
		if resourceDecision == policyDecisionAllow {
			return nil
		}
		return s3err.GetAPIError(s3err.ErrObjectLocked)
	}

	identity, err := identityPolicyDecisions(pe, AccessOptions{
		Acc:     acc,
		Bucket:  bucket,
		Object:  key,
		Actions: []Action{BypassGovernanceRetentionAction},
	}, []string{key}, be.NormalizeObjectKey, condCtx)
	if err != nil {
		return err
	}

	identityDecision := identity.Decisions[0].Decision
	sessionDenies := identity.HasSessionPolicy && identity.SessionDecisions[0].Decision == policyDecisionDeny
	// A session policy filters this permission the same way it filters any
	// other: it can only take away what the role or the bucket policy grants.
	sessionWithholds := identity.HasSessionPolicy && identity.SessionDecisions[0].Decision != policyDecisionAllow

	if identityDecision == policyDecisionDeny || sessionDenies {
		principal := identity.PrincipalArn
		if principal == "" {
			principal = principalName(acc)
		}
		return s3err.GetExplicitDenyAccessErr(principal, string(BypassGovernanceRetentionAction), resourceArn, "an identity-based policy")
	}
	if !sessionWithholds &&
		(resourceDecision == policyDecisionAllow || identityDecision == policyDecisionAllow) {
		return nil
	}

	principal := identity.PrincipalArn
	if principal == "" {
		principal = principalName(acc)
	}
	return s3err.GetImplicitDenyAccessErr(principal, string(BypassGovernanceRetentionAction), resourceArn)
}

func ParseObjectLockRetentionOutput(input []byte) (*types.ObjectLockRetention, error) {
	var retention types.ObjectLockRetention
	if err := json.Unmarshal(input, &retention); err != nil {
		debuglogger.Logf("parse object lock retention output: %v", err)
		return nil, fmt.Errorf("parse object lock retention: %w", err)
	}

	return &retention, nil
}

func ParseObjectLegalHoldOutput(status *bool) *s3response.GetObjectLegalHoldResult {
	if status == nil {
		return nil
	}

	if *status {
		return &s3response.GetObjectLegalHoldResult{
			Status: types.ObjectLockLegalHoldStatusOn,
		}
	}

	return &s3response.GetObjectLegalHoldResult{
		Status: types.ObjectLockLegalHoldStatusOff,
	}
}

// CheckObjectAccess enforces the object locks protecting objects, for the
// single-object write paths. The multi-object delete path uses
// VerifyObjectsAccess instead, which folds this together with the
// authorization check into one pass.
func CheckObjectAccess(ctx fiber.Ctx, bucket string, acc Account, objects []types.ObjectIdentifier, bypass BypassMode, isBucketPublic bool, be backend.Backend, iam IAMService, isOverwrite bool) error {
	rctx := ctx.RequestCtx()
	state, err := loadObjectLockState(rctx, be, bucket, isOverwrite)
	if err != nil || !state.applies {
		return err
	}

	condCtx := requestConditionContext(ctx)
	for _, obj := range objects {
		if err := state.checkObject(rctx, be, iam, acc, bucket, obj, bypass, isBucketPublic, condCtx); err != nil {
			return err
		}
	}

	return nil
}

// objectLockState is the bucket-level object-lock configuration a request is
// evaluated against, resolved once so a request naming many objects doesn't
// re-fetch it per key.
type objectLockState struct {
	// applies is false when nothing about this bucket can block the request:
	// object lock is off, unconfigured, or the write creates a new version
	// rather than replacing anything.
	applies bool
	// defaultRetention is the bucket's default retention, only set when it
	// is configured and still in force.
	defaultRetention *types.DefaultRetention
	// versioningEnabled makes a delete without a version id a new delete
	// marker, which no retention protects against.
	versioningEnabled bool
}

func loadObjectLockState(ctx context.Context, be backend.Backend, bucket string, isOverwrite bool) (objectLockState, error) {
	var state objectLockState

	if isOverwrite {
		// if bucket versioning is enabled, any overwrite request
		// should be enabled, as it leads to a new object version
		// creation
		res, err := be.GetBucketVersioning(ctx, bucket)
		if err == nil && res.Status != nil && *res.Status == types.BucketVersioningStatusEnabled {
			return state, nil
		}
	}

	data, err := be.GetObjectLockConfiguration(ctx, bucket)
	if err != nil {
		if errors.Is(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)) {
			return state, nil
		}

		return state, err
	}

	var bucketLockConfig BucketLockConfig
	if err := json.Unmarshal(data, &bucketLockConfig); err != nil {
		return state, fmt.Errorf("parse object lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return state, nil
	}
	state.applies = true

	if bucketLockConfig.DefaultRetention != nil && bucketLockConfig.CreatedAt != nil {
		expirationDate := *bucketLockConfig.CreatedAt
		if bucketLockConfig.DefaultRetention.Days != nil {
			expirationDate = expirationDate.AddDate(0, 0, int(*bucketLockConfig.DefaultRetention.Days))
		}
		if bucketLockConfig.DefaultRetention.Years != nil {
			expirationDate = expirationDate.AddDate(int(*bucketLockConfig.DefaultRetention.Years), 0, 0)
		}

		if expirationDate.After(time.Now()) {
			state.defaultRetention = bucketLockConfig.DefaultRetention
		}
	}

	vers, err := be.GetBucketVersioning(ctx, bucket)
	if err == nil && vers.Status != nil {
		state.versioningEnabled = *vers.Status == types.BucketVersioningStatusEnabled
	}

	return state, nil
}

// checkObject reports whether one object's retention or legal hold blocks
// this request. A nil error means this object is writable; it says nothing
// about any other object in the same request.
func (s objectLockState) checkObject(ctx context.Context, be backend.Backend, iam IAMService, acc Account, bucket string, obj types.ObjectIdentifier, bypass BypassMode, isBucketPublic bool, condCtx map[string][]string) error {
	var key, versionId string
	if obj.Key != nil {
		key = *obj.Key
	}
	if obj.VersionId != nil {
		versionId = *obj.VersionId
	}

	// if bucket versioning is enabled and versionId isn't provided
	// no lock check is needed, as it leads to a new delete marker creation
	if s.versioningEnabled && versionId == "" {
		return nil
	}

	checkRetention := true
	retentionData, err := be.GetObjectRetention(ctx, bucket, key, versionId)
	if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
		return nil
	}
	// the object is a delete marker, if a `MethodNotAllowed` error is returned
	// no object lock check is needed
	if errors.Is(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)) {
		return nil
	}
	if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) {
		checkRetention = false
	}
	if err != nil && checkRetention {
		return err
	}

	if checkRetention {
		retention, err := ParseObjectLockRetentionOutput(retentionData)
		if err != nil {
			return err
		}

		if retention.Mode != "" && retention.RetainUntilDate != nil {
			// An expired retention protects nothing, and an object's own
			// retention supersedes the bucket default, so this object is
			// past its lock. Note this also skips the legal-hold check
			// below, preserving long-standing behavior; it returns for
			// this object only, where the same statement previously
			// short-circuited the caller's whole request and let every
			// remaining object through unchecked.
			if retention.RetainUntilDate.Before(time.Now()) {
				return nil
			}

			if err := s.checkRetentionMode(ctx, be, iam, acc, bucket, key, retention.Mode, bypass, isBucketPublic, condCtx); err != nil {
				return err
			}
		}
	}

	checkLegalHold := true

	status, err := be.GetObjectLegalHold(ctx, bucket, key, versionId)
	if err != nil {
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
			return nil
		}
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) {
			checkLegalHold = false
		} else {
			return err
		}
	}

	if checkLegalHold && *status {
		return s3err.GetAPIError(s3err.ErrObjectLocked)
	}

	if s.defaultRetention != nil {
		return s.checkRetentionMode(ctx, be, iam, acc, bucket, key, s.defaultRetention.Mode, bypass, isBucketPublic, condCtx)
	}

	return nil
}

// checkRetentionMode applies one retention mode's rule: COMPLIANCE blocks
// unconditionally, GOVERNANCE blocks unless the request both asked to
// override it and is permitted to.
func (s objectLockState) checkRetentionMode(ctx context.Context, be backend.Backend, iam IAMService, acc Account, bucket, key string, mode types.ObjectLockRetentionMode, bypass BypassMode, isBucketPublic bool, condCtx map[string][]string) error {
	switch mode {
	case types.ObjectLockRetentionModeGovernance:
		if !bypass.allowsGovernanceOverride() {
			return s3err.GetAPIError(s3err.ErrObjectLocked)
		}
		return verifyBypassGovernancePermission(ctx, be, iam, acc, bucket, key, bypass, isBucketPublic, condCtx)
	case types.ObjectLockRetentionModeCompliance:
		return s3err.GetAPIError(s3err.ErrObjectLocked)
	}

	return nil
}
