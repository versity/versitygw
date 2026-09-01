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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

func VerifyObjectCopyAccess(ctx fiber.Ctx, be backend.Backend, copySource string, opts AccessOptions) error {
	// Verify destination bucket access first. VerifyAccess enforces the
	// readonly gate before its own root/admin bypass, and that ordering
	// must hold here too — readonly mode blocks writes for everyone,
	// including root/admin, not just ordinary users.
	if err := VerifyAccess(ctx, be, opts); err != nil {
		return err
	}
	// Root/admin already cleared the destination check above; skip the
	// source-bucket ACL lookup entirely for them, same as before.
	if opts.IsRoot {
		return nil
	}
	if opts.Acc.Role == RoleAdmin {
		return nil
	}

	// Verify source bucket access.
	// URL-decode the copy source before splitting so that clients which send
	// the bucket/key separator as "%2F" are handled correctly.
	// Callers are expected to have already stripped any leading '/'.
	decodedSrc, err := url.QueryUnescape(copySource)
	if err != nil {
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, copySource)
	}
	srcBucket, srcObject, found := strings.Cut(decodedSrc, "/")
	if !found {
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceBucket, copySource)
	}

	// Get source bucket ACL
	srcBucketACLBytes, err := be.GetBucketAcl(ctx.RequestCtx(), &s3.GetBucketAclInput{Bucket: &srcBucket})
	if err != nil {
		return err
	}

	var srcBucketAcl ACL
	if err := json.Unmarshal(srcBucketACLBytes, &srcBucketAcl); err != nil {
		return err
	}

	if err := VerifyAccess(ctx, be, AccessOptions{
		Acl:           srcBucketAcl,
		AclPermission: PermissionRead,
		IsRoot:        opts.IsRoot,
		Acc:           opts.Acc,
		Bucket:        srcBucket,
		Object:        srcObject,
		Actions:       []Action{GetObjectAction},
		Iam:           opts.Iam,
		DisableACL:    opts.DisableACL,
	}); err != nil {
		return err
	}

	return nil
}

type AccessOptions struct {
	Acl             ACL
	AclPermission   Permission
	IsRoot          bool
	Acc             Account
	Bucket          string
	Object          string
	Actions         []Action
	Readonly        bool
	IsPublicRequest bool
	DisableACL      bool
	Iam             IAMService
}

// VerifyAccess decides whether opts.Acc may perform opts.Actions against
// opts.Bucket/opts.Object, combining the bucket's own resource-based
// decision (policy, or ACL absent one) with an identity-based decision from
// opts.Iam when it implements PolicyEvaluator. An explicit Deny from either
// source denies the request outright, even when the other source would
// otherwise allow it; absent any explicit Deny, either source's Allow is
// independently sufficient; absent both, the request is denied. All three
// denial shapes are Code: AccessDenied, HTTP 403 — differing only in the
// dynamic Message text.
func VerifyAccess(ctx fiber.Ctx, be backend.Backend, opts AccessOptions) error {
	if err := verifyAccessGates(opts); err != nil || !authorizationApplies(opts) {
		return err
	}

	errs, err := objectsAccessErrors(ctx.RequestCtx(), be, opts, []string{opts.Object}, requestConditionContext(ctx))
	if err != nil {
		return err
	}
	return errs[0]
}

// VerifyObjectsAccess authorizes a multi-object delete — the parsed contents
// of a DeleteObjects request body, passed straight through. It answers, for
// every object independently, whether policy allows deleting it and whether
// an object lock protects it, in a single pass. DeleteObjects supports
// partial success — unlike every other write path — so a denial on one
// object must not affect any other: the caller sends only the objects that
// pass through to the backend, and reports the rest as per-object errors
// straight from the returned slice.
//
// Both halves are deliberately here rather than split across the caller: the
// per-object work needs one loop, not one loop per concern at a different
// layer, and the expensive parts of each half — the bucket policy, the
// batched identity-policy round trip, the bucket's lock configuration — are
// resolved once up front for the whole request.
//
// Every key is authorized against its own object ARN, the way real AWS does
// it: a policy granting s3:DeleteObject on "arn:aws:s3:::bucket/*" and
// nothing else deletes successfully. An object named with a VersionId is
// authorized against s3:DeleteObjectVersion instead of s3:DeleteObject, the
// same split the single-object DELETE path already makes: a policy granting
// only s3:DeleteObject denies the versioned deletes in the same batch that
// its keyed deletes succeed under, and the batch's response reports that
// denial on just that object, the rest unaffected.
//
// The returned slice has one entry per object: nil where that object may
// proceed, an AWS-shaped denial otherwise. opts.Object and opts.Actions are
// both ignored in favor of objects. The second return is non-nil only for a
// failure that isn't about any one object — readonly mode, or an error
// resolving the bucket's policy or lock configuration — and fails the whole
// request, matching what a hard failure did before this returned per-object
// results at all.
func VerifyObjectsAccess(ctx fiber.Ctx, be backend.Backend, opts AccessOptions, objects []types.ObjectIdentifier, bypass BypassMode) ([]error, error) {
	if err := verifyAccessGates(opts); err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, nil
	}

	rctx := ctx.RequestCtx()
	condCtx := requestConditionContext(ctx)

	keys := make([]string, len(objects))
	for i, obj := range objects {
		if obj.Key != nil {
			keys[i] = *obj.Key
		}
	}

	errs := make([]error, len(objects))

	// Authorization doesn't apply to root, admin, or a public-bucket
	// request — errs stays all-nil from policy's perspective, and object
	// locks still apply to them, so the loop below runs either way.
	if authorizationApplies(opts) {
		var plainIdx, versionedIdx []int
		for i, obj := range objects {
			if obj.VersionId != nil && *obj.VersionId != "" {
				versionedIdx = append(versionedIdx, i)
			} else {
				plainIdx = append(plainIdx, i)
			}
		}

		if err := authorizeObjectSubset(rctx, be, opts, keys, plainIdx, DeleteObjectAction, errs, condCtx); err != nil {
			return nil, err
		}
		if err := authorizeObjectSubset(rctx, be, opts, keys, versionedIdx, DeleteObjectVersionAction, errs, condCtx); err != nil {
			return nil, err
		}
	}

	lockState, err := loadObjectLockState(rctx, be, opts.Bucket, false)
	if err != nil {
		return nil, err
	}
	if lockState.applies {
		for i, obj := range objects {
			if errs[i] != nil {
				// Already denied by policy — no need to also resolve this
				// object's lock state, and a lock error here would only
				// overwrite the more specific policy denial.
				continue
			}
			if err := lockState.checkObject(rctx, be, opts.Iam, opts.Acc, opts.Bucket, obj, bypass, opts.IsPublicRequest, condCtx); err != nil {
				errs[i] = err
			}
		}
	}

	return errs, nil
}

// authorizeObjectSubset runs objectsAccessErrors for the objects at idx (a
// subset of keys, given by original index) against a single action, and
// scatters the results back into errs at their original positions. Splitting
// DeleteObjects' batch into one group per action this way keeps the
// round-trip count at one per distinct action in the batch — normally one or
// two — rather than one per object.
func authorizeObjectSubset(ctx context.Context, be backend.Backend, opts AccessOptions, keys []string, idx []int, action Action, errs []error, condCtx map[string][]string) error {
	if len(idx) == 0 {
		return nil
	}

	subKeys := make([]string, len(idx))
	for i, origIdx := range idx {
		subKeys[i] = keys[origIdx]
	}

	subOpts := opts
	subOpts.Actions = []Action{action}
	subErrs, err := objectsAccessErrors(ctx, be, subOpts, subKeys, condCtx)
	if err != nil {
		return err
	}
	for i, origIdx := range idx {
		errs[origIdx] = subErrs[i]
	}
	return nil
}

// verifyAccessGates applies the checks that depend on gateway configuration
// rather than on the caller's policies. Readonly mode blocks writes for
// everyone, root and admin included, which is why it runs before any bypass.
func verifyAccessGates(opts AccessOptions) error {
	if opts.Readonly {
		if opts.AclPermission == PermissionWrite || opts.AclPermission == PermissionWriteAcp {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}
	return nil
}

// authorizationApplies reports whether policy/ACL evaluation is meaningful
// for this caller at all. It is not for an anonymous request to a public
// bucket (already authorized by the public-access check) nor for root/admin
// (who bypass policy entirely — though not object locks).
func authorizationApplies(opts AccessOptions) bool {
	return !opts.IsPublicRequest && !opts.IsRoot && opts.Acc.Role != RoleAdmin
}

// objectsAccessErrors evaluates every key against the bucket's resource
// policy (or ACL) and the caller's identity policy, returning one result per
// key: nil where the key is authorized, and the AWS-shaped denial otherwise.
// The returned slice always has one entry per key.
//
// The keys are evaluated as one batch, not one VerifyAccess call each: the
// bucket policy is fetched once, and the identity policy is evaluated for
// every key in a single round trip to the IAM service. A per-key loop would
// cost a backend call and a network round trip per object, and DeleteObjects
// accepts up to 1000 of them.
func objectsAccessErrors(ctx context.Context, be backend.Backend, opts AccessOptions, keys []string, condCtx map[string][]string) ([]error, error) {
	resourceDecisions, err := verifyResourceAccess(ctx, be, opts, keys, condCtx)
	if err != nil {
		return nil, err
	}

	errs := make([]error, len(keys))

	// An explicit deny from the bucket policy wins outright, whatever the
	// IAM backend is and whatever an identity policy would have said, so
	// every denied key is settled here and never revisited below. Each key
	// is settled on its own: this is a partial-success API, so a deny on one
	// key says nothing about the next one, which still has to be evaluated
	// on its own merits.
	allDenied := true
	for i, rd := range resourceDecisions {
		if rd.Decision == policyDecisionDeny {
			errs[i] = s3err.GetExplicitDenyAccessErr(opts.Acc.Access, string(rd.Action), objectPolicyArn(opts.Bucket, keys[i], be.NormalizeObjectKey), "a resource-based policy")
			continue
		}
		allDenied = false
	}
	// Nothing is left to decide, so skip the identity policy entirely —
	// which also saves the standalone IAM service round trip. That shortcut
	// only holds when the bucket policy denied every key; a single
	// undecided key still needs the identity policy consulted for it.
	if allDenied {
		return errs, nil
	}

	pe, hasPolicyEvaluator := opts.Iam.(PolicyEvaluator)
	if !hasPolicyEvaluator {
		// No identity-policy layer exists for this backend at all: preserve
		// today's exact behavior and generic message, unconditionally, for
		// every internal/LDAP/Vault/IPA/S3-IAM deployment.
		for i, rd := range resourceDecisions {
			if errs[i] != nil {
				// Explicitly denied above — keep that specific message
				// rather than flattening it to the generic one.
				continue
			}
			if rd.Decision != policyDecisionAllow {
				errs[i] = s3err.GetAPIError(s3err.ErrAccessDenied)
			}
		}
		return errs, nil
	}

	identity, err := identityPolicyDecisions(pe, opts, keys, be.NormalizeObjectKey, condCtx)
	if err != nil {
		return nil, err
	}

	principal := identity.PrincipalArn
	if principal == "" {
		principal = opts.Acc.Access
	}

	for i := range keys {
		if errs[i] != nil {
			// Explicitly denied by the bucket policy. An explicit deny is
			// final, so no identity-policy result can clear it, and the
			// resource-based message is the one AWS reports for it.
			continue
		}

		resourceArn := objectPolicyArn(opts.Bucket, keys[i], be.NormalizeObjectKey)

		if identity.Decisions[i].Decision == policyDecisionDeny {
			errs[i] = s3err.GetExplicitDenyAccessErr(principal, string(identity.Decisions[i].Action), resourceArn, "an identity-based policy")
			continue
		}
		if identity.HasSessionPolicy && identity.SessionDecisions[i].Decision == policyDecisionDeny {
			errs[i] = s3err.GetExplicitDenyAccessErr(principal, string(identity.SessionDecisions[i].Action), resourceArn, "an identity-based policy")
			continue
		}

		granted := resourceDecisions[i].Decision == policyDecisionAllow ||
			identity.Decisions[i].Decision == policyDecisionAllow

		// A session policy filters everything the session can do — including
		// what the bucket policy granted it, not just what the role's own
		// policies did. Confirmed against real AWS: a role with no identity
		// policy at all, a bucket policy granting it both s3:GetObject and
		// s3:PutObject, and a session policy allowing only s3:GetObject
		// yields a successful Get and a denied Put.
		if identity.HasSessionPolicy && identity.SessionDecisions[i].Decision != policyDecisionAllow {
			granted = false
		}
		if granted {
			continue
		}

		blamedAction := resourceDecisions[i].Action
		if blamedAction == "" {
			blamedAction = identity.Decisions[i].Action
		}
		if blamedAction == "" && identity.HasSessionPolicy {
			blamedAction = identity.SessionDecisions[i].Action
		}
		errs[i] = s3err.GetImplicitDenyAccessErr(principal, string(blamedAction), resourceArn)
	}

	return errs, nil
}

// decisionForResource is one resource's tri-state decision plus, for
// Deny/NoMatch, the specific action responsible — so the caller can build an
// AWS-shaped message naming it.
type decisionForResource struct {
	Decision policyDecision
	Action   Action
}

// verifyResourceAccess checks the bucket's own policy or, absent one, ACL,
// for each object key, returning one decision per key. The bucket policy is
// fetched once regardless of how many keys there are. ACL evaluation can
// only ever produce Allow/NoMatch — ACLs have no concept of an explicit
// deny — and applies to the whole bucket, so every key shares its verdict.
func verifyResourceAccess(ctx context.Context, be backend.Backend, opts AccessOptions, objects []string, condCtx map[string][]string) ([]decisionForResource, error) {
	decisions := make([]decisionForResource, len(objects))

	policy, policyErr := be.GetBucketPolicy(ctx, opts.Bucket)
	if policyErr != nil {
		if !errors.Is(policyErr, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
			return nil, policyErr
		}

		decision := policyDecisionAllow
		if err := verifyACL(opts.Acl, opts.Acc.Access, opts.AclPermission, opts.DisableACL); err != nil {
			decision = policyDecisionNoMatch
		}
		for i := range decisions {
			decisions[i] = decisionForResource{Decision: decision}
		}
		return decisions, nil
	}

	for i, object := range objects {
		decision, action, err := verifyBucketPolicy(policy, opts.Acc.Access, opts.Bucket, object, condCtx, be.NormalizeObjectKey, opts.Actions...)
		if err != nil {
			return nil, err
		}
		decisions[i] = decisionForResource{Decision: decision, Action: action}
	}
	return decisions, nil
}

// identityPolicyDecisions evaluates every action in opts.Actions against
// every object key, all in a single request, and aggregates each key's
// actions with the same precedence bucketPolicyDecision uses for a bucket
// policy: a Deny on any action wins immediately; otherwise Allow only if
// every action has a matching Allow; otherwise NoMatch, paired with the
// first action that lacked one.
//
// It returns one decision per key, plus the resolved principal ARN, which is
// shared across the whole batch since one call always evaluates a single
// identity.
func identityPolicyDecisions(pe PolicyEvaluator, opts AccessOptions, objects []string, normalizeObjectKey objectKeyNormalizer, condition map[string][]string) (identityDecisions, error) {
	resources := make([]string, len(objects))
	for i, object := range objects {
		resources[i] = objectPolicyArn(opts.Bucket, object, normalizeObjectKey)
	}

	eval, err := pe.EvaluatePolicy(opts.Acc.Access, opts.Acc.SessionToken, opts.Actions, resources, condition)
	if err != nil {
		return identityDecisions{}, err
	}

	decisions, err := aggregateActionDecisions(eval.Decisions, resources, opts.Actions)
	if err != nil {
		return identityDecisions{}, err
	}

	result := identityDecisions{Decisions: decisions, PrincipalArn: eval.PrincipalArn}
	if eval.HasSessionPolicy {
		sessionDecisions, err := aggregateActionDecisions(eval.SessionDecisions, resources, opts.Actions)
		if err != nil {
			return identityDecisions{}, err
		}
		result.HasSessionPolicy = true
		result.SessionDecisions = sessionDecisions
	}
	return result, nil
}

// identityDecisions is identityPolicyDecisions' result: one aggregated
// decision per object from the caller's identity policies, the same from its
// session policy when it has one, and the resolved principal ARN.
type identityDecisions struct {
	Decisions        []decisionForResource
	SessionDecisions []decisionForResource
	HasSessionPolicy bool
	PrincipalArn     string
}

// aggregateActionDecisions collapses each resource's per-action decisions
// into one, using the same precedence bucketPolicyDecision uses: a Deny on
// any action wins immediately; otherwise Allow only if every action has a
// matching Allow; otherwise NoMatch, paired with the first action that
// lacked one.
func aggregateActionDecisions(matrix [][]policyDecision, resources []string, actions []Action) ([]decisionForResource, error) {
	if len(matrix) != len(resources) {
		// A protocol mismatch between the gateway and IAM service builds —
		// fail closed rather than authorizing a key nobody evaluated.
		return nil, fmt.Errorf("evaluate policy returned %d resource decisions for %d resources", len(matrix), len(resources))
	}

	results := make([]decisionForResource, len(resources))
	for i, perAction := range matrix {
		if len(perAction) != len(actions) {
			return nil, fmt.Errorf("evaluate policy returned %d action decisions for %d actions", len(perAction), len(actions))
		}

		result := decisionForResource{Decision: policyDecisionAllow}
		for j, decision := range perAction {
			if decision == policyDecisionDeny {
				result = decisionForResource{Decision: policyDecisionDeny, Action: actions[j]}
				break
			}
			if decision == policyDecisionNoMatch && result.Decision != policyDecisionNoMatch {
				result.Decision = policyDecisionNoMatch
				result.Action = actions[j]
			}
		}
		results[i] = result
	}
	return results, nil
}

// objectPolicyArn builds the ARN a policy statement is matched against for
// one bucket/object pair — the bucket's own ARN when object is empty.
func objectPolicyArn(bucket, object string, normalizeObjectKey objectKeyNormalizer) string {
	return ResourceArnPrefix + makePolicyResource(bucket, object, normalizeObjectKey)
}

// VerifyPublicAccess checks if the bucket is publically accessible by ACL or Policy
func VerifyPublicAccess(ctx fiber.Ctx, be backend.Backend, action Action, permission Permission, bucket, object string) error {
	// ACL disabled
	policy, err := be.GetBucketPolicy(ctx.RequestCtx(), bucket)
	if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
		return err
	}
	if err == nil {
		err = VerifyPublicBucketPolicy(policy, bucket, object, requestConditionContext(ctx), be.NormalizeObjectKey, action)
		if errors.Is(err, errExplicitDeny) {
			// Explicit public-policy Deny has higher precedence than any
			// public ACL grant, so do not continue to ACL fallback.
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
		if err == nil {
			// if ACLs are disabled, and the bucket grants public access,
			// policy actions should return 'MethodNotAllowed'
			switch action {
			case GetBucketPolicyAction:
				return s3err.GetMethodNotAllowedErr(http.MethodGet, s3err.ResourceTypeBucketPolicy, nil)
			case PutBucketPolicyAction:
				return s3err.GetMethodNotAllowedErr(http.MethodPut, s3err.ResourceTypeBucketPolicy, nil)
			case DeleteBucketPolicyAction:
				return s3err.GetMethodNotAllowedErr(http.MethodDelete, s3err.ResourceTypeBucketPolicy, nil)
			}

			return nil
		}
	}

	// if the action is not in the ACL whitelist the access is denied
	_, ok := publicACLAllowedActions[action]
	if !ok {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	err = VerifyPublicBucketACL(ctx.RequestCtx(), be, bucket, action, permission)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}

// VerifyCreateBucketAccess decides whether acc may create a bucket named
// bucket. Unlike VerifyAccess, the bucket doesn't exist yet at this point,
// so there is no bucket policy or ACL to consult — root/admin always
// bypass, and otherwise authorization comes from whichever mechanism the
// configured iam backend actually supports: for backends that implement
// PolicyEvaluator (currently only the standalone IAM service client), an
// identity-policy Allow for s3:CreateBucket grants access, exactly like any
// other IAM-policy-gated action; the legacy userplus-role bypass applies
// only to backends with no such policy layer (internal/LDAP/Vault/IPA/S3-IAM),
// since those have no other way to grant a plain "user" account this
// permission.
func VerifyCreateBucketAccess(ctx fiber.Ctx, iam IAMService, isRoot bool, acc Account, bucket string) error {
	if isRoot || acc.Role == RoleAdmin {
		return nil
	}

	pe, hasPolicyEvaluator := iam.(PolicyEvaluator)
	if !hasPolicyEvaluator {
		if acc.Role == RoleUserPlus {
			return nil
		}
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return verifyIdentityOnlyAccess(ctx, pe, acc, CreateBucketAction, bucket)
}

// VerifyListAllMyBucketsAccess decides whether acc may list buckets. The
// request names no bucket, so only identity policies apply: an Allow for
// s3:ListAllMyBuckets on "arn:aws:s3:::*", the ARN AWS's own bucket-listing
// policy names. Backends with no identity-policy layer already narrow the
// listing to the caller's own buckets, so they need no permission of their own.
func VerifyListAllMyBucketsAccess(ctx fiber.Ctx, iam IAMService, isRoot bool, acc Account) error {
	if isRoot || acc.Role == RoleAdmin {
		return nil
	}

	pe, hasPolicyEvaluator := iam.(PolicyEvaluator)
	if !hasPolicyEvaluator {
		return nil
	}

	return verifyIdentityOnlyAccess(ctx, pe, acc, ListAllMyBucketsAction, "*")
}

// verifyIdentityOnlyAccess decides one action from the caller's identity
// policies alone, for requests naming no existing bucket and therefore no
// resource-based policy. resource is the ARN part after "arn:aws:s3:::": a
// bucket name for CreateBucket, "*" for an account-level action.
func verifyIdentityOnlyAccess(ctx fiber.Ctx, pe PolicyEvaluator, acc Account, action Action, resource string) error {
	resourceArn := ResourceArnPrefix + resource
	identity, err := identityPolicyDecisions(pe, AccessOptions{
		Acc:     acc,
		Bucket:  resource,
		Actions: []Action{action},
	}, []string{""}, nil, requestConditionContext(ctx))
	if err != nil {
		return err
	}

	principal := identity.PrincipalArn
	if principal == "" {
		principal = acc.Access
	}

	// A session policy narrows what the session may do; there is no resource
	// policy to combine with here, so the two decisions simply intersect.
	decision := identity.Decisions[0].Decision
	if identity.HasSessionPolicy {
		switch sd := identity.SessionDecisions[0].Decision; {
		case sd == policyDecisionDeny:
			decision = policyDecisionDeny
		case sd != policyDecisionAllow && decision == policyDecisionAllow:
			decision = policyDecisionNoMatch
		}
	}

	switch decision {
	case policyDecisionDeny:
		return s3err.GetExplicitDenyAccessErr(principal, string(action), resourceArn, "an identity-based policy")
	case policyDecisionAllow:
		return nil
	}
	return s3err.GetImplicitDenyAccessErr(principal, string(action), resourceArn)
}

type PublicACLAllowedActions map[Action]struct{}

var publicACLAllowedActions PublicACLAllowedActions = PublicACLAllowedActions{
	ListBucketAction:                 struct{}{},
	PutObjectAction:                  struct{}{},
	ListBucketMultipartUploadsAction: struct{}{},
	DeleteObjectAction:               struct{}{},
	ListBucketVersionsAction:         struct{}{},
	GetObjectAction:                  struct{}{},
	GetObjectAttributesAction:        struct{}{},
	GetObjectAclAction:               struct{}{},
}
