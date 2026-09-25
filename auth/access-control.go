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
	"slices"
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
// otherwise allow it; absent any explicit Deny, each action is allowed by
// either source's Allow on its own, and the request needs every action
// allowed. All three denial shapes are Code: AccessDenied, HTTP 403 —
// differing only in the dynamic Message text.
func VerifyAccess(ctx fiber.Ctx, be backend.Backend, opts AccessOptions) error {
	if err := verifyAccessGates(opts); err != nil || !authorizationApplies(opts) {
		return err
	}

	errs, err := objectsAccessErrors(ctx.RequestCtx(), be, opts, []string{opts.Object}, requestConditionContext(ctx, opts.Actions))
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
	// A DeleteObjects batch reads no If-Match/If-None-Match, so no
	// conditional-write key applies to any object in it.
	condCtx := requestConditionContext(ctx, nil)

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
//
// Within a key, each action is authorized on its own: it is allowed when
// either the bucket policy or the identity policy allows it, and the key is
// allowed when every action is. A tagged PutObject whose s3:PutObject comes
// from the bucket policy and whose s3:PutObjectTagging comes from the
// identity policy is therefore allowed, though neither source allows both.
func objectsAccessErrors(ctx context.Context, be backend.Backend, opts AccessOptions, keys []string, condCtx map[string][]string) ([]error, error) {
	if len(opts.Actions) == 0 {
		// With every action decided on its own, no actions would leave
		// nothing to deny. Fail closed rather than allow vacuously.
		return nil, errors.New("no actions to authorize")
	}

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
	for i, perAction := range resourceDecisions {
		if j := slices.Index(perAction, policyDecisionDeny); j >= 0 {
			errs[i] = s3err.GetExplicitDenyAccessErr(principalName(opts.Acc), string(opts.Actions[j]), objectPolicyArn(opts.Bucket, keys[i], be.NormalizeObjectKey), "a resource-based policy")
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
		for i, perAction := range resourceDecisions {
			if errs[i] != nil {
				// Explicitly denied above — keep that specific message
				// rather than flattening it to the generic one.
				continue
			}
			if slices.ContainsFunc(perAction, func(d policyDecision) bool { return d != policyDecisionAllow }) {
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
		principal = principalName(opts.Acc)
	}

	for i := range keys {
		if errs[i] != nil {
			// Explicitly denied by the bucket policy. An explicit deny is
			// final, so no identity-policy result can clear it, and the
			// resource-based message is the one AWS reports for it.
			continue
		}

		resourceArn := objectPolicyArn(opts.Bucket, keys[i], be.NormalizeObjectKey)

		if j := slices.Index(identity.Decisions[i], policyDecisionDeny); j >= 0 {
			errs[i] = s3err.GetExplicitDenyAccessErr(principal, string(opts.Actions[j]), resourceArn, "an identity-based policy")
			continue
		}
		if identity.HasSessionPolicy {
			if j := slices.Index(identity.SessionDecisions[i], policyDecisionDeny); j >= 0 {
				errs[i] = s3err.GetExplicitDenyAccessErr(principal, string(opts.Actions[j]), resourceArn, "an identity-based policy")
				continue
			}
		}

		// The first action neither source allows is the one the denial
		// names, which matches AWS: a tagged PutObject missing both actions
		// names s3:PutObject, and one missing only the tagging action names
		// s3:PutObjectTagging.
		for j, action := range opts.Actions {
			granted := resourceDecisions[i][j] == policyDecisionAllow ||
				identity.Decisions[i][j] == policyDecisionAllow

			// A session policy filters everything the session can do —
			// including what the bucket policy granted it, not just what the
			// role's own policies did: a role with no identity policy at
			// all, a bucket policy granting it both s3:GetObject and
			// s3:PutObject, and a session policy allowing only s3:GetObject
			// yields a successful Get and a denied Put.
			if identity.HasSessionPolicy && identity.SessionDecisions[i][j] != policyDecisionAllow {
				granted = false
			}
			if !granted {
				errs[i] = s3err.GetImplicitDenyAccessErr(principal, string(action), resourceArn)
				break
			}
		}
	}

	return errs, nil
}

// principalName is how a denial message names acc: by its principal ARN
// where the IAM backend gives it one, and by its access key id otherwise —
// the only name the other backends have for it.
func principalName(acc Account) string {
	if acc.Arn != "" {
		return acc.Arn
	}
	return acc.Access
}

// verifyResourceAccess checks the bucket's own policy or, absent one, ACL,
// for every action on each object key, returning decisions[i][j] for
// objects[i] and opts.Actions[j]. The bucket policy is fetched and parsed
// once regardless of how many keys there are. ACL evaluation can only ever
// produce Allow/NoMatch — ACLs have no concept of an explicit deny — and
// grants a permission on the whole bucket rather than an action on an
// object, so every key and action shares its verdict.
func verifyResourceAccess(ctx context.Context, be backend.Backend, opts AccessOptions, objects []string, condCtx map[string][]string) ([][]policyDecision, error) {
	decisions := make([][]policyDecision, len(objects))

	policy, policyErr := be.GetBucketPolicy(ctx, opts.Bucket)
	if policyErr != nil {
		if !errors.Is(policyErr, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
			return nil, policyErr
		}

		decision := policyDecisionAllow
		if err := verifyACL(opts.Acl, opts.Acc.Access, opts.AclPermission, opts.DisableACL); err != nil {
			decision = policyDecisionNoMatch
		}
		perAction := slices.Repeat([]policyDecision{decision}, len(opts.Actions))
		for i := range decisions {
			decisions[i] = perAction
		}
		return decisions, nil
	}

	var bp BucketPolicy
	if err := json.Unmarshal(policy, &bp); err != nil {
		return nil, fmt.Errorf("failed to parse the bucket policy: %w", err)
	}

	for i, object := range objects {
		resource := makePolicyResource(opts.Bucket, object, be.NormalizeObjectKey)
		decisions[i] = make([]policyDecision, len(opts.Actions))
		for j, action := range opts.Actions {
			decisions[i][j] = bp.decisionFor(opts.Acc, action, resource, condCtx, be.NormalizeObjectKey)
		}
	}
	return decisions, nil
}

// identityPolicyDecisions evaluates every action in opts.Actions against
// every object key, all in a single request. The result keeps one decision
// per action — Decisions[i][j] for objects[i] and opts.Actions[j], and the
// same for SessionDecisions when HasSessionPolicy is set — so the caller can
// combine each action with the bucket policy's decision for that same
// action. PrincipalArn is shared across the whole batch since one call
// always evaluates a single identity.
func identityPolicyDecisions(pe PolicyEvaluator, opts AccessOptions, objects []string, normalizeObjectKey objectKeyNormalizer, condition map[string][]string) (PolicyEvaluation, error) {
	resources := make([]string, len(objects))
	for i, object := range objects {
		resources[i] = objectPolicyArn(opts.Bucket, object, normalizeObjectKey)
	}

	eval, err := pe.EvaluatePolicy(opts.Acc.Access, opts.Acc.SessionToken, opts.Actions, resources, condition)
	if err != nil {
		return PolicyEvaluation{}, err
	}

	if err := checkDecisionMatrix(eval.Decisions, len(resources), len(opts.Actions)); err != nil {
		return PolicyEvaluation{}, err
	}
	if eval.HasSessionPolicy {
		if err := checkDecisionMatrix(eval.SessionDecisions, len(resources), len(opts.Actions)); err != nil {
			return PolicyEvaluation{}, err
		}
	}
	return eval, nil
}

// checkDecisionMatrix confirms matrix holds a decision for every resource
// and action that was asked about. A mismatch is a protocol mismatch
// between the gateway and IAM service builds — fail closed rather than
// authorizing a key or action nobody evaluated.
func checkDecisionMatrix(matrix [][]policyDecision, resources, actions int) error {
	if len(matrix) != resources {
		return fmt.Errorf("evaluate policy returned %d resource decisions for %d resources", len(matrix), resources)
	}
	for _, perAction := range matrix {
		if len(perAction) != actions {
			return fmt.Errorf("evaluate policy returned %d action decisions for %d actions", len(perAction), actions)
		}
	}
	return nil
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
		err = VerifyPublicBucketPolicy(policy, bucket, object, requestConditionContext(ctx, []Action{action}), be.NormalizeObjectKey, action)
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
	}, []string{""}, nil, requestConditionContext(ctx, []Action{action}))
	if err != nil {
		return err
	}

	principal := identity.PrincipalArn
	if principal == "" {
		principal = principalName(acc)
	}

	// A session policy narrows what the session may do; there is no resource
	// policy to combine with here, so the two decisions simply intersect.
	decision := identity.Decisions[0][0]
	if identity.HasSessionPolicy {
		switch sd := identity.SessionDecisions[0][0]; {
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
