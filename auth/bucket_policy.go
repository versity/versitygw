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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/versity/versitygw/internal/condition"
	"github.com/versity/versitygw/s3err"
)

var errAccessDenied = errors.New("access denied")
var errExplicitDeny = errors.New("explicit deny")

// policyDecision preserves the difference between "not allowed" and
// "denied". Public bucket authorization needs that distinction so no-match
// can fall back to ACLs while explicit Deny cannot; VerifyAccess needs it to
// combine a bucket policy's decision with an identity policy's own — an
// explicit Deny from either source must override an Allow from the other,
// which a plain bool can't express.
type policyDecision int

const (
	policyDecisionNoMatch policyDecision = iota
	policyDecisionAllow
	policyDecisionDeny
)

type policyErr string

func (p policyErr) Error() string {
	return string(p)
}

const (
	policyErrResourceMismatch        = policyErr("Action does not apply to any resource(s) in statement")
	policyErrInvalidResource         = policyErr("Policy has invalid resource")
	policyErrInvalidPrincipal        = policyErr("Invalid principal in policy")
	policyErrInvalidAction           = policyErr("Policy has invalid action")
	policyErrInvalidPolicy           = policyErr("This policy contains invalid Json")
	policyErrInvalidFirstChar        = policyErr("Policies must be valid JSON and the first byte must be '{'")
	policyErrEmptyStatement          = policyErr("Could not parse the policy: Statement is empty!")
	policyErrMissingStatmentField    = policyErr("Missing required field Statement")
	policyErrInvalidVersion          = policyErr("The policy must contain a valid version string")
	policyErrInvalidConditionKey     = policyErr("Policy has an invalid condition key")
	policyErrConditionActionMismatch = policyErr("Conditions do not apply to combination of actions and resources in statement")
	policyErrInvalidIPCondition      = policyErr("Invalid IP address in Conditions")
)

type BucketPolicy struct {
	Version   PolicyVersion      `json:"Version"`
	Statement []BucketPolicyItem `json:"Statement"`
}

type objectKeyNormalizer func(bucket, object string) string

func (bp *BucketPolicy) UnmarshalJSON(data []byte) error {
	var tmp struct {
		Version   *PolicyVersion
		Statement *[]BucketPolicyItem `json:"Statement"`
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// If Statement is nil (not present in JSON), return an error
	if tmp.Statement == nil {
		return policyErrMissingStatmentField
	}

	if tmp.Version == nil {
		// bucket policy version should default to '2008-10-17'
		bp.Version = PolicyVersion2008
	} else {
		bp.Version = *tmp.Version
	}

	bp.Statement = *tmp.Statement
	return nil
}

func (bp *BucketPolicy) Validate(bucket string, iam IAMService) error {
	if !bp.Version.isValid() {
		return policyErrInvalidVersion
	}

	for _, statement := range bp.Statement {
		err := statement.Validate(bucket, iam)
		if err != nil {
			return err
		}
	}

	return nil
}

// decisionFor evaluates a single action against bp for acc/resource,
// returning the tri-state policyDecision. A statement whose principal/action/resource
// otherwise matches but whose Condition block can't be evaluated
// denies the whole decision immediately, regardless of that statement's own
// Effect — the same "can't rule out a hidden Deny" fail-closed contract
// iamapi/policy.EvaluateIdentityPolicies uses for identity policies,
// enforced per-statement here instead of per-document. In practice this
// branch is unreachable for any policy PutBucketPolicy accepted after
// Condition write-time validation existed — it only guards a document
// stored before that validation existed, or naming a future operator the
// gateway doesn't yet recognize.
func (bp *BucketPolicy) decisionFor(acc Account, action Action, resource string, condCtx map[string][]string, normalizeObjectKey objectKeyNormalizer) policyDecision {
	var isAllowed bool
	for _, statement := range bp.Statement {
		matched, evaluable := statement.findMatch(acc, action, resource, condCtx, bp.Version, normalizeObjectKey)
		if !evaluable {
			return policyDecisionDeny
		}
		if !matched {
			continue
		}
		switch statement.Effect {
		case BucketPolicyAccessTypeAllow:
			isAllowed = true
		case BucketPolicyAccessTypeDeny:
			return policyDecisionDeny
		}
	}

	if isAllowed {
		return policyDecisionAllow
	}
	return policyDecisionNoMatch
}

// publicDecisionFor mirrors decisionFor for the anonymous/public-bucket-access
// path
func (bp *BucketPolicy) publicDecisionFor(resource string, action Action, condCtx map[string][]string, normalizeObjectKey objectKeyNormalizer) policyDecision {
	var isAllowed bool
	for _, statement := range bp.Statement {
		matched, evaluable := statement.isPublicFor(resource, action, condCtx, bp.Version, normalizeObjectKey)
		if !evaluable {
			return policyDecisionDeny
		}
		if !matched {
			continue
		}
		switch statement.Effect {
		case BucketPolicyAccessTypeAllow:
			isAllowed = true
		case BucketPolicyAccessTypeDeny:
			return policyDecisionDeny
		}
	}

	// A matching Allow grants access only when no matching Deny was found.
	if isAllowed {
		return policyDecisionAllow
	}
	return policyDecisionNoMatch
}

// IsPublic checks if one of bucket policy statments grant
// public access to ALL users
func (bp *BucketPolicy) IsPublic() bool {
	for _, statement := range bp.Statement {
		if statement.isPublic() {
			return true
		}
	}

	return false
}

type BucketPolicyItem struct {
	Effect     BucketPolicyAccessType `json:"Effect"`
	Principals Principals             `json:"Principal"`
	Actions    Actions                `json:"Action"`
	Resources  Resources              `json:"Resource"`
	Condition  json.RawMessage        `json:"Condition,omitempty"`
}

func (bpi *BucketPolicyItem) Validate(bucket string, iam IAMService) error {
	if err := bpi.Effect.Validate(); err != nil {
		return err
	}
	if err := bpi.Principals.Validate(iam); err != nil {
		return err
	}
	if err := bpi.Resources.Validate(bucket); err != nil {
		return err
	}

	// Condition applicability is checked before the action/resource-type
	// pairing below: AWS reports a Condition key that doesn't apply to the
	// statement's actions even when those actions also don't apply to the
	// statement's resource type, e.g. s3:prefix with s3:ListBucketMultipartUploads
	// against an object resource — reported as the Condition mismatch, not
	// the resource-type one.
	if err := validateBucketPolicyCondition(bpi.Condition, bpi.Actions); err != nil {
		return err
	}

	containsObjectAction := bpi.Resources.ContainsObjectPattern()
	containsBucketAction := bpi.Resources.ContainsBucketPattern()

	for action := range bpi.Actions {
		isObjectAction := action.IsObjectAction()
		if isObjectAction == nil {
			break
		}
		if *isObjectAction && !containsObjectAction {
			return policyErrResourceMismatch
		}
		if !*isObjectAction && !containsBucketAction {
			return policyErrResourceMismatch
		}
	}

	return nil
}

// findMatch reports whether the statement's principal/action/resource cover
// this request, and — only when they do — whether its Condition block holds
// against condCtx. matched is only meaningful when evaluable is true; see
// condition.Evaluate and decisionFor's fail-closed handling of evaluable =false.
func (bpi *BucketPolicyItem) findMatch(acc Account, action Action, resource string, condCtx map[string][]string, version PolicyVersion, normalizeObjectKey objectKeyNormalizer) (matched bool, evaluable bool) {
	if !(bpi.matchesPrincipal(acc) && bpi.Actions.FindMatch(action) && bpi.Resources.FindMatch(resource, normalizeObjectKey)) {
		return false, true
	}
	return condition.Evaluate(bpi.Condition, condCtx, string(version))
}

// matchesPrincipal reports whether this statement's Principal element
// covers acc, given what this statement's Effect makes of an account-level
// match.
//
// A statement naming the account — its root ARN, or the bare account id —
// only delegates to the account: it says the account's own IAM may grant
// this, not that this is granted. So it allows nothing by itself, and a
// caller under it is authorized only if an identity policy independently
// allows the request, which VerifyAccess already covers by treating either
// source's Allow as sufficient. Skipping the statement here is what makes
// the account-level Allow contribute nothing.
//
// Deny is not symmetric with that: a statement denying the account denies
// every principal in it outright, delegating nothing.
func (bpi *BucketPolicyItem) matchesPrincipal(acc Account) bool {
	switch bpi.Principals.matchFor(acc) {
	case principalDirectMatch:
		return true
	case principalAccountMatch:
		return bpi.Effect == BucketPolicyAccessTypeDeny
	default:
		return false
	}
}

// isPublicFor checks if the bucket policy statement grants public access
// for given resource and action, and — only when it otherwise matches —
// whether its Condition block holds against condCtx. A public statement's
// Condition is evaluated with whatever request-derived keys condCtx carries;
// there is no caller identity to resolve for an anonymous request
func (bpi *BucketPolicyItem) isPublicFor(resource string, action Action, condCtx map[string][]string, version PolicyVersion, normalizeObjectKey objectKeyNormalizer) (matched bool, evaluable bool) {
	if !(bpi.Principals.isPublic() && bpi.Actions.FindMatch(action) && bpi.Resources.FindMatch(resource, normalizeObjectKey)) {
		return false, true
	}
	return condition.Evaluate(bpi.Condition, condCtx, string(version))
}

// isPublic checks if the statement grants public access
// to ALL users
func (bpi *BucketPolicyItem) isPublic() bool {
	return bpi.Principals.isPublic()
}

func getMalformedPolicyError(err error) error {
	return s3err.APIError{
		Code:           "MalformedPolicy",
		Description:    err.Error(),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// ParsePolicyDocument parses raw bytes to 'BucketPolicy'
func ParsePolicyDocument(data []byte) (*BucketPolicy, error) {
	var policy BucketPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		var pe policyErr
		if errors.As(err, &pe) {
			return nil, getMalformedPolicyError(err)
		}
		return nil, getMalformedPolicyError(policyErrInvalidPolicy)
	}

	return &policy, nil
}

func ValidatePolicyDocument(policyBin []byte, bucket string, iam IAMService) error {
	if len(policyBin) == 0 || policyBin[0] != '{' {
		return getMalformedPolicyError(policyErrInvalidFirstChar)
	}
	policy, err := ParsePolicyDocument(policyBin)
	if err != nil {
		return err
	}

	if len(policy.Statement) == 0 {
		return getMalformedPolicyError(policyErrEmptyStatement)
	}

	if err := policy.Validate(bucket, iam); err != nil {
		var lookupErr principalLookupError
		if errors.As(err, &lookupErr) {
			// Not a defect in the document: the IAM service could not be
			// asked whether its principals exist. Report that as itself
			// rather than telling the caller their policy is malformed.
			return lookupErr.err
		}
		return getMalformedPolicyError(err)
	}

	return nil
}

// verifyBucketPolicy parses policyBytes and evaluates it against every
// action, aggregating with the same precedence isAllowed uses for a single
// action: a Deny on any action wins immediately (returned along with that
// action, for building an AWS-shaped message); otherwise the decision is
// Allow only if every action has a matching Allow; otherwise NoMatch,
// paired with the first action that lacked one. Zero actions is
// conservatively NoMatch, not vacuously Allow.
func verifyBucketPolicy(policyBytes []byte, acc Account, bucket, object string, condCtx map[string][]string, normalizeObjectKey objectKeyNormalizer, actions ...Action) (policyDecision, Action, error) {
	if len(actions) == 0 {
		return policyDecisionNoMatch, "", nil
	}

	var bp BucketPolicy
	if err := json.Unmarshal(policyBytes, &bp); err != nil {
		return policyDecisionNoMatch, "", fmt.Errorf("failed to parse the bucket policy: %w", err)
	}

	resource := makePolicyResource(bucket, object, normalizeObjectKey)

	result := policyDecisionAllow
	var blamed Action
	for _, action := range actions {
		switch d := bp.decisionFor(acc, action, resource, condCtx, normalizeObjectKey); d {
		case policyDecisionDeny:
			return policyDecisionDeny, action, nil
		case policyDecisionNoMatch:
			if result != policyDecisionNoMatch {
				result = policyDecisionNoMatch
				blamed = action
			}
		}
	}

	return result, blamed, nil
}

// Checks if the bucket policy grants public access
func VerifyPublicBucketPolicy(policy []byte, bucket, object string, condCtx map[string][]string, normalizeObjectKey objectKeyNormalizer, action Action) error {
	var bucketPolicy BucketPolicy
	if err := json.Unmarshal(policy, &bucketPolicy); err != nil {
		return err
	}

	resource := makePolicyResource(bucket, object, normalizeObjectKey)

	switch bucketPolicy.publicDecisionFor(resource, action, condCtx, normalizeObjectKey) {
	case policyDecisionAllow:
		return nil
	case policyDecisionDeny:
		return errExplicitDeny
	default:
		return errAccessDenied
	}
}

func makePolicyResource(bucket, object string, normalizeObjectKey objectKeyNormalizer) string {
	if object == "" {
		return bucket
	}

	return bucket + "/" + normalizePolicyObjectKey(bucket, object, normalizeObjectKey)
}

func normalizePolicyObjectKey(bucket, key string, normalizeObjectKey objectKeyNormalizer) string {
	if key == "" || normalizeObjectKey == nil {
		return key
	}

	return normalizeObjectKey(bucket, key)
}

// matchPattern checks if the input string matches the given pattern with wildcard(`*`) and any character(`?`).
// - `?` matches exactly one occurrence of any character.
// - `*` matches arbitrary many (including zero) occurrences of any character.
func matchPattern(pattern, input string) bool {
	pIdx, sIdx := 0, 0
	starIdx, matchIdx := -1, 0

	for sIdx < len(input) {
		if pIdx < len(pattern) && (pattern[pIdx] == '?' || pattern[pIdx] == input[sIdx]) {
			sIdx++
			pIdx++
		} else if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = sIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			sIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}

	return pIdx == len(pattern)
}
