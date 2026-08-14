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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/versity/versitygw/internal/condition"
)

// conditionKeyRule is one condition key's write-time compatibility check: a
// PutBucketPolicy statement naming this key in its Condition block is only
// accepted when appliesTo holds for every (non-wildcard) action the
// statement names
type conditionKeyRule struct {
	appliesTo func(Action) bool
	// ipSemantic marks a key AWS validates as an IP address/CIDR at write
	// time, independent of which operator wraps it.
	ipSemantic bool
}

func anyAction(Action) bool { return true }

// isListAction is s3:prefix/s3:delimiter/s3:max-keys' applicable-action set:
// s3:ListBucket and s3:ListBucketVersions, not s3:GetObject and — notably —
// not s3:ListBucketMultipartUploads either, so this is deliberately not
// "every List-shaped action".
func isListAction(a Action) bool {
	return a == ListBucketAction || a == ListBucketVersionsAction
}

// isAclPutAction is s3:x-amz-acl's applicable-action set: s3:PutObject,
// s3:PutBucketAcl, and s3:PutObjectAcl. s3:CreateBucket is excluded — AWS
// rejects s3:CreateBucket in any bucket-policy statement at all, a
// pre-existing, Condition-unrelated validation gap, since bucket policies
// attach to a bucket that must already exist.
func isAclPutAction(a Action) bool {
	switch a {
	case PutObjectAction, PutBucketAclAction, PutObjectAclAction:
		return true
	default:
		return false
	}
}

// isVersionedAction is s3:VersionId's applicable-action set: the *Version*
// action family.
func isVersionedAction(a Action) bool {
	switch a {
	case GetObjectVersionAction, DeleteObjectVersionAction, GetObjectVersionAttributesAction,
		GetObjectVersionTaggingAction, PutObjectVersionTaggingAction, DeleteObjectVersionTaggingAction:
		return true
	default:
		return false
	}
}

// bucketPolicyConditionKeys is the fixed catalogue of condition keys this
// gateway's S3 bucket-policy Condition support recognizes, each mapped to
// the actions it may be used with. Keys are looked up case-insensitively
// (AWS documents condition key *names*, unlike their values, as
// case-insensitive: "AWS:SourceIp" is accepted the same as "aws:SourceIp"),
// so every key here is stored lowercase.
//
// This deliberately does not cover AWS's full S3 condition-key catalogue —
// tag-based keys (s3:ExistingObjectTag/*, s3:RequestObjectTag/*,
// s3:RequestObjectTagKeys), object-lock keys, s3:x-amz-server-side-encryption
// (the gateway never reads that header, so enforcing it would be
// misleading), and aws:MultiFactorAuthAge (no MFA concept here) are out of
// scope. A Condition naming one of those is still accepted at write time —
// the key just never appears in the runtime context, so any Condition
// depending on it simply never matches, the same as any other key this
// package doesn't populate.
var bucketPolicyConditionKeys = map[string]conditionKeyRule{
	// Generic keys: AWS accepts these with any action.
	"aws:sourceip":           {appliesTo: anyAction, ipSemantic: true},
	"aws:currenttime":        {appliesTo: anyAction},
	"aws:epochtime":          {appliesTo: anyAction},
	"aws:securetransport":    {appliesTo: anyAction},
	"aws:useragent":          {appliesTo: anyAction},
	"aws:referer":            {appliesTo: anyAction},
	"aws:principalarn":       {appliesTo: anyAction},
	"aws:username":           {appliesTo: anyAction},
	"aws:userid":             {appliesTo: anyAction},
	"aws:multifactorauthage": {appliesTo: anyAction},

	// S3-specific keys: only valid with a specific action subset.
	"s3:prefix":    {appliesTo: isListAction},
	"s3:delimiter": {appliesTo: isListAction},
	"s3:max-keys":  {appliesTo: isListAction},
	"s3:x-amz-acl": {appliesTo: isAclPutAction},
	"s3:versionid": {appliesTo: isVersionedAction},
}

// lookupConditionKeyRule finds key's rule case-insensitively.
func lookupConditionKeyRule(key string) (conditionKeyRule, bool) {
	rule, ok := bucketPolicyConditionKeys[strings.ToLower(key)]
	return rule, ok
}

// validateBucketPolicyCondition checks a bucket-policy statement's raw
// Condition block against the same write-time rules real AWS enforces for
// PutBucketPolicy:
//
//   - an unrecognized operator name -> "Invalid Condition type : <Name>"
//   - a key outside bucketPolicyConditionKeys -> policyErrInvalidConditionKey
//   - a key whose rule doesn't apply to some (non-wildcard) action in
//     actions -> policyErrConditionActionMismatch. For an explicit
//     multi-action list, EVERY action must support the key (e.g.
//     ["s3:GetObject","s3:PutObject"] with the PutObject-only s3:x-amz-acl
//     is rejected even though PutObject alone would accept it); a wildcard
//     action pattern (containing '*' or '?', e.g. "s3:*" or
//     "s3:PutObject*") is exempt from this check entirely, so both accept
//     s3:x-amz-acl even though s3:* covers many actions that don't support
//     it.
//   - an ipSemantic key (aws:SourceIp) with a value that doesn't parse as
//     an IP address or CIDR range -> policyErrInvalidIPCondition,
//     regardless of which operator wraps it.
func validateBucketPolicyCondition(raw json.RawMessage, actions Actions) error {
	block, err := condition.Parse(raw)
	if err != nil {
		op, ok := unrecognizedConditionOperator(raw)
		if ok {
			//lint:ignore ST1005 Reason: This error message is intended for end-user clarity and follows their expectations
			return fmt.Errorf("Invalid Condition type : %s", op)
		}
		return policyErrInvalidPolicy
	}

	concreteActions := make([]Action, 0, len(actions))
	for action := range actions {
		if strings.ContainsAny(string(action), "*?") {
			continue
		}
		concreteActions = append(concreteActions, action)
	}

	for _, kvs := range block {
		for key, values := range kvs {
			rule, ok := lookupConditionKeyRule(key)
			if !ok {
				return policyErrInvalidConditionKey
			}
			for _, action := range concreteActions {
				if !rule.appliesTo(action) {
					return policyErrConditionActionMismatch
				}
			}
			if rule.ipSemantic {
				for _, v := range values {
					if !condition.ParseIPOrCIDR(v) {
						return policyErrInvalidIPCondition
					}
				}
			}
		}
	}
	return nil
}

// unrecognizedConditionOperator re-walks raw's top-level operator names to
// find the first one ParseOperatorName rejects, for building AWS's exact
// "Invalid Condition type : <Name>" message — condition.Parse itself only
// reports that parsing failed, not which operator caused it.
func unrecognizedConditionOperator(raw json.RawMessage) (string, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return "", false
	}
	for operator := range top {
		if _, ok := condition.ParseOperatorName(operator); !ok {
			return operator, true
		}
	}
	return "", false
}
