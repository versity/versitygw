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
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/internal/condition"
)

// ListBucketsScope is which buckets ListBuckets returns to a caller that is
// neither root nor an admin, under an IAM backend with no identity-policy
// layer. There each account acts as its own AWS account, so by default it
// lists only the buckets it owns, as AWS does. The wider scopes are a
// gateway extension for sharing buckets between accounts.
type ListBucketsScope string

const (
	// ListBucketsScopeOwned lists the buckets the caller owns. The default.
	ListBucketsScopeOwned ListBucketsScope = "owned"
	// ListBucketsScopeAccessible also lists each bucket whose ACL or bucket
	// policy grants the caller s3:ListBucket on at least part of it, as
	// BucketVisibleTo decides.
	ListBucketsScopeAccessible ListBucketsScope = "accessible"
	// ListBucketsScopeAll lists every bucket, the way an IAM user allowed
	// s3:ListAllMyBuckets sees its AWS account's buckets.
	ListBucketsScopeAll ListBucketsScope = "all"
)

// ParseListBucketsScope parses s, ignoring case and surrounding space. An
// empty s is ListBucketsScopeOwned.
func ParseListBucketsScope(s string) (ListBucketsScope, error) {
	switch scope := ListBucketsScope(strings.ToLower(strings.TrimSpace(s))); scope {
	case "":
		return ListBucketsScopeOwned, nil
	case ListBucketsScopeOwned, ListBucketsScopeAccessible, ListBucketsScopeAll:
		return scope, nil
	}
	return "", fmt.Errorf("invalid list buckets scope %q: must be %q, %q or %q",
		s, ListBucketsScopeOwned, ListBucketsScopeAccessible, ListBucketsScopeAll)
}

// ValidateListBucketsScope checks that scope can be used with iam. An IAM
// backend that evaluates identity policies or fixes bucket ownership — the
// standalone IAM service — lists buckets exactly as S3 does, deciding with
// s3:ListAllMyBuckets, and no gateway setting may change that. So only
// ListBucketsScopeOwned, which changes nothing, is accepted with one. The
// empty scope is ListBucketsScopeOwned.
func ValidateListBucketsScope(iam IAMService, scope ListBucketsScope) error {
	switch scope {
	case "", ListBucketsScopeOwned:
		return nil
	case ListBucketsScopeAccessible, ListBucketsScopeAll:
	default:
		return fmt.Errorf("invalid list buckets scope %q: must be %q, %q or %q",
			scope, ListBucketsScopeOwned, ListBucketsScopeAccessible, ListBucketsScopeAll)
	}

	_, fixesOwner := iam.(FixedBucketOwner)
	_, evaluatesPolicies := iam.(PolicyEvaluator)
	if fixesOwner || evaluatesPolicies {
		return fmt.Errorf("list buckets scope %q is not supported with an IAM service that evaluates identity policies, such as the standalone IAM service: "+
			"ListBuckets there follows S3 and is granted by s3:ListAllMyBuckets, so the scope must be %q",
			scope, ListBucketsScopeOwned)
	}
	return nil
}

// listObjectsConditionKeys are the condition keys that describe a
// ListObjects request. A ListBuckets request has no values for them, so
// whether a statement conditioned on one applies to some ListObjects request
// the caller could make is unknown.
var listObjectsConditionKeys = []string{"s3:prefix", "s3:delimiter", "s3:max-keys"}

// BucketVisibleTo reports whether ListBuckets lists bucket to acc under
// ListBucketsScopeAccessible: whether acc owns it or could list at least
// part of it. acl is the bucket's ACL, policy its bucket policy (nil or
// empty for none) and condCtx the ListBuckets request's condition keys, as
// ListBucketsConditionContext builds them.
//
// A bucket acc owns is always visible, whatever its policy says. Any other
// bucket is visible when its ACL or its policy grants acc s3:ListBucket, and
// no Deny in its policy takes that away:
//
//   - An ACL grant counts as it does for ListObjects, except that a grant to
//     the AllUsers group does not, and with disableACL none does.
//   - A policy Allow counts when its Principal names acc itself. One naming
//     only "*" does not, since a public grant never makes a bucket visible.
//   - A policy Deny hides the bucket whomever its Principal names, "*"
//     included.
//
// A Condition clause on a key describing a ListObjects request (s3:prefix,
// s3:delimiter, s3:max-keys) is taken to hold in an Allow and not to hold in
// a Deny, so an Allow limited to part of the bucket still shows it and a
// Deny limited to part of it doesn't hide it. So is a clause with a value
// naming one of those keys as a policy variable, unless its other values
// already settle it, as condition.EvaluateAssuming describes. A Condition
// that can't be evaluated, or a policy that can't be parsed, hides the
// bucket.
//
// The result may show a bucket in which a contradictory policy lets acc list
// nothing, but never hides one acc could list part of.
func BucketVisibleTo(acc Account, bucket string, acl ACL, policy []byte, condCtx map[string][]string, disableACL bool) bool {
	if acl.Owner == acc.Access {
		return true
	}

	aclGrants := aclAllows(withoutPublicGrants(acl), acc.Access, ListBucketAction, disableACL)
	if len(policy) == 0 {
		return aclGrants
	}

	var bp BucketPolicy
	if err := json.Unmarshal(policy, &bp); err != nil {
		debuglogger.Logf("list buckets: hiding bucket %q, its bucket policy failed to parse: %v", bucket, err)
		return false
	}

	switch bp.visibilityFor(acc, bucket, condCtx) {
	case policyDecisionAllow:
		return true
	case policyDecisionDeny:
		return false
	}
	return aclGrants
}

// visibilityFor is decisionFor for s3:ListBucket on bucket, as
// BucketVisibleTo applies it: an Allow decides only when it names acc
// itself, and a Condition clause on a ListObjects key is assumed to hold in
// an Allow and not to hold in a Deny. Every statement covering acc, as
// decisionFor matches principals, is still checked for a Condition that
// can't be evaluated, which denies as it does in decisionFor.
func (bp *BucketPolicy) visibilityFor(acc Account, bucket string, condCtx map[string][]string) policyDecision {
	var isAllowed bool
	for _, statement := range bp.Statement {
		if !statement.matchesPrincipal(acc) ||
			!statement.Actions.FindMatch(ListBucketAction) ||
			!statement.Resources.FindMatch(bucket, nil) {
			continue
		}

		isAllow := statement.Effect == BucketPolicyAccessTypeAllow
		matched, evaluable := condition.EvaluateAssuming(statement.Condition, condCtx, string(bp.Version), listObjectsConditionKeys, isAllow)
		if !evaluable {
			return policyDecisionDeny
		}
		if !matched {
			continue
		}

		switch statement.Effect {
		case BucketPolicyAccessTypeAllow:
			if statement.Principals.namesCaller(acc) {
				isAllowed = true
			}
		case BucketPolicyAccessTypeDeny:
			return policyDecisionDeny
		}
	}

	if isAllowed {
		return policyDecisionAllow
	}
	return policyDecisionNoMatch
}

// namesCaller reports whether p names acc itself, rather than covering it
// only through "*".
func (p Principals) namesCaller(acc Account) bool {
	if !p.isPublic() {
		return p.matchFor(acc) == principalDirectMatch
	}

	named := make(Principals, len(p))
	for principal := range p {
		if principal != "*" {
			named.Add(principal)
		}
	}
	return named.matchFor(acc) == principalDirectMatch
}

// withoutPublicGrants returns acl without its grants to the AllUsers group.
func withoutPublicGrants(acl ACL) ACL {
	acl.Grantees = slices.DeleteFunc(slices.Clone(acl.Grantees), func(grt Grantee) bool {
		return grt.Type == types.TypeGroup && grt.Access == "all-users"
	})
	return acl
}
