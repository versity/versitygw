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

package integration

// This file tests authorization (allow/deny) decisions for the standalone
// IAM/STS service: identity-based inline policies (user and role), role
// trust policies, and condition evaluation across both. It deliberately does
// not test policy-document validation, malformed input, or other API
// surface already covered by iam_put_user_policy.go/iam_create_role.go/etc.
//
// Session/session-policy scope: AssumeRoleWithWebIdentity is the only action
// that mints a session in this codebase, and a real successful call requires
// the server to fetch a real JWKS from the token's issuer and verify a real
// cryptographic signature. The SSRF guard in iamutil's OIDC fetch path
// (isDisallowedFetchTarget) unconditionally rejects loopback, private
// (RFC1918), and link-local addresses as fetch targets — so no JWKS server
// this test process stands up on the same machine can ever be reachable,
// and a real successful AssumeRoleWithWebIdentity is unreachable from this
// suite by design. Every test below that needs to observe a trust-policy
// "Allowed" decision instead uses the same technique the rest of this
// package's AssumeRoleWithWebIdentity tests already use (see
// IAMAssumeRoleWithWebIdentity_oaud_condition_matches in
// iam_assume_role_with_web_identity.go): point the provider at a loopback
// URL and observe that evaluation reaches the network-dependent signature
// step (InvalidIdentityTokenIDPCommunicationError) rather than being
// rejected earlier by trust evaluation itself (AccessDenied or the
// claims-stage InvalidIdentityToken). Reaching that step is only possible
// once Principal, Condition, and audience matching have all already
// succeeded, so it's a reliable, deterministic proxy for "Allowed" — but it
// means this suite cannot exercise anything that requires an actual minted
// session (session-policy intersection, a live session calling further IAM
// actions).

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

// Every ARN the gateway issues is scoped to this single fixed account.
const testAccountID = "000000000000"

const (
	actGetUser          = "iam:GetUser"
	actListUsers        = "iam:ListUsers"
	actListUserPolicies = "iam:ListUserPolicies"
	actGetUserPolicy    = "iam:GetUserPolicy"
	actDeleteUserPolicy = "iam:DeleteUserPolicy"
	actPutUserPolicy    = "iam:PutUserPolicy"
	actCreateUser       = "iam:CreateUser"
	actGetRole          = "iam:GetRole"
	actListRolePolicies = "iam:ListRolePolicies"
)

// defaultTestAudience is the OIDC ClientIDList/token-audience pair used by
// every trust-policy test below that isn't specifically exercising audience
// matching itself
var defaultTestAudience = []string{"client1"}

// IAMAccessControl_ImplicitDenyNoMatchingPolicy verifies a caller with no
// policies at all is denied by default (no Allow ever exists to grant
// anything).
func IAMAccessControl_ImplicitDenyNoMatchingPolicy(s *S3Conf) error {
	testName := "IAMAccessControl_ImplicitDenyNoMatchingPolicy"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", nil)
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_AllowGrantsMatchingRequest verifies a single matching
// Allow statement grants the request, and that the response actually
// reflects the target resource (not just a nil error) — proving the call
// was genuinely authorized and executed, not accidentally short-circuited.
func IAMAccessControl_AllowGrantsMatchingRequest(s *S3Conf) error {
	testName := "IAMAccessControl_AllowGrantsMatchingRequest"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"grant": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		out, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		if err := wantAllowed(caller.arn, actGetUser, targetArn, err); err != nil {
			return err
		}
		if out == nil || out.User == nil || aws.ToString(out.User.UserName) != targetName {
			return fmt.Errorf("expected GetUser to return user %q, got %#v", targetName, out)
		}
		return nil
	})
}

// IAMAccessControl_NonMatchingStatementDoesNotGrant verifies a policy whose
// only statement covers a *different* action does not grant the tested
// action — a non-matching statement contributes nothing, it isn't a
// fallback Allow.
func IAMAccessControl_NonMatchingStatementDoesNotGrant(s *S3Conf) error {
	testName := "IAMAccessControl_NonMatchingStatementDoesNotGrant"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actListRolePolicies, Resource: "*"})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"grant": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ExplicitDenyOverridesAllow verifies an explicit Deny
// always wins over a matching Allow, regardless of statement order or
// whether the Deny is in the same policy document or a separate one.
func IAMAccessControl_ExplicitDenyOverridesAllow(s *S3Conf) error {
	testName := "IAMAccessControl_ExplicitDenyOverridesAllow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		allow := accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn}
		deny := accessStatement{Effect: "Deny", Action: actGetUser, Resource: targetArn}

		cases := []struct {
			name     string
			policies map[string]string
		}{
			{"deny after allow, same document", map[string]string{"p": policyDoc(allow, deny)}},
			{"deny before allow, same document", map[string]string{"p": policyDoc(deny, allow)}},
			{"allow and deny in separate documents", map[string]string{"allow": policyDoc(allow), "deny": policyDoc(deny)}},
		}
		for _, tc := range cases {
			if err := func() error {
				caller, cleanupCaller, err := newAccessControlCaller(root, s, "", tc.policies)
				if err != nil {
					return err
				}
				defer cleanupCaller()

				_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
				return wantDenied(caller.arn, actGetUser, targetArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_MultipleStatementsEvaluatedIndependently verifies two
// statements in one policy document, covering two different actions, are
// each evaluated on their own terms: both grant their own action, and
// neither grants the other's.
func IAMAccessControl_MultipleStatementsEvaluatedIndependently(s *S3Conf) error {
	testName := "IAMAccessControl_MultipleStatementsEvaluatedIndependently"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(
			accessStatement{Sid: "AllowGet", Effect: "Allow", Action: actGetUser, Resource: targetArn},
			accessStatement{Sid: "AllowListPolicies", Effect: "Allow", Action: actListUserPolicies, Resource: targetArn},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); wantAllowed(caller.arn, actGetUser, targetArn, err) != nil {
			return wantAllowed(caller.arn, actGetUser, targetArn, err)
		}
		if _, err := listIAMUserPolicies(caller.client, &iam.ListUserPoliciesInput{UserName: aws.String(targetName)}); wantAllowed(caller.arn, actListUserPolicies, targetArn, err) != nil {
			return wantAllowed(caller.arn, actListUserPolicies, targetArn, err)
		}
		// Neither statement covers DeleteUserPolicy.
		_, err = deleteIAMUserPolicyRaw(caller.client, &iam.DeleteUserPolicyInput{UserName: aws.String(targetName), PolicyName: aws.String("irrelevant")})
		return wantDenied(caller.arn, actDeleteUserPolicy, targetArn, err)
	})
}

// IAMAccessControl_MultipleInlinePoliciesCombinedAllow verifies two separate
// inline policies attached to the same user are combined: a statement in
// either one is enough to grant its action.
func IAMAccessControl_MultipleInlinePoliciesCombinedAllow(s *S3Conf) error {
	testName := "IAMAccessControl_MultipleInlinePoliciesCombinedAllow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policies := map[string]string{
			"policy-a": policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn}),
			"policy-b": policyDoc(accessStatement{Effect: "Allow", Action: actListUserPolicies, Resource: targetArn}),
		}
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", policies)
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, targetArn, err)
		}
		_, err = listIAMUserPolicies(caller.client, &iam.ListUserPoliciesInput{UserName: aws.String(targetName)})
		return wantAllowed(caller.arn, actListUserPolicies, targetArn, err)
	})
}

// IAMAccessControl_MultipleInlinePoliciesExplicitDenyWins verifies a Deny in
// one inline policy overrides an Allow in a *different* inline policy on the
// same user — combination is not "most permissive wins", explicit Deny is
// global across every attached policy.
func IAMAccessControl_MultipleInlinePoliciesExplicitDenyWins(s *S3Conf) error {
	testName := "IAMAccessControl_MultipleInlinePoliciesExplicitDenyWins"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policies := map[string]string{
			"allow-everything": policyDoc(accessStatement{Effect: "Allow", Action: "iam:*", Resource: "*"}),
			"deny-get-user":    policyDoc(accessStatement{Effect: "Deny", Action: actGetUser, Resource: targetArn}),
		}
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", policies)
		if err != nil {
			return err
		}
		defer cleanupCaller()

		// The broad Allow still grants an unrelated action...
		if _, err := listIAMUserPolicies(caller.client, &iam.ListUserPoliciesInput{UserName: aws.String(targetName)}); err != nil {
			return wantAllowed(caller.arn, actListUserPolicies, targetArn, err)
		}
		// ...but the specific Deny still wins for the action it names.
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_EffectNonMatchingAllowStillImplicitlyDenies verifies an
// Allow statement present in a policy but not covering the tested
// action/resource contributes nothing — the request is still implicitly
// denied, not accidentally granted just because *some* Allow exists
// somewhere in the document.
func IAMAccessControl_EffectNonMatchingAllowStillImplicitlyDenies(s *S3Conf) error {
	testName := "IAMAccessControl_EffectNonMatchingAllowStillImplicitlyDenies"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()
		otherName, _, cleanupOther, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupOther()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: "arn:aws:iam::" + testAccountID + ":user/" + otherName})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_EffectNonMatchingDenyDoesNotBlockUnrelatedAllow verifies
// a Deny statement that doesn't cover the tested action/resource simply
// doesn't apply — it does not somehow block an unrelated Allow elsewhere in
// the same policy.
func IAMAccessControl_EffectNonMatchingDenyDoesNotBlockUnrelatedAllow(s *S3Conf) error {
	testName := "IAMAccessControl_EffectNonMatchingDenyDoesNotBlockUnrelatedAllow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn},
			accessStatement{Effect: "Deny", Action: actDeleteUserPolicy, Resource: targetArn},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantAllowed(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ActionMatchingVariants covers exact, wildcard, array, and
// case-insensitive Action matching, all against the same target resource so
// only the Action dimension varies row to row.
func IAMAccessControl_ActionMatchingVariants(s *S3Conf) error {
	testName := "IAMAccessControl_ActionMatchingVariants"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		cases := []struct {
			name        string
			action      any
			wantAllowed bool
		}{
			{"exact action match", "iam:GetUser", true},
			{"service wildcard iam:*", "iam:*", true},
			{"operation prefix wildcard iam:Get*", "iam:Get*", true},
			{"suffix wildcard iam:*User", "iam:*User", true},
			{"single-char ? wildcard", "iam:GetUse?", true},
			{"action present in an array", []string{"iam:ListUsers", "iam:GetUser"}, true},
			{"case-insensitive policy action", "IAM:GETUSER", true},
			{"nonmatching action", "iam:PutUserPolicy", false},
			{"nonmatching prefix wildcard", "iam:List*", false},
		}
		for _, tc := range cases {
			if err := func() error {
				policy := policyDoc(accessStatement{Effect: "Allow", Action: tc.action, Resource: targetArn})
				caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
				if err != nil {
					return err
				}
				defer cleanupCaller()

				_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
				if tc.wantAllowed {
					return wantAllowed(caller.arn, actGetUser, targetArn, err)
				}
				return wantDenied(caller.arn, actGetUser, targetArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_ActionAllowOneDenyAnotherByOmission verifies a policy
// granting exactly one action grants only that action — a sibling action
// against the very same resource is still denied.
func IAMAccessControl_ActionAllowOneDenyAnotherByOmission(s *S3Conf) error {
	testName := "IAMAccessControl_ActionAllowOneDenyAnotherByOmission"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, targetArn, err)
		}
		_, err = listIAMUserPolicies(caller.client, &iam.ListUserPoliciesInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actListUserPolicies, targetArn, err)
	})
}

// IAMAccessControl_ActionExplicitDenySubsetOfWildcardAllow verifies an
// explicit Deny for one specific action carves it out of an otherwise
// all-encompassing wildcard Allow, without affecting any other action the
// wildcard still covers.
func IAMAccessControl_ActionExplicitDenySubsetOfWildcardAllow(s *S3Conf) error {
	testName := "IAMAccessControl_ActionExplicitDenySubsetOfWildcardAllow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: "iam:*", Resource: targetArn},
			accessStatement{Effect: "Deny", Action: actDeleteUserPolicy, Resource: targetArn},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, targetArn, err)
		}
		_, err = deleteIAMUserPolicyRaw(caller.client, &iam.DeleteUserPolicyInput{UserName: aws.String(targetName), PolicyName: aws.String("irrelevant")})
		return wantDenied(caller.arn, actDeleteUserPolicy, targetArn, err)
	})
}

// IAMAccessControl_NotActionAllowGrantsEverythingExceptExcluded verifies an
// Allow+NotAction statement grants every action *except* the ones listed —
// the excluded action is denied, a nonexcluded one is allowed.
func IAMAccessControl_NotActionAllowGrantsEverythingExceptExcluded(s *S3Conf) error {
	testName := "IAMAccessControl_NotActionAllowGrantsEverythingExceptExcluded"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(accessStatement{Effect: "Allow", NotAction: []string{actListUsers, actDeleteUserPolicy}, Resource: "*"})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		// GetUser is not in the NotAction list, so it's covered by the Allow.
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, targetArn, err)
		}
		// ListUsers is excluded via NotAction, so the statement doesn't cover it.
		_, err = listIAMUsers(caller.client, &iam.ListUsersInput{})
		return wantDenied(caller.arn, actListUsers, "*", err)
	})
}

// IAMAccessControl_NotActionDenyBlocksEverythingExceptExcluded verifies the
// interaction between an Action-based Allow and a NotAction-based Deny: a
// broad Allow grants everything, but a Deny+NotAction statement denies every
// action *except* the one named — net effect, only that one action remains
// allowed.
func IAMAccessControl_NotActionDenyBlocksEverythingExceptExcluded(s *S3Conf) error {
	testName := "IAMAccessControl_NotActionDenyBlocksEverythingExceptExcluded"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: "iam:*", Resource: "*"},
			accessStatement{Effect: "Deny", NotAction: actGetUser, Resource: "*"},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		// GetUser is excluded from the Deny's NotAction coverage, so only the
		// Allow applies to it.
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, targetArn, err)
		}
		// Every other action is covered by the Deny (it's not GetUser).
		_, err = listIAMUsers(caller.client, &iam.ListUsersInput{})
		return wantDenied(caller.arn, actListUsers, "*", err)
	})
}

// IAMAccessControl_ResourceMatchingVariants covers exact, wildcard, and
// array Resource matching for both a user and a role target.
func IAMAccessControl_ResourceMatchingVariants(s *S3Conf) error {
	testName := "IAMAccessControl_ResourceMatchingVariants"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetUserName, targetUserArn, cleanupUser, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupUser()
		targetRoleName, targetRoleArn, cleanupRole, err := newTargetRole(root)
		if err != nil {
			return err
		}
		defer cleanupRole()
		pathUserName, pathUserArn, cleanupPathUser, err := newTargetUserWithPath(root, "/ac-team/")
		if err != nil {
			return err
		}
		defer cleanupPathUser()
		otherName, _, cleanupOther, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupOther()

		run := func(name, action, resourcePattern, wantResource string, call func(client *iam.Client) error) error {
			policy := policyDoc(accessStatement{Effect: "Allow", Action: action, Resource: resourcePattern})
			caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			defer cleanupCaller()
			if err := wantAllowed(caller.arn, action, wantResource, call(caller.client)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		}

		if err := run("exact user ARN", actGetUser, targetUserArn, targetUserArn, func(c *iam.Client) error {
			_, err := getIAMUser(c, &iam.GetUserInput{UserName: aws.String(targetUserName)})
			return err
		}); err != nil {
			return err
		}
		if err := run("exact role ARN", actGetRole, targetRoleArn, targetRoleArn, func(c *iam.Client) error {
			_, err := getIAMRole(c, targetRoleName)
			return err
		}); err != nil {
			return err
		}
		if err := run("wildcard resource ARN", actGetUser, "*", targetUserArn, func(c *iam.Client) error {
			_, err := getIAMUser(c, &iam.GetUserInput{UserName: aws.String(targetUserName)})
			return err
		}); err != nil {
			return err
		}
		if err := run("resource path wildcard", actGetUser, "arn:aws:iam::"+testAccountID+":user/ac-team/*", pathUserArn, func(c *iam.Client) error {
			_, err := getIAMUser(c, &iam.GetUserInput{UserName: aws.String(pathUserName)})
			return err
		}); err != nil {
			return err
		}

		// Multiple resources in an array: both named ARNs are granted, a third
		// (equally valid) resource is not.
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: []string{targetUserArn, pathUserArn}})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return fmt.Errorf("resource array: %w", err)
		}
		defer cleanupCaller()
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetUserName)}); wantAllowed(caller.arn, actGetUser, targetUserArn, err) != nil {
			return fmt.Errorf("resource array, first entry: %w", wantAllowed(caller.arn, actGetUser, targetUserArn, err))
		}
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(pathUserName)}); wantAllowed(caller.arn, actGetUser, pathUserArn, err) != nil {
			return fmt.Errorf("resource array, second entry: %w", wantAllowed(caller.arn, actGetUser, pathUserArn, err))
		}
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(otherName)}); wantDenied(caller.arn, actGetUser, "(not in array)", err) != nil {
			return fmt.Errorf("resource array, nonmatching entry: %w", wantDenied(caller.arn, actGetUser, "(not in array)", err))
		}

		// Nonmatching resource: exact grant to one user does not cover another.
		exactPolicy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetUserArn})
		exactCaller, cleanupExact, err := newAccessControlCaller(root, s, "", map[string]string{"p": exactPolicy})
		if err != nil {
			return fmt.Errorf("nonmatching resource denied: %w", err)
		}
		defer cleanupExact()
		_, err = getIAMUser(exactCaller.client, &iam.GetUserInput{UserName: aws.String(otherName)})
		if err := wantDenied(exactCaller.arn, actGetUser, targetUserArn, err); err != nil {
			return fmt.Errorf("nonmatching resource denied: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_ResourceOneAllowedOneDeniedSameAction verifies a
// resource-scoped Allow grants the same action against its named resource
// but denies it against an equally-valid, unrelated resource.
func IAMAccessControl_ResourceOneAllowedOneDeniedSameAction(s *S3Conf) error {
	testName := "IAMAccessControl_ResourceOneAllowedOneDeniedSameAction"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		allowedName, allowedArn, cleanupAllowed, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupAllowed()
		deniedName, deniedArn, cleanupDenied, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupDenied()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: allowedArn})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(allowedName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, allowedArn, err)
		}
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(deniedName)})
		return wantDenied(caller.arn, actGetUser, deniedArn, err)
	})
}

// IAMAccessControl_ResourceWildcardRequiredForListAction verifies a
// List-type action (whose only valid resource-level scope is "*", per
// resourceForAction's classification) is denied by a resource-scoped grant
// naming a specific entity, and allowed once the grant uses "*".
func IAMAccessControl_ResourceWildcardRequiredForListAction(s *S3Conf) error {
	testName := "IAMAccessControl_ResourceWildcardRequiredForListAction"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		_, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		scoped := policyDoc(accessStatement{Effect: "Allow", Action: actListUsers, Resource: targetArn})
		scopedCaller, cleanupScoped, err := newAccessControlCaller(root, s, "", map[string]string{"p": scoped})
		if err != nil {
			return err
		}
		defer cleanupScoped()
		_, err = listIAMUsers(scopedCaller.client, &iam.ListUsersInput{})
		if err := wantDenied(scopedCaller.arn, actListUsers, "*", err); err != nil {
			return fmt.Errorf("resource-scoped grant: %w", err)
		}

		wildcard := policyDoc(accessStatement{Effect: "Allow", Action: actListUsers, Resource: "*"})
		wildcardCaller, cleanupWildcard, err := newAccessControlCaller(root, s, "", map[string]string{"p": wildcard})
		if err != nil {
			return err
		}
		defer cleanupWildcard()
		_, err = listIAMUsers(wildcardCaller.client, &iam.ListUsersInput{})
		if err := wantAllowed(wildcardCaller.arn, actListUsers, "*", err); err != nil {
			return fmt.Errorf("wildcard grant: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_ResourceExplicitDenyOverridesBroaderAllow verifies a
// Deny scoped to one specific resource carves it out of a broader
// Resource:"*" Allow, without affecting any other resource the Allow still
// covers.
func IAMAccessControl_ResourceExplicitDenyOverridesBroaderAllow(s *S3Conf) error {
	testName := "IAMAccessControl_ResourceExplicitDenyOverridesBroaderAllow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		blockedName, blockedArn, cleanupBlocked, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupBlocked()
		otherName, otherArn, cleanupOther, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupOther()

		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: actGetUser, Resource: "*"},
			accessStatement{Effect: "Deny", Action: actGetUser, Resource: blockedArn},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(otherName)}); err != nil {
			return wantAllowed(caller.arn, actGetUser, otherArn, err)
		}
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(blockedName)})
		return wantDenied(caller.arn, actGetUser, blockedArn, err)
	})
}

// IAMAccessControl_NotResourceExcludesTarget verifies both directions of
// NotResource: an Allow+NotResource statement applies to every resource
// *except* the excluded one, while a Deny+NotResource statement (layered
// over a broader baseline Allow) denies every resource *except* the
// excluded one — the excluded resource's fate inverts between the two.
func IAMAccessControl_NotResourceExcludesTarget(s *S3Conf) error {
	testName := "IAMAccessControl_NotResourceExcludesTarget"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user1Name, user1Arn, cleanup1, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanup1()
		user2Name, user2Arn, cleanup2, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanup2()

		// Allow + NotResource[user2]: user1 allowed, user2 (excluded) denied.
		allowPolicy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, NotResource: user2Arn})
		allowCaller, cleanupAllow, err := newAccessControlCaller(root, s, "", map[string]string{"p": allowPolicy})
		if err != nil {
			return err
		}
		defer cleanupAllow()
		if _, err := getIAMUser(allowCaller.client, &iam.GetUserInput{UserName: aws.String(user1Name)}); wantAllowed(allowCaller.arn, actGetUser, user1Arn, err) != nil {
			return fmt.Errorf("Allow+NotResource, non-excluded: %w", wantAllowed(allowCaller.arn, actGetUser, user1Arn, err))
		}
		if _, err := getIAMUser(allowCaller.client, &iam.GetUserInput{UserName: aws.String(user2Name)}); wantDenied(allowCaller.arn, actGetUser, user2Arn, err) != nil {
			return fmt.Errorf("Allow+NotResource, excluded: %w", wantDenied(allowCaller.arn, actGetUser, user2Arn, err))
		}

		// Baseline Allow(*) + Deny+NotResource[user2]: user1 denied (Deny
		// covers it, since it's not the excluded one), user2 allowed (Deny
		// doesn't cover the excluded resource, so only the baseline Allow
		// applies to it).
		denyPolicy := policyDoc(
			accessStatement{Effect: "Allow", Action: actGetUser, Resource: "*"},
			accessStatement{Effect: "Deny", Action: actGetUser, NotResource: user2Arn},
		)
		denyCaller, cleanupDeny, err := newAccessControlCaller(root, s, "", map[string]string{"p": denyPolicy})
		if err != nil {
			return err
		}
		defer cleanupDeny()
		if _, err := getIAMUser(denyCaller.client, &iam.GetUserInput{UserName: aws.String(user1Name)}); wantDenied(denyCaller.arn, actGetUser, user1Arn, err) != nil {
			return fmt.Errorf("Deny+NotResource, non-excluded: %w", wantDenied(denyCaller.arn, actGetUser, user1Arn, err))
		}
		if _, err := getIAMUser(denyCaller.client, &iam.GetUserInput{UserName: aws.String(user2Name)}); wantAllowed(denyCaller.arn, actGetUser, user2Arn, err) != nil {
			return fmt.Errorf("Deny+NotResource, excluded: %w", wantAllowed(denyCaller.arn, actGetUser, user2Arn, err))
		}
		return nil
	})
}

// IAMAccessControl_NotResourceMultipleExcludedResources verifies a
// NotResource array excludes every listed resource, not just the first.
func IAMAccessControl_NotResourceMultipleExcludedResources(s *S3Conf) error {
	testName := "IAMAccessControl_NotResourceMultipleExcludedResources"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		includedName, includedArn, cleanupIncluded, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupIncluded()
		excluded1Name, excluded1Arn, cleanupExcluded1, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupExcluded1()
		excluded2Name, excluded2Arn, cleanupExcluded2, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupExcluded2()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, NotResource: []string{excluded1Arn, excluded2Arn}})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(includedName)}); wantAllowed(caller.arn, actGetUser, includedArn, err) != nil {
			return fmt.Errorf("non-excluded resource: %w", wantAllowed(caller.arn, actGetUser, includedArn, err))
		}
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(excluded1Name)}); wantDenied(caller.arn, actGetUser, excluded1Arn, err) != nil {
			return fmt.Errorf("first excluded resource: %w", wantDenied(caller.arn, actGetUser, excluded1Arn, err))
		}
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(excluded2Name)})
		if err := wantDenied(caller.arn, actGetUser, excluded2Arn, err); err != nil {
			return fmt.Errorf("second excluded resource: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_NotResourceWildcardExclusion verifies NotResource
// supports the same wildcard glob Resource does: excluding a whole
// path-prefix pattern excludes every resource under it, not just one exact
// ARN.
func IAMAccessControl_NotResourceWildcardExclusion(s *S3Conf) error {
	testName := "IAMAccessControl_NotResourceWildcardExclusion"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		excludedName, excludedArn, cleanupExcluded, err := newTargetUserWithPath(root, "/ac-excluded/")
		if err != nil {
			return err
		}
		defer cleanupExcluded()
		includedName, includedArn, cleanupIncluded, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupIncluded()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, NotResource: "arn:aws:iam::" + testAccountID + ":user/ac-excluded/*"})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(includedName)}); wantAllowed(caller.arn, actGetUser, includedArn, err) != nil {
			return fmt.Errorf("outside excluded path: %w", wantAllowed(caller.arn, actGetUser, includedArn, err))
		}
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(excludedName)})
		if err := wantDenied(caller.arn, actGetUser, excludedArn, err); err != nil {
			return fmt.Errorf("inside excluded path: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_ConditionStringOperators covers the full String
// condition-operator family against aws:username — a key this suite fully
// controls on both sides (the caller's actual username, and the policy's
// expected value), giving every row a deterministic outcome.
func IAMAccessControl_ConditionStringOperators(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionStringOperators"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		cases := []struct {
			name        string
			callerName  string
			condition   func(callerName string) json.RawMessage
			wantAllowed bool
		}{
			{"StringEquals exact match", "ac-str-alice-" + genRandString(6),
				func(c string) json.RawMessage { return cond("StringEquals", "aws:username", c) }, true},
			{"StringEquals nonmatch", "ac-str-bob-" + genRandString(6),
				func(string) json.RawMessage { return cond("StringEquals", "aws:username", "someone-else") }, false},
			{"StringNotEquals matches when different", "ac-str-carol-" + genRandString(6),
				func(string) json.RawMessage { return cond("StringNotEquals", "aws:username", "someone-else") }, true},
			{"StringNotEquals denies when equal", "ac-str-dave-" + genRandString(6),
				func(c string) json.RawMessage { return cond("StringNotEquals", "aws:username", c) }, false},
			{"StringEqualsIgnoreCase matches different case", "ac-str-erin-" + genRandString(6),
				func(c string) json.RawMessage { return cond("StringEqualsIgnoreCase", "aws:username", upperASCII(c)) }, true},
			{"StringNotEqualsIgnoreCase denies matching case-insensitively", "ac-str-frank-" + genRandString(6),
				func(c string) json.RawMessage {
					return cond("StringNotEqualsIgnoreCase", "aws:username", upperASCII(c))
				}, false},
			{"StringLike prefix wildcard", "ac-str-wild-prefix-" + genRandString(6),
				func(string) json.RawMessage { return cond("StringLike", "aws:username", "ac-str-wild-prefix-*") }, true},
			{"StringLike suffix wildcard", "ac-str-wild-suffix-suf",
				func(string) json.RawMessage { return cond("StringLike", "aws:username", "*-suf") }, true},
			{"StringLike middle wildcard", "ac-str-wild-mid-zzz-tail",
				func(string) json.RawMessage { return cond("StringLike", "aws:username", "ac-str-wild-mid-*-tail") }, true},
			{"StringLike ? wildcard", "ac-str-wld-abc",
				func(string) json.RawMessage { return cond("StringLike", "aws:username", "ac-str-wld-a?c") }, true},
			{"StringLike nonmatch", "ac-str-nomatch-" + genRandString(6),
				func(string) json.RawMessage { return cond("StringLike", "aws:username", "totally-different-*") }, false},
			{"StringNotLike denies matching wildcard", "ac-str-notlike-" + genRandString(6),
				func(string) json.RawMessage { return cond("StringNotLike", "aws:username", "ac-str-notlike-*") }, false},
			{"StringNotLike allows nonmatching wildcard", "ac-str-abc-" + genRandString(6),
				func(string) json.RawMessage { return cond("StringNotLike", "aws:username", "zzz-*") }, true},
		}
		for _, tc := range cases {
			if err := func() error {
				policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: tc.condition(tc.callerName)})
				caller, cleanupCaller, err := newAccessControlCaller(root, s, tc.callerName, map[string]string{"p": policy})
				if err != nil {
					return err
				}
				defer cleanupCaller()

				_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
				if tc.wantAllowed {
					return wantAllowed(caller.arn, actGetUser, targetArn, err)
				}
				return wantDenied(caller.arn, actGetUser, targetArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_ConditionStringMultipleExpectedValuesOR verifies a
// StringEquals condition with an array of expected values matches if the
// actual value equals *any* of them.
func IAMAccessControl_ConditionStringMultipleExpectedValuesOR(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionStringMultipleExpectedValuesOR"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		callerName := "ac-str-or-" + genRandString(8)
		condition := cond("StringEquals", "aws:username", []string{"nobody-1", callerName, "nobody-2"})
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: condition})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, callerName, map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantAllowed(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ConditionArnOperators covers the ArnEquals/ArnLike/
// ArnNotEquals/ArnNotLike family against aws:PrincipalArn — a real,
// fully-known ARN this suite controls exactly (the caller's own Arn).
func IAMAccessControl_ConditionArnOperators(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionArnOperators"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		callerName := "ac-arn-" + genRandString(8)
		callerArnPattern := "arn:aws:iam::" + testAccountID + ":user/" + callerName
		otherArn := "arn:aws:iam::" + testAccountID + ":user/someone-else"

		cases := []struct {
			name        string
			condition   json.RawMessage
			wantAllowed bool
		}{
			{"ArnEquals exact match", cond("ArnEquals", "aws:PrincipalArn", callerArnPattern), true},
			{"ArnEquals nonmatch", cond("ArnEquals", "aws:PrincipalArn", otherArn), false},
			{"ArnLike wildcard match", cond("ArnLike", "aws:PrincipalArn", "arn:aws:iam::"+testAccountID+":user/ac-arn-*"), true},
			{"ArnNotEquals matches when different", cond("ArnNotEquals", "aws:PrincipalArn", otherArn), true},
			{"ArnNotEquals denies when equal", cond("ArnNotEquals", "aws:PrincipalArn", callerArnPattern), false},
			{"ArnNotLike denies matching wildcard", cond("ArnNotLike", "aws:PrincipalArn", "arn:aws:iam::"+testAccountID+":user/ac-arn-*"), false},
			{"array of expected ARNs matches any", cond("ArnEquals", "aws:PrincipalArn", []string{otherArn, callerArnPattern}), true},
		}
		for _, tc := range cases {
			if err := func() error {
				policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: tc.condition})
				caller, cleanupCaller, err := newAccessControlCaller(root, s, callerName, map[string]string{"p": policy})
				if err != nil {
					return err
				}
				defer cleanupCaller()

				_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
				if tc.wantAllowed {
					return wantAllowed(caller.arn, actGetUser, targetArn, err)
				}
				return wantDenied(caller.arn, actGetUser, targetArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_ConditionIpAddressRealSourceIp covers IpAddress/
// NotIpAddress against the *real* aws:SourceIp the gateway observes for this
// test process's own connection (see callerSourceIP), proving the
// source-IP condition context is actually wired end to end — not just that
// the operator's CIDR logic works in isolation (see
// IAMAccessControl_ConditionIpAddressOperators for the broader operator
// coverage via a fully test-controlled claim value).
func IAMAccessControl_ConditionIpAddressRealSourceIp(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionIpAddressRealSourceIp"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		sourceIP, err := callerSourceIP(s)
		if err != nil {
			return err
		}
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		cases := []struct {
			name        string
			condition   json.RawMessage
			wantAllowed bool
		}{
			{"exact IP match", cond("IpAddress", "aws:SourceIp", sourceIP), true},
			{"broad CIDR match", cond("IpAddress", "aws:SourceIp", "127.0.0.0/8"), true},
			{"CIDR outside range denied", cond("IpAddress", "aws:SourceIp", "10.0.0.0/8"), false},
			{"NotIpAddress denies matching range", cond("NotIpAddress", "aws:SourceIp", "127.0.0.0/8"), false},
			{"NotIpAddress allows non-matching range", cond("NotIpAddress", "aws:SourceIp", "10.0.0.0/8"), true},
			{"multiple CIDRs, one matches (OR)", cond("IpAddress", "aws:SourceIp", []string{"10.0.0.0/8", "127.0.0.0/8"}), true},
		}
		for _, tc := range cases {
			if err := func() error {
				policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: tc.condition})
				caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
				if err != nil {
					return err
				}
				defer cleanupCaller()

				_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
				if tc.wantAllowed {
					return wantAllowed(caller.arn, actGetUser, targetArn, err)
				}
				return wantDenied(caller.arn, actGetUser, targetArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_ConditionIpAddressExplicitDenyOverridesBroaderAllow
// verifies a Deny scoped to one IP range carves it out of a broader Allow,
// using a range guaranteed to contain this test process's real source IP.
func IAMAccessControl_ConditionIpAddressExplicitDenyOverridesBroaderAllow(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionIpAddressExplicitDenyOverridesBroaderAllow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		if _, err := callerSourceIP(s); err != nil {
			return err
		}
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn},
			accessStatement{Effect: "Deny", Action: actGetUser, Resource: targetArn, Condition: cond("IpAddress", "aws:SourceIp", "127.0.0.0/8")},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ConditionMultipleContextKeysANDed verifies two different
// condition keys within the same Condition block are ANDed: both
// aws:username and aws:PrincipalTag/department must match for the statement
// to apply.
func IAMAccessControl_ConditionMultipleContextKeysANDed(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionMultipleContextKeysANDed"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		callerName := "ac-and-" + genRandString(8)
		condition := condAll(map[string]map[string]any{
			"StringEquals": {"aws:username": callerName, "aws:PrincipalTag/department": "eng"},
		})
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: condition})

		// Both keys match.
		matching, cleanupMatching, err := newAccessControlCallerTagged(root, s, callerName, map[string]string{"p": policy}, map[string]string{"department": "eng"})
		if err != nil {
			return err
		}
		defer cleanupMatching()
		if _, err := getIAMUser(matching.client, &iam.GetUserInput{UserName: aws.String(targetName)}); wantAllowed(matching.arn, actGetUser, targetArn, err) != nil {
			return fmt.Errorf("both keys match: %w", wantAllowed(matching.arn, actGetUser, targetArn, err))
		}

		// Username matches but the tag does not: one failed key voids the
		// whole statement (AND, not OR, across keys).
		wrongTagName := "ac-and-" + genRandString(8)
		wrongTagCondition := condAll(map[string]map[string]any{
			"StringEquals": {"aws:username": wrongTagName, "aws:PrincipalTag/department": "eng"},
		})
		wrongTagPolicy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: wrongTagCondition})
		mismatched, cleanupMismatched, err := newAccessControlCallerTagged(root, s, wrongTagName, map[string]string{"p": wrongTagPolicy}, map[string]string{"department": "sales"})
		if err != nil {
			return err
		}
		defer cleanupMismatched()
		_, err = getIAMUser(mismatched.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		if err := wantDenied(mismatched.arn, actGetUser, targetArn, err); err != nil {
			return fmt.Errorf("one key mismatched: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_ConditionAllowMatchesDenyConditionDoesNotApply verifies
// that when an Allow's condition matches but a separate Deny statement's own
// condition does *not* match, the Deny simply doesn't apply and the Allow
// wins — a failing condition on a Deny is not the same as the Deny being
// absent, but it does mean that particular Deny never fires.
func IAMAccessControl_ConditionAllowMatchesDenyConditionDoesNotApply(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionAllowMatchesDenyConditionDoesNotApply"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		callerName := "ac-mixed-" + genRandString(8)
		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn},
			accessStatement{Effect: "Deny", Action: actGetUser, Resource: targetArn, Condition: cond("StringEquals", "aws:username", "not-"+callerName)},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, callerName, map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantAllowed(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ConditionAllowAndDenyBothMatchDenyWins verifies that when
// both an Allow's and a Deny's conditions match the same request, the Deny
// still wins — condition-matching does not change explicit Deny precedence.
func IAMAccessControl_ConditionAllowAndDenyBothMatchDenyWins(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionAllowAndDenyBothMatchDenyWins"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		callerName := "ac-bothmatch-" + genRandString(8)
		policy := policyDoc(
			accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: cond("StringEquals", "aws:username", callerName)},
			accessStatement{Effect: "Deny", Action: actGetUser, Resource: targetArn, Condition: cond("StringEquals", "aws:username", callerName)},
		)
		caller, cleanupCaller, err := newAccessControlCaller(root, s, callerName, map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ConditionOneFailedConditionVoidsStatement verifies a
// statement combining two condition keys (ANDed) does not apply if either
// one fails to match — demonstrated here via aws:username (matching) AND
// aws:SourceIp (deliberately scoped to a range that excludes this test
// process's real source IP).
func IAMAccessControl_ConditionOneFailedConditionVoidsStatement(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionOneFailedConditionVoidsStatement"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		if _, err := callerSourceIP(s); err != nil {
			return err
		}
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		callerName := "ac-voided-" + genRandString(8)
		condition := condAll(map[string]map[string]any{
			"StringEquals": {"aws:username": callerName},
			"IpAddress":    {"aws:SourceIp": "10.0.0.0/8"}, // deliberately excludes the real (127.0.0.0/8) source
		})
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: condition})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, callerName, map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantDenied(caller.arn, actGetUser, targetArn, err)
	})
}

// IAMAccessControl_ConditionNullPrincipalTag covers the Null operator
// against aws:PrincipalTag/<key>, a key that's genuinely absent from
// request context for an untagged caller and present for a tagged one —
// exercising Null's "key does not exist"/"key exists" semantics against a
// real, request-driven context key rather than a synthetic one.
func IAMAccessControl_ConditionNullPrincipalTag(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionNullPrincipalTag"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		run := func(name string, tags map[string]string, nullValue string, wantAllow bool) error {
			condition := cond("Null", "aws:PrincipalTag/department", nullValue)
			policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: condition})
			caller, cleanupCaller, err := newAccessControlCallerTagged(root, s, "", map[string]string{"p": policy}, tags)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			defer cleanupCaller()

			_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
			if wantAllow {
				err = wantAllowed(caller.arn, actGetUser, targetArn, err)
			} else {
				err = wantDenied(caller.arn, actGetUser, targetArn, err)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		}

		if err := run("Null true matches absent tag", nil, "true", true); err != nil {
			return err
		}
		if err := run("Null true denies present tag", map[string]string{"department": "eng"}, "true", false); err != nil {
			return err
		}
		if err := run("Null false matches present tag", map[string]string{"department": "eng"}, "false", true); err != nil {
			return err
		}
		return run("Null false denies absent tag", nil, "false", false)
	})
}

// IAMAccessControl_ConditionIfExistsPrincipalTag covers a StringEqualsIfExists
// condition against aws:PrincipalTag/<key>: absent (vacuously allowed),
// present and matching (allowed), present and mismatched (denied).
func IAMAccessControl_ConditionIfExistsPrincipalTag(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionIfExistsPrincipalTag"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		condition := cond("StringEqualsIfExists", "aws:PrincipalTag/department", "eng")
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: condition})

		run := func(name string, tags map[string]string, wantAllow bool) error {
			caller, cleanupCaller, err := newAccessControlCallerTagged(root, s, "", map[string]string{"p": policy}, tags)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			defer cleanupCaller()

			_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
			if wantAllow {
				err = wantAllowed(caller.arn, actGetUser, targetArn, err)
			} else {
				err = wantDenied(caller.arn, actGetUser, targetArn, err)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		}

		if err := run("absent tag is vacuously allowed", nil, true); err != nil {
			return err
		}
		if err := run("present matching tag allowed", map[string]string{"department": "eng"}, true); err != nil {
			return err
		}
		return run("present mismatched tag denied", map[string]string{"department": "sales"}, false)
	})
}

// IAMAccessControl_ConditionResourceTagOnTarget covers iam:ResourceTag/
// aws:ResourceTag: a Condition scoping the *target* resource's own tag,
// proving resourceForAction's tag resolution is wired into Condition
// evaluation, not just the caller's own tags.
func IAMAccessControl_ConditionResourceTagOnTarget(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionResourceTagOnTarget"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		taggedName, taggedArn, cleanupTagged, err := newTargetUserTagged(root, map[string]string{"team": "payments"})
		if err != nil {
			return err
		}
		defer cleanupTagged()
		untaggedName, untaggedArn, cleanupUntagged, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupUntagged()

		condition := cond("StringEquals", "iam:ResourceTag/team", "payments")
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: "*", Condition: condition})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(taggedName)}); wantAllowed(caller.arn, actGetUser, taggedArn, err) != nil {
			return fmt.Errorf("matching resource tag: %w", wantAllowed(caller.arn, actGetUser, taggedArn, err))
		}
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(untaggedName)})
		if err := wantDenied(caller.arn, actGetUser, untaggedArn, err); err != nil {
			return fmt.Errorf("untagged resource: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_ConditionRequestTagOnCreateUser covers aws:RequestTag/
// aws:TagKeys: a Condition scoping the Tags parameter of a CreateUser
// request itself, proving request-scoped (not just principal- or
// resource-scoped) context is evaluated.
func IAMAccessControl_ConditionRequestTagOnCreateUser(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionRequestTagOnCreateUser"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		condition := cond("StringEquals", "aws:RequestTag/team", "payments")
		policy := policyDoc(accessStatement{
			Effect: "Allow", Action: actCreateUser,
			Resource:  "arn:aws:iam::" + testAccountID + ":user/ac-created-*",
			Condition: condition,
		})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		allowedName := "ac-created-" + genRandString(10)
		out, err := createIAMUser(caller.client, &iam.CreateUserInput{
			UserName: aws.String(allowedName), Tags: []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("payments")}},
		})
		if err := wantAllowed(caller.arn, actCreateUser, allowedName, err); err != nil {
			return fmt.Errorf("matching request tag: %w", err)
		}
		if out != nil {
			defer deleteIAMUser(root, allowedName)
		}

		deniedName := "ac-created-" + genRandString(10)
		_, err = createIAMUser(caller.client, &iam.CreateUserInput{
			UserName: aws.String(deniedName), Tags: []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("other")}},
		})
		return wantDenied(caller.arn, actCreateUser, deniedName, err)
	})
}

// IAMAccessControl_ConditionCurrentTimeBroadWindow covers Numeric/Date
// operators against the server's own request-time keys (aws:EpochTime,
// aws:CurrentTime) — since "now" can't be injected or fixed by the test,
// this uses deliberately broad, never-flaky bounds (year 2001 through year
// 2100) rather than tight boundaries; see
// IAMAccessControl_ConditionNumericOperators/ConditionDateOperators for
// precise boundary coverage against a fully test-controlled claim value.
func IAMAccessControl_ConditionCurrentTimeBroadWindow(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionCurrentTimeBroadWindow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()

		condition := condAll(map[string]map[string]any{
			"NumericGreaterThan": {"aws:EpochTime": "1000000000"}, // ~2001
			"NumericLessThan":    {"aws:EpochTime": "4102444800"}, // ~2100
			"DateGreaterThan":    {"aws:CurrentTime": "2001-01-01T00:00:00Z"},
			"DateLessThan":       {"aws:CurrentTime": "2100-01-01T00:00:00Z"},
		})
		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: targetArn, Condition: condition})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		return wantAllowed(caller.arn, actGetUser, targetArn, err)
	})
}

// upperASCII uppercases a plain ASCII string (test fixture names are always
// ASCII), avoiding a dependency on strings.ToUpper's full-Unicode behavior
// for what's fundamentally a fixed test value.
func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// IAMAccessControl_ConditionNumericOperators covers the full Numeric
// condition-operator family, using a custom "level" claim this suite fully
// controls, around a fixed boundary value of 5.
func IAMAccessControl_ConditionNumericOperators(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionNumericOperators"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		numCond := func(operator string, value any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond(operator, host+":level", value) }
		}
		cases := []federatedConditionCase{
			{"NumericEquals at boundary allowed", map[string]any{"level": 5}, numCond("NumericEquals", 5), true},
			{"NumericEquals off boundary denied", map[string]any{"level": 5}, numCond("NumericEquals", 6), false},
			{"NumericNotEquals allowed when different", map[string]any{"level": 5}, numCond("NumericNotEquals", 6), true},
			{"NumericNotEquals denied when equal", map[string]any{"level": 5}, numCond("NumericNotEquals", 5), false},
			{"NumericLessThan below boundary allowed", map[string]any{"level": 5}, numCond("NumericLessThan", 6), true},
			{"NumericLessThan at boundary denied (exclusive)", map[string]any{"level": 5}, numCond("NumericLessThan", 5), false},
			{"NumericLessThanEquals at boundary allowed (inclusive)", map[string]any{"level": 5}, numCond("NumericLessThanEquals", 5), true},
			{"NumericLessThanEquals above boundary denied", map[string]any{"level": 6}, numCond("NumericLessThanEquals", 5), false},
			{"NumericGreaterThan above boundary allowed", map[string]any{"level": 6}, numCond("NumericGreaterThan", 5), true},
			{"NumericGreaterThan at boundary denied (exclusive)", map[string]any{"level": 5}, numCond("NumericGreaterThan", 5), false},
			{"NumericGreaterThanEquals at boundary allowed (inclusive)", map[string]any{"level": 5}, numCond("NumericGreaterThanEquals", 5), true},
			{"NumericGreaterThanEquals below boundary denied", map[string]any{"level": 4}, numCond("NumericGreaterThanEquals", 5), false},
			{"multiple expected values matches any (OR)", map[string]any{"level": 5}, numCond("NumericEquals", []any{5, 100}), true},
			{"missing context key denies", map[string]any{}, numCond("NumericEquals", 5), false},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionDateOperators covers the full Date
// condition-operator family, using a custom "joined" claim around a fixed
// boundary of 2024-06-15T00:00:00Z (epoch 1718409600) — both RFC3339 and
// epoch-seconds forms are exercised since evaluateCondition accepts either
// on either side.
func IAMAccessControl_ConditionDateOperators(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionDateOperators"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		const boundary = "2024-06-15T00:00:00Z"
		const before = "2024-01-01T00:00:00Z"
		const after = "2024-12-01T00:00:00Z"
		dateCond := func(operator string, value any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond(operator, host+":joined", value) }
		}
		cases := []federatedConditionCase{
			{"DateEquals exact match", map[string]any{"joined": boundary}, dateCond("DateEquals", boundary), true},
			{"DateEquals nonmatch", map[string]any{"joined": boundary}, dateCond("DateEquals", before), false},
			{"DateEquals matches across epoch-vs-RFC3339 forms", map[string]any{"joined": "1718409600"}, dateCond("DateEquals", boundary), true},
			{"DateNotEquals allowed when different", map[string]any{"joined": boundary}, dateCond("DateNotEquals", before), true},
			{"DateNotEquals denied when equal", map[string]any{"joined": boundary}, dateCond("DateNotEquals", boundary), false},
			{"DateLessThan before boundary allowed", map[string]any{"joined": before}, dateCond("DateLessThan", boundary), true},
			{"DateLessThan at boundary denied (exclusive)", map[string]any{"joined": boundary}, dateCond("DateLessThan", boundary), false},
			{"DateLessThanEquals at boundary allowed (inclusive)", map[string]any{"joined": boundary}, dateCond("DateLessThanEquals", boundary), true},
			{"DateLessThanEquals after boundary denied", map[string]any{"joined": after}, dateCond("DateLessThanEquals", boundary), false},
			{"DateGreaterThan after boundary allowed", map[string]any{"joined": after}, dateCond("DateGreaterThan", boundary), true},
			{"DateGreaterThan at boundary denied (exclusive)", map[string]any{"joined": boundary}, dateCond("DateGreaterThan", boundary), false},
			{"DateGreaterThanEquals at boundary allowed (inclusive)", map[string]any{"joined": boundary}, dateCond("DateGreaterThanEquals", boundary), true},
			{"DateGreaterThanEquals before boundary denied", map[string]any{"joined": before}, dateCond("DateGreaterThanEquals", boundary), false},
			{"multiple expected dates matches any (OR)", map[string]any{"joined": boundary}, dateCond("DateEquals", []any{before, boundary}), true},
			{"missing date context denies", map[string]any{}, dateCond("DateGreaterThan", boundary), false},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionBoolOperator covers Bool: true/false claim
// values, a string-typed "true"/"false" claim (still matched, since both
// sides parse via strconv.ParseBool), and a missing key.
func IAMAccessControl_ConditionBoolOperator(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionBoolOperator"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		boolCond := func(value any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond("Bool", host+":admin", value) }
		}
		cases := []federatedConditionCase{
			{"true claim matches Bool true", map[string]any{"admin": true}, boolCond(true), true},
			{"false claim denied against Bool true", map[string]any{"admin": false}, boolCond(true), false},
			{"false claim matches Bool false", map[string]any{"admin": false}, boolCond(false), true},
			{"string representation \"true\" matches Bool true", map[string]any{"admin": "true"}, boolCond(true), true},
			{"missing key denies", map[string]any{}, boolCond(true), false},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionNullOperatorClaim covers Null against a custom
// claim: key exists vs. does not, Null:true vs. Null:false, and Null
// combined (ANDed) with a separate StringEquals condition in the same
// statement.
func IAMAccessControl_ConditionNullOperatorClaim(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionNullOperatorClaim"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		nullCond := func(value any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond("Null", host+":nickname", value) }
		}
		cases := []federatedConditionCase{
			{"Null true matches when key absent", map[string]any{}, nullCond("true"), true},
			{"Null true denies when key present", map[string]any{"nickname": "bob"}, nullCond("true"), false},
			{"Null false matches when key present", map[string]any{"nickname": "bob"}, nullCond("false"), true},
			{"Null false denies when key absent", map[string]any{}, nullCond("false"), false},
			{
				"Null combined with StringEquals: both satisfied allowed",
				map[string]any{"nickname": "bob"},
				func(host string) json.RawMessage {
					return condAll(map[string]map[string]any{
						"Null":         {host + ":nickname": "false"},
						"StringEquals": {host + ":nickname": "bob"},
					})
				},
				true,
			},
			{
				"Null combined with StringEquals: Null satisfied but StringEquals fails denies",
				map[string]any{"nickname": "bob"},
				func(host string) json.RawMessage {
					return condAll(map[string]map[string]any{
						"Null":         {host + ":nickname": "false"},
						"StringEquals": {host + ":nickname": "someone-else"},
					})
				},
				false,
			},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionBinaryEqualsOperator covers BinaryEquals with
// deterministic base64-encoded claim values.
func IAMAccessControl_ConditionBinaryEqualsOperator(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionBinaryEqualsOperator"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		const wantB64 = "aGVsbG8="  // base64("hello")
		const otherB64 = "d29ybGQ=" // base64("world")
		binCond := func(value any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond("BinaryEquals", host+":cert", value) }
		}
		cases := []federatedConditionCase{
			{"matching base64 value allowed", map[string]any{"cert": wantB64}, binCond(wantB64), true},
			{"nonmatching base64 value denied", map[string]any{"cert": otherB64}, binCond(wantB64), false},
			{"missing key denied", map[string]any{}, binCond(wantB64), false},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionForAnyValueOperator covers ForAnyValue:
// StringEquals against a multi-valued "groups" claim: one request value
// matching is enough.
func IAMAccessControl_ConditionForAnyValueOperator(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionForAnyValueOperator"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		anyCond := func(expected any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond("ForAnyValue:StringEquals", host+":groups", expected) }
		}
		cases := []federatedConditionCase{
			{"one request value matches", map[string]any{"groups": []string{"dev", "qa"}}, anyCond([]any{"qa", "admin"}), true},
			{"all request values match", map[string]any{"groups": []string{"dev", "qa"}}, anyCond([]any{"dev", "qa"}), true},
			{"none match", map[string]any{"groups": []string{"dev", "qa"}}, anyCond([]any{"admin"}), false},
			{"empty request-value set never matches", map[string]any{"groups": []string{}}, anyCond([]any{"dev"}), false},
			{"missing context key denies", map[string]any{}, anyCond([]any{"dev"}), false},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionForAllValuesOperator covers
// ForAllValues:StringEquals against a multi-valued "groups" claim: every
// request value must match one of the expected values.
func IAMAccessControl_ConditionForAllValuesOperator(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionForAllValuesOperator"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		allCond := func(expected any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond("ForAllValues:StringEquals", host+":groups", expected) }
		}
		cases := []federatedConditionCase{
			{"all request values match", map[string]any{"groups": []string{"dev", "qa"}}, allCond([]any{"dev", "qa", "admin"}), true},
			{"only some request values match denies", map[string]any{"groups": []string{"dev", "qa"}}, allCond([]any{"dev"}), false},
			{"none match denies", map[string]any{"groups": []string{"dev", "qa"}}, allCond([]any{"admin"}), false},
			{"empty request-value set is vacuously true", map[string]any{"groups": []string{}}, allCond([]any{"dev"}), true},
			{"missing context key is vacuously true", map[string]any{}, allCond([]any{"dev"}), true},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionIfExistsTrustClaim covers a *IfExists operator
// against a custom claim: absent (vacuously allowed), present and matching
// (allowed), present and mismatched (denied).
func IAMAccessControl_ConditionIfExistsTrustClaim(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionIfExistsTrustClaim"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		ifExistsCond := func(value any) func(string) json.RawMessage {
			return func(host string) json.RawMessage { return cond("StringEqualsIfExists", host+":department", value) }
		}
		cases := []federatedConditionCase{
			{"absent key is vacuously allowed", map[string]any{}, ifExistsCond("eng"), true},
			{"present matching key allowed", map[string]any{"department": "eng"}, ifExistsCond("eng"), true},
			{"present mismatched key denied", map[string]any{"department": "sales"}, ifExistsCond("eng"), false},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// IAMAccessControl_ConditionMultipleOperatorBlocksANDedTrust verifies two
// separate operator blocks in the same trust-statement Condition (a
// StringEquals on sub and a NumericGreaterThan on a custom claim) are
// ANDed: both must be satisfied.
func IAMAccessControl_ConditionMultipleOperatorBlocksANDedTrust(s *S3Conf) error {
	testName := "IAMAccessControl_ConditionMultipleOperatorBlocksANDedTrust"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		cases := []federatedConditionCase{
			{
				"both operator blocks satisfied allowed",
				map[string]any{"sub": "user1", "level": 5},
				func(host string) json.RawMessage {
					return condAll(map[string]map[string]any{
						"StringEquals":       {host + ":sub": "user1"},
						"NumericGreaterThan": {host + ":level": 3},
					})
				},
				true,
			},
			{
				"sub matches but level condition fails denies",
				map[string]any{"sub": "user1", "level": 2},
				func(host string) json.RawMessage {
					return condAll(map[string]map[string]any{
						"StringEquals":       {host + ":sub": "user1"},
						"NumericGreaterThan": {host + ":level": 3},
					})
				},
				false,
			},
		}
		return runFederatedConditionCases(root, s, cases)
	})
}

// Principal-related authorization decisions are tested exclusively through
// role trust policies: an identity-based inline policy can never carry a
// Principal at all (PutUserPolicy/PutRolePolicy reject one outright), so
// there is nothing to test on that side. Within trust policies, only
// Principal.Federated is ever consulted at runtime — this gateway
// implements just sts:AssumeRoleWithWebIdentity, never a plain sts:AssumeRole
// or AssumeRoleWithSAML, so an "AWS" (IAM user/role/root/account) or
// "Service" principal, while accepted by write-time validation, has no
// runtime authorization meaning at all. IAMAccessControl_
// TrustPolicyNonFederatedPrincipalsIgnored demonstrates this divergence from
// real AWS directly. NotPrincipal is likewise grammar-recognized but
// unconditionally rejected at write time on both identity and trust
// policies (Allow and Deny alike), so no valid stored policy can ever carry
// one — there is no authorization decision to test, only a validation
// rejection, which is out of this suite's scope by design.

// IAMAccessControl_TrustPolicyFederatedExactMatchAllowed verifies a trust
// policy naming the exact registered OIDC provider ARN as its Federated
// principal allows assumption for a token issued by that provider.
func IAMAccessControl_TrustPolicyFederatedExactMatchAllowed(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyFederatedExactMatchAllowed"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyFederatedWrongProviderDenied verifies a trust
// policy federating a *real, registered* provider still denies a token
// issued by a *different* real, registered provider — an existing-but-
// mismatched principal, distinct from a dangling reference to a provider
// that was never created at all (see
// IAMAssumeRoleWithWebIdentity_no_matching_principal for that case).
func IAMAccessControl_TrustPolicyFederatedWrongProviderDenied(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyFederatedWrongProviderDenied"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, _, cleanupRole, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanupRole()

		otherProviderURL := newLoopbackOIDCURL()
		otherProviderArn, err := createTestOIDCProviderWithURL(root, otherProviderURL)
		if err != nil {
			return err
		}
		defer deleteOIDCProvider(root, otherProviderArn)

		token := mustToken(map[string]any{"iss": otherProviderURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})
		return wantTrustDeniedInvalidClaims(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyFederatedArrayMatchesAny verifies a Federated
// principal given as an array of provider ARNs matches a token issued by
// *either* one.
func IAMAccessControl_TrustPolicyFederatedArrayMatchesAny(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyFederatedArrayMatchesAny"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		firstURL := newLoopbackOIDCURL()
		firstArn, err := createTestOIDCProviderWithURL(root, firstURL)
		if err != nil {
			return err
		}
		defer deleteOIDCProvider(root, firstArn)

		roleArn, secondURL, cleanupRole, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": []string{firstArn, providerArn}}, Action: "sts:AssumeRoleWithWebIdentity",
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanupRole()

		// A token from the *second* array entry (not the first) still matches.
		token := mustToken(map[string]any{"iss": secondURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyNonFederatedPrincipalsIgnored documents a
// meaningful divergence from real AWS IAM: this gateway's only
// AssumeRole-family action is AssumeRoleWithWebIdentity, so
// EvaluateWebIdentityTrust only ever inspects a statement's
// Principal.Federated value — an "AWS" principal (even a wildcard "*", or a
// literal account root ARN, both of which would grant real AWS's plain
// sts:AssumeRole) or a "Service" principal is accepted by write-time
// validation but has no runtime effect: a role trusting *only* one of these
// can never actually be assumed by anyone, denied exactly as if the trust
// policy had no usable principal at all.
func IAMAccessControl_TrustPolicyNonFederatedPrincipalsIgnored(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyNonFederatedPrincipalsIgnored"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		cases := []struct {
			name      string
			principal any
		}{
			{"AWS wildcard principal alone", map[string]any{"AWS": "*"}},
			{"AWS root account principal alone", map[string]any{"AWS": "arn:aws:iam::" + testAccountID + ":root"}},
			{"Service principal alone", map[string]any{"Service": "sts.amazonaws.com"}},
		}
		for _, tc := range cases {
			if err := func() error {
				roleName := "ac-nonfed-" + genRandString(12)
				trust := trustDoc(trustStatement{Effect: "Allow", Principal: tc.principal, Action: "sts:AssumeRoleWithWebIdentity"})
				if _, err := createIAMRole(root, &iam.CreateRoleInput{RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trust)}); err != nil {
					return err
				}
				defer deleteIAMRole(root, roleName)

				roleArn := "arn:aws:iam::" + testAccountID + ":role/" + roleName
				token := mustToken(map[string]any{"iss": "https://unused.example.com", "aud": "client1", "sub": "user1", "exp": 9999999999})
				return wantTrustDeniedNoPrincipal(s, roleArn, token)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_TrustPolicyStringEqualsSubjectExactAllowed verifies a
// StringEquals condition on <provider>:sub allows a token whose subject
// matches exactly.
func IAMAccessControl_TrustPolicyStringEqualsSubjectExactAllowed(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyStringEqualsSubjectExactAllowed"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":sub", "repo:my-org/my-repo:ref:refs/heads/main"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "exp": 9999999999, "sub": "repo:my-org/my-repo:ref:refs/heads/main"})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyStringEqualsSubjectMismatchDenied is the
// StringEqualsSubjectExactAllowed companion: a different repository's
// subject is denied.
func IAMAccessControl_TrustPolicyStringEqualsSubjectMismatchDenied(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyStringEqualsSubjectMismatchDenied"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":sub", "repo:my-org/my-repo:ref:refs/heads/main"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "exp": 9999999999, "sub": "repo:my-org/other-repo:ref:refs/heads/main"})
		return wantTrustDeniedInvalidClaims(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyStringLikeBranchWildcardAllowed verifies a
// StringLike condition on <provider>:sub with a trailing wildcard allows any
// branch under refs/heads/ — a realistic GitHub-Actions-style pattern.
func IAMAccessControl_TrustPolicyStringLikeBranchWildcardAllowed(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyStringLikeBranchWildcardAllowed"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringLike", host+":sub", "repo:my-org/my-repo:ref:refs/heads/*"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "exp": 9999999999, "sub": "repo:my-org/my-repo:ref:refs/heads/feature-x"})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyStringLikeTagSubjectDenied is the
// StringLikeBranchWildcardAllowed companion: a pull-request-triggered
// subject (a different sub shape entirely, not matching the refs/heads/*
// pattern) is denied.
func IAMAccessControl_TrustPolicyStringLikeTagSubjectDenied(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyStringLikeTagSubjectDenied"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringLike", host+":sub", "repo:my-org/my-repo:ref:refs/heads/*"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "exp": 9999999999, "sub": "repo:my-org/my-repo:pull_request"})
		return wantTrustDeniedInvalidClaims(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyAudienceCorrectAllowed verifies a StringEquals
// condition on <provider>:aud allows a token whose (ClientIDList-valid)
// audience matches the condition's expected value. The provider's
// ClientIDList registers *two* acceptable audiences so this and
// AudienceIncorrectDenied can each present a ClientIDList-valid audience,
// isolating the Condition itself as what's actually under test (see
// newFederatedRole's doc comment).
func IAMAccessControl_TrustPolicyAudienceCorrectAllowed(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyAudienceCorrectAllowed"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, []string{"expected-aud", "other-aud"}, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":aud", "expected-aud"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": "expected-aud", "sub": "user1", "exp": 9999999999})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyAudienceIncorrectDenied is the
// AudienceCorrectAllowed companion: an audience that's valid per
// ClientIDList but doesn't match the trust policy's Condition is denied.
func IAMAccessControl_TrustPolicyAudienceIncorrectDenied(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyAudienceIncorrectDenied"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, []string{"expected-aud", "other-aud"}, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":aud", "expected-aud"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": "other-aud", "sub": "user1", "exp": 9999999999})
		return wantTrustDeniedInvalidClaims(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyMultipleAudiencesArrayAllowed verifies a
// StringEquals condition on <provider>:aud with an array of acceptable
// values matches any one of them.
func IAMAccessControl_TrustPolicyMultipleAudiencesArrayAllowed(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyMultipleAudiencesArrayAllowed"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, []string{"aud-one", "aud-two"}, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":aud", []string{"aud-one", "aud-two"}),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": "aud-two", "sub": "user1", "exp": 9999999999})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyAudienceAndSubjectBothMustMatch verifies a
// trust statement with Conditions on both <provider>:aud and <provider>:sub
// requires both to match — either alone is not enough.
func IAMAccessControl_TrustPolicyAudienceAndSubjectBothMustMatch(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyAudienceAndSubjectBothMustMatch"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		cases := []struct {
			name        string
			aud, sub    string
			wantAllowed bool
		}{
			{"both match allowed", "expected-aud", "expected-sub", true},
			{"only audience matches denied", "expected-aud", "wrong-sub", false},
			{"only subject matches denied", "wrong-aud", "expected-sub", false},
			{"neither matches denied", "wrong-aud", "wrong-sub", false},
		}
		for _, tc := range cases {
			if err := func() error {
				roleArn, providerURL, cleanup, err := newFederatedRole(root, []string{"expected-aud", "wrong-aud"}, func(providerArn, providerURL string) string {
					host := trimProviderScheme(providerURL)
					return trustDoc(trustStatement{
						Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
						Condition: condAll(map[string]map[string]any{
							"StringEquals": {host + ":aud": "expected-aud", host + ":sub": "expected-sub"},
						}),
					})
				}, nil)
				if err != nil {
					return err
				}
				defer cleanup()

				token := mustToken(map[string]any{"iss": providerURL, "aud": tc.aud, "sub": tc.sub, "exp": 9999999999})
				if tc.wantAllowed {
					return wantTrustAllowed(s, roleArn, token)
				}
				return wantTrustDeniedInvalidClaims(s, roleArn, token)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_TrustPolicyExplicitDenyStatement verifies an explicit
// Deny statement scoped to one subject blocks assumption for that subject
// while a broader Allow still covers every other subject.
func IAMAccessControl_TrustPolicyExplicitDenyStatement(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyExplicitDenyStatement"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(
				trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"},
				trustStatement{
					Effect: "Deny", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
					Condition: cond("StringEquals", host+":sub", "blocked-user"),
				},
			)
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		blockedToken := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "blocked-user", "exp": 9999999999})
		if err := wantTrustDeniedExplicit(s, roleArn, blockedToken); err != nil {
			return fmt.Errorf("blocked subject: %w", err)
		}

		allowedToken := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "someone-else", "exp": 9999999999})
		if err := wantTrustAllowed(s, roleArn, allowedToken); err != nil {
			return fmt.Errorf("non-blocked subject: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_TrustPolicyMultipleStatementsSecondGrants verifies a
// trust policy is evaluated statement by statement across the whole
// document: a first statement referencing an unrelated provider doesn't
// prevent a second statement (for the *actual* issuer) from granting
// assumption.
func IAMAccessControl_TrustPolicyMultipleStatementsSecondGrants(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyMultipleStatementsSecondGrants"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		unrelatedURL := newLoopbackOIDCURL()
		unrelatedArn, err := createTestOIDCProviderWithURL(root, unrelatedURL)
		if err != nil {
			return err
		}
		defer deleteOIDCProvider(root, unrelatedArn)

		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(
				trustStatement{Sid: "Unrelated", Effect: "Allow", Principal: map[string]any{"Federated": unrelatedArn}, Action: "sts:AssumeRoleWithWebIdentity"},
				trustStatement{Sid: "Actual", Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"},
			)
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})
		return wantTrustAllowed(s, roleArn, token)
	})
}

// IAMAccessControl_TrustPolicyMissingRequiredClaimDenied verifies a
// StringEquals condition against a claim key the token simply never carries
// denies assumption — a positive (non-IfExists) operator against an absent
// key fails closed (see IAMAccessControl_ConditionIfExistsTrustClaim for
// the IfExists variant's opposite behavior on the same kind of absence).
func IAMAccessControl_TrustPolicyMissingRequiredClaimDenied(s *S3Conf) error {
	testName := "IAMAccessControl_TrustPolicyMissingRequiredClaimDenied"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":employee_id", "12345"),
			})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		// The token never includes an employee_id claim at all.
		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})
		return wantTrustDeniedInvalidClaims(s, roleArn, token)
	})
}

// IAMAccessControl_UserInlinePolicyWorkflow exercises the full lifecycle a
// user's inline policy goes through: create two users (one caller, one
// target), attach an inline policy scoped to a condition on the caller's
// own identity, create access keys, make signed calls as the caller,
// verify the permitted action+resource succeeds, verify denial for another
// action, another user resource, a condition mismatch (a second,
// differently-named caller under the same policy shape), and an explicit
// Deny, then update the policy and verify the changed authorization takes
// effect while the explicit Deny still holds.
func IAMAccessControl_UserInlinePolicyWorkflow(s *S3Conf) error {
	testName := "IAMAccessControl_UserInlinePolicyWorkflow"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		targetName, targetArn, cleanupTarget, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupTarget()
		otherName, otherArn, cleanupOther, err := newTargetUser(root)
		if err != nil {
			return err
		}
		defer cleanupOther()

		callerName := "ac-workflow-" + genRandString(10)
		grant := func(callerUserName string) string {
			return policyDoc(
				accessStatement{Sid: "AllowGetTarget", Effect: "Allow", Action: actGetUser, Resource: targetArn,
					Condition: cond("StringEquals", "aws:username", callerUserName)},
				accessStatement{Sid: "DenyDeletePolicy", Effect: "Deny", Action: actDeleteUserPolicy, Resource: "*"},
			)
		}
		caller, cleanupCaller, err := newAccessControlCaller(root, s, callerName, map[string]string{"grant": grant(callerName)})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		// Permitted action + resource succeeds, and genuinely returns the
		// target's data (not just a nil error).
		getOut, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(targetName)})
		if err := wantAllowed(caller.arn, actGetUser, targetArn, err); err != nil {
			return fmt.Errorf("permitted action+resource: %w", err)
		}
		if getOut == nil || getOut.User == nil || aws.ToString(getOut.User.UserName) != targetName {
			return fmt.Errorf("expected GetUser to return user %q, got %#v", targetName, getOut)
		}

		// Another action against the same resource is denied.
		if _, err := listIAMUserPolicies(caller.client, &iam.ListUserPoliciesInput{UserName: aws.String(targetName)}); wantDenied(caller.arn, actListUserPolicies, targetArn, err) != nil {
			return fmt.Errorf("another action: %w", wantDenied(caller.arn, actListUserPolicies, targetArn, err))
		}

		// The same permitted action against a different user resource is denied.
		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(otherName)}); wantDenied(caller.arn, actGetUser, otherArn, err) != nil {
			return fmt.Errorf("another resource: %w", wantDenied(caller.arn, actGetUser, otherArn, err))
		}

		// A condition mismatch (a caller whose own username differs from what
		// the policy's Condition expects) is denied even under the identical
		// policy shape.
		mismatchName := "ac-workflow-" + genRandString(10)
		mismatchCaller, cleanupMismatch, err := newAccessControlCaller(root, s, mismatchName, map[string]string{"grant": grant(callerName)})
		if err != nil {
			return err
		}
		defer cleanupMismatch()
		if _, err := getIAMUser(mismatchCaller.client, &iam.GetUserInput{UserName: aws.String(targetName)}); wantDenied(mismatchCaller.arn, actGetUser, targetArn, err) != nil {
			return fmt.Errorf("condition mismatch: %w", wantDenied(mismatchCaller.arn, actGetUser, targetArn, err))
		}

		// An explicit Deny blocks an action the broad wildcard Resource on
		// that statement would otherwise apply to, regardless of what the
		// named policy/resource actually is.
		_, err = deleteIAMUserPolicyRaw(caller.client, &iam.DeleteUserPolicyInput{UserName: aws.String(targetName), PolicyName: aws.String("irrelevant")})
		if err := wantDenied(caller.arn, actDeleteUserPolicy, targetArn, err); err != nil {
			return fmt.Errorf("explicit deny: %w", err)
		}

		// Updating the policy to grant the previously-denied action takes
		// effect immediately.
		updated := policyDoc(
			accessStatement{Sid: "AllowGetTarget", Effect: "Allow", Action: []string{actGetUser, actListUserPolicies}, Resource: targetArn,
				Condition: cond("StringEquals", "aws:username", callerName)},
			accessStatement{Sid: "DenyDeletePolicy", Effect: "Deny", Action: actDeleteUserPolicy, Resource: "*"},
		)
		if _, err := putIAMUserPolicy(root, &iam.PutUserPolicyInput{
			UserName: aws.String(caller.userName), PolicyName: aws.String("grant"), PolicyDocument: aws.String(updated),
		}); err != nil {
			return fmt.Errorf("update policy: %w", err)
		}
		if _, err := listIAMUserPolicies(caller.client, &iam.ListUserPoliciesInput{UserName: aws.String(targetName)}); wantAllowed(caller.arn, actListUserPolicies, targetArn, err) != nil {
			return fmt.Errorf("newly granted action after update: %w", wantAllowed(caller.arn, actListUserPolicies, targetArn, err))
		}

		// The explicit Deny is still in effect after the update.
		_, err = deleteIAMUserPolicyRaw(caller.client, &iam.DeleteUserPolicyInput{UserName: aws.String(targetName), PolicyName: aws.String("irrelevant")})
		if err := wantDenied(caller.arn, actDeleteUserPolicy, targetArn, err); err != nil {
			return fmt.Errorf("explicit deny after update: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_UserPathScopedResourceGrantsOnlyMatchingPath verifies a
// resource pattern scoped to one path prefix grants access to users under
// that path but not to a user with a different path, even with an
// otherwise-identical name prefix.
func IAMAccessControl_UserPathScopedResourceGrantsOnlyMatchingPath(s *S3Conf) error {
	testName := "IAMAccessControl_UserPathScopedResourceGrantsOnlyMatchingPath"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		inPathName, inPathArn, cleanupInPath, err := newTargetUserWithPath(root, "/ac-finance/")
		if err != nil {
			return err
		}
		defer cleanupInPath()
		outOfPathName, outOfPathArn, cleanupOutOfPath, err := newTargetUserWithPath(root, "/ac-marketing/")
		if err != nil {
			return err
		}
		defer cleanupOutOfPath()

		policy := policyDoc(accessStatement{Effect: "Allow", Action: actGetUser, Resource: "arn:aws:iam::" + testAccountID + ":user/ac-finance/*"})
		caller, cleanupCaller, err := newAccessControlCaller(root, s, "", map[string]string{"p": policy})
		if err != nil {
			return err
		}
		defer cleanupCaller()

		if _, err := getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(inPathName)}); wantAllowed(caller.arn, actGetUser, inPathArn, err) != nil {
			return fmt.Errorf("in-path user: %w", wantAllowed(caller.arn, actGetUser, inPathArn, err))
		}
		_, err = getIAMUser(caller.client, &iam.GetUserInput{UserName: aws.String(outOfPathName)})
		if err := wantDenied(caller.arn, actGetUser, outOfPathArn, err); err != nil {
			return fmt.Errorf("out-of-path user: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_RolePermissionPolicyDoesNotAffectAssumptionDecision
// demonstrates that trust-policy authorization and role-permission
// authorization are separate stages: a role's inline (permission) policy —
// absent, permissive, or deny-all — has no bearing on whether the role can
// be assumed. Every variant reaches the identical trust-evaluation outcome
// (this suite's network-stage proxy for "Allowed", per the file doc
// comment) with the trust policy held fixed.
func IAMAccessControl_RolePermissionPolicyDoesNotAffectAssumptionDecision(s *S3Conf) error {
	testName := "IAMAccessControl_RolePermissionPolicyDoesNotAffectAssumptionDecision"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		cases := []struct {
			name           string
			rolePermission map[string]string
		}{
			{"no permission policy at all", nil},
			{"broad permissive permission policy", map[string]string{"perm": policyDoc(accessStatement{Effect: "Allow", Action: "iam:*", Resource: "*"})}},
			{"deny-all permission policy", map[string]string{"perm": policyDoc(accessStatement{Effect: "Deny", Action: "iam:*", Resource: "*"})}},
		}
		for _, tc := range cases {
			if err := func() error {
				roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
					return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"})
				}, tc.rolePermission)
				if err != nil {
					return err
				}
				defer cleanup()

				token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})
				return wantTrustAllowed(s, roleArn, token)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAccessControl_RoleTrustDenialIndependentOfPermissionPolicy is the
// converse of RolePermissionPolicyDoesNotAffectAssumptionDecision: even a
// maximally permissive role permission policy cannot compensate for a trust
// policy that doesn't authorize the caller — assumption is still denied.
func IAMAccessControl_RoleTrustDenialIndependentOfPermissionPolicy(s *S3Conf) error {
	testName := "IAMAccessControl_RoleTrustDenialIndependentOfPermissionPolicy"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, _, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
			host := trimProviderScheme(providerURL)
			return trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity",
				Condition: cond("StringEquals", host+":sub", "expected-user"),
			})
		}, map[string]string{"perm": policyDoc(accessStatement{Effect: "Allow", Action: "iam:*", Resource: "*"})})
		if err != nil {
			return err
		}
		defer cleanup()

		// A different subject: trust Condition fails despite the role's own
		// permission policy granting everything.
		token := mustToken(map[string]any{"iss": "https://unused-in-this-assertion.example.com", "aud": defaultTestAudience[0], "sub": "someone-else", "exp": 9999999999})
		return wantTrustDeniedInvalidClaims(s, roleArn, token)
	})
}

// IAMAccessControl_CrossIdentity_UnrelatedRoleCannotBeAssumedViaWrongIssuer
// verifies isolation between two independently-configured federated roles:
// a token issued for role A's provider cannot assume role B, even though it
// can (still) assume role A.
func IAMAccessControl_CrossIdentity_UnrelatedRoleCannotBeAssumedViaWrongIssuer(s *S3Conf) error {
	testName := "IAMAccessControl_CrossIdentity_UnrelatedRoleCannotBeAssumedViaWrongIssuer"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleAArn, providerAURL, cleanupA, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanupA()

		roleBArn, _, cleanupB, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanupB()

		tokenForA := mustToken(map[string]any{"iss": providerAURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})

		if err := wantTrustAllowed(s, roleAArn, tokenForA); err != nil {
			return fmt.Errorf("token still assumes its own role: %w", err)
		}
		if err := wantTrustDeniedInvalidClaims(s, roleBArn, tokenForA); err != nil {
			return fmt.Errorf("same token cannot assume an unrelated role: %w", err)
		}
		return nil
	})
}

// IAMAccessControl_CrossIdentity_AssumeRoleWithWebIdentityHasNoCallerIdentityCheck
// documents a meaningful divergence from real AWS's plain sts:AssumeRole:
// this gateway's only assume-role action is unauthenticated (see
// stsOpenRoute in iamapi/router.go — VerifyIAMAuth never runs for it), so
// there is no calling IAM identity and thus no identity-based-policy check
// on the assumption call itself, only the target role's trust policy. This
// is demonstrated by showing an identical trust/token pair produces an
// identical result (the same network-dependent failure this suite uses
// throughout as its proxy for reaching a genuine Allowed decision — see the
// file doc comment) whether the request is signed with the real root
// credential or with a completely arbitrary, nonexistent access key: if
// caller identity mattered here, at least one of these would fail
// differently (e.g. an unknown-access-key error) instead of both reaching
// the identical outcome.
func IAMAccessControl_CrossIdentity_AssumeRoleWithWebIdentityHasNoCallerIdentityCheck(s *S3Conf) error {
	testName := "IAMAccessControl_CrossIdentity_AssumeRoleWithWebIdentityHasNoCallerIdentityCheck"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, _ string) string {
			return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"Federated": providerArn}, Action: "sts:AssumeRoleWithWebIdentity"})
		}, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		token := mustToken(map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999})

		if err := wantTrustAllowed(s, roleArn, token); err != nil {
			return fmt.Errorf("signed with the real root credential: %w", err)
		}

		bogusCfg := *s
		bogusCfg.awsID, bogusCfg.awsSecret = "AKIA"+genRandString(16), genRandString(32)
		if err := wantTrustAllowed(&bogusCfg, roleArn, token); err != nil {
			return fmt.Errorf("signed with an arbitrary, nonexistent access key: %w", err)
		}
		return nil
	})
}

// accessControlCaller is an isolated IAM user with its own long-term access
// key, used as the authenticated caller for an identity-policy authorization
// test.
type accessControlCaller struct {
	userName string
	userID   string
	arn      string
	client   *iam.Client
}

// newAccessControlCaller creates an isolated IAM user (userName, or an
// auto-generated one if empty), attaches the given named inline policies
// (policyName -> document; may be nil/empty), creates one long-term access
// key, and returns an *iam.Client authenticated as that user plus a cleanup
// func that removes the key, every attached policy, and the user itself.
func newAccessControlCaller(root *iam.Client, s *S3Conf, userName string, policies map[string]string) (*accessControlCaller, func(), error) {
	return newAccessControlCallerTagged(root, s, userName, policies, nil)
}

// newAccessControlCallerTagged is newAccessControlCaller plus tags on the
// created user, for aws:PrincipalTag/Null/IfExists-style tests.
func newAccessControlCallerTagged(root *iam.Client, s *S3Conf, userName string, policies map[string]string, tags map[string]string) (*accessControlCaller, func(), error) {
	if userName == "" {
		userName = newIAMUserName()
	}

	input := &iam.CreateUserInput{UserName: aws.String(userName)}
	for k, v := range tags {
		input.Tags = append(input.Tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	createOut, err := createIAMUser(root, input)
	if err != nil {
		return nil, nil, fmt.Errorf("create caller user: %w", err)
	}

	for name, doc := range policies {
		if _, err := putIAMUserPolicy(root, &iam.PutUserPolicyInput{
			UserName: aws.String(userName), PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
		}); err != nil {
			deleteIAMUser(root, userName)
			return nil, nil, fmt.Errorf("attach caller policy %q: %w", name, err)
		}
	}

	keyOut, err := createIAMAccessKey(root, &iam.CreateAccessKeyInput{UserName: aws.String(userName)})
	if err != nil {
		deleteAccessControlCaller(root, userName)
		return nil, nil, fmt.Errorf("create caller access key: %w", err)
	}

	caller := &accessControlCaller{
		userName: userName,
		userID:   aws.ToString(createOut.User.UserId),
		arn:      aws.ToString(createOut.User.Arn),
		client:   iamClientWithCreds(s, aws.ToString(keyOut.AccessKey.AccessKeyId), aws.ToString(keyOut.AccessKey.SecretAccessKey), ""),
	}
	cleanup := func() { deleteAccessControlCaller(root, userName) }
	return caller, cleanup, nil
}

// deleteAccessControlCaller removes every dependency DeleteUser would
// otherwise reject (inline policies, access keys) before deleting the user
// itself. Neither of the existing deleteIAMUserAndPolicies/
// deleteIAMUserAndAccessKeys helpers alone covers the combination
// newAccessControlCaller's fixtures always create (both policies and a
// key), so this file needs its own.
func deleteAccessControlCaller(root *iam.Client, userName string) error {
	polOut, err := listIAMUserPolicies(root, &iam.ListUserPoliciesInput{UserName: aws.String(userName)})
	if err != nil {
		return err
	}
	for _, name := range polOut.PolicyNames {
		if err := deleteIAMUserPolicy(root, userName, name); err != nil {
			return err
		}
	}

	keyOut, err := listIAMAccessKeys(root, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
	if err != nil {
		return err
	}
	for _, key := range keyOut.AccessKeyMetadata {
		if err := deleteIAMAccessKey(root, userName, aws.ToString(key.AccessKeyId)); err != nil {
			return err
		}
	}

	return deleteIAMUser(root, userName)
}

// newTargetUser creates a plain, isolated IAM user with no policies of its
// own, to be used as the resource another caller's policy is tested
// against.
func newTargetUser(root *iam.Client) (userName, arn string, cleanup func(), err error) {
	return newTargetUserWithPath(root, "")
}

// newTargetUserWithPath is newTargetUser with an explicit Path, for
// resource-path-wildcard tests.
func newTargetUserWithPath(root *iam.Client, path string) (userName, arn string, cleanup func(), err error) {
	userName = "ac-target-" + genRandString(12)
	input := &iam.CreateUserInput{UserName: aws.String(userName)}
	if path != "" {
		input.Path = aws.String(path)
	}
	out, err := createIAMUser(root, input)
	if err != nil {
		return "", "", nil, err
	}
	return userName, aws.ToString(out.User.Arn), func() { deleteIAMUser(root, userName) }, nil
}

// newTargetUserTagged is newTargetUser plus tags, for
// iam:ResourceTag/aws:ResourceTag condition tests.
func newTargetUserTagged(root *iam.Client, tags map[string]string) (userName, arn string, cleanup func(), err error) {
	userName = "ac-target-" + genRandString(12)
	input := &iam.CreateUserInput{UserName: aws.String(userName)}
	for k, v := range tags {
		input.Tags = append(input.Tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	out, err := createIAMUser(root, input)
	if err != nil {
		return "", "", nil, err
	}
	return userName, aws.ToString(out.User.Arn), func() { deleteIAMUser(root, userName) }, nil
}

// newTargetRole creates a plain role (permissive default trust policy, no
// inline policies) to be used as the resource another caller's policy is
// tested against.
func newTargetRole(root *iam.Client) (roleName, arn string, cleanup func(), err error) {
	roleName = "ac-target-role-" + genRandString(12)
	if _, err = createIAMRole(root, &iam.CreateRoleInput{
		RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
	}); err != nil {
		return "", "", nil, err
	}
	return roleName, "arn:aws:iam::" + testAccountID + ":role/" + roleName, func() { deleteIAMRole(root, roleName) }, nil
}

// iamClientWithCreds builds an *iam.Client authenticated as the given
// access/secret/session-token triple, reusing s's endpoint/region/http
// client. S3Conf has no session-token field of its own (only
// AssumeRoleWithWebIdentity-derived credentials would ever need one, and
// this file never gets that far — see the file doc comment), so every call
// site here passes token="" — but the parameter exists so this stays
// reusable if that ever changes.
func iamClientWithCreds(s *S3Conf, access, secret, token string) *iam.Client {
	cfg := s.Config()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(access, secret, token)
	return iam.NewFromConfig(cfg)
}

// getIAMUser is the GetUser counterpart to the existing getIAMRole/
// getIAMUserPolicy/getIAMRolePolicy helpers elsewhere in this package — no
// prior test file needed a generic wrapper for it.
func getIAMUser(client *iam.Client, input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.GetUser(ctx, input)
}

// wantAllowed reports a descriptive error if err is non-nil, identifying the
// caller, action, and resource a test expected to be authorized.
func wantAllowed(callerArn, action, resource string, err error) error {
	if err != nil {
		return fmt.Errorf("caller=%s action=%s resource=%s: expected ALLOW, got error: %v", callerArn, action, resource, err)
	}
	return nil
}

// wantDenied asserts err is exactly the AccessDenied error VerifyIAMPolicy
// produces for callerArn/action — not merely "some error" (a wrong ARN, a
// missing parameter, or a not-found resource must not be mistaken for an
// authorization denial).
func wantDenied(callerArn, action, resource string, err error) error {
	if cerr := checkIAMApiErr(err, iamerr.AccessDeniedIAMAction(callerArn, action)); cerr != nil {
		return fmt.Errorf("caller=%s action=%s resource=%s: expected DENY: %w", callerArn, action, resource, cerr)
	}
	return nil
}

// accessStatement is a safe, type-checked builder for one identity-policy
// statement — used instead of hand-formatted JSON strings so a test typo
// produces a Go compile error or a visibly-wrong marshaled document instead
// of a silently-malformed policy. Action/NotAction/Resource/NotResource
// accept either a bare string or a []string (both marshal the way this
// gateway's StringOrSlice unmarshals them).
type accessStatement struct {
	Sid         string          `json:"Sid,omitempty"`
	Effect      string          `json:"Effect"`
	Action      any             `json:"Action,omitempty"`
	NotAction   any             `json:"NotAction,omitempty"`
	Resource    any             `json:"Resource,omitempty"`
	NotResource any             `json:"NotResource,omitempty"`
	Condition   json.RawMessage `json:"Condition,omitempty"`
}

// policyDoc marshals statements into a complete "2012-10-17" identity-policy
// document string. Marshaling a fixed struct of strings/[]string/
// json.RawMessage cannot fail in practice; a panic here means a test itself
// is malformed, not a runtime condition to recover from.
func policyDoc(statements ...accessStatement) string {
	doc := struct {
		Version   string            `json:"Version"`
		Statement []accessStatement `json:"Statement"`
	}{"2012-10-17", statements}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(fmt.Sprintf("iam_access_control: policyDoc: %v", err))
	}
	return string(b)
}

// trustStatement is accessStatement's counterpart for role trust policies:
// Principal is required (never NotPrincipal — see the file's Principal
// section for why versitygw rejects NotPrincipal unconditionally), and
// Resource/NotResource don't exist in trust-policy grammar at all.
type trustStatement struct {
	Sid       string          `json:"Sid,omitempty"`
	Effect    string          `json:"Effect"`
	Principal any             `json:"Principal"`
	Action    any             `json:"Action,omitempty"`
	NotAction any             `json:"NotAction,omitempty"`
	Condition json.RawMessage `json:"Condition,omitempty"`
}

func trustDoc(statements ...trustStatement) string {
	doc := struct {
		Version   string           `json:"Version"`
		Statement []trustStatement `json:"Statement"`
	}{"2012-10-17", statements}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(fmt.Sprintf("iam_access_control: trustDoc: %v", err))
	}
	return string(b)
}

// cond builds a Condition block containing a single operator/key/value(s)
// entry, e.g. cond("StringEquals", "aws:username", "alice") or
// cond("StringEquals", "aws:username", []string{"alice", "bob"}).
func cond(operator, key string, value any) json.RawMessage {
	b, err := json.Marshal(map[string]map[string]any{operator: {key: value}})
	if err != nil {
		panic(fmt.Sprintf("iam_access_control: cond: %v", err))
	}
	return b
}

// condAll builds a Condition block from multiple operator blocks and/or
// multiple keys within a block, for multi-condition-semantics tests (see
// evaluateCondition's AND-across-operators/keys, OR-across-values
// semantics).
func condAll(blocks map[string]map[string]any) json.RawMessage {
	b, err := json.Marshal(blocks)
	if err != nil {
		panic(fmt.Sprintf("iam_access_control: condAll: %v", err))
	}
	return b
}

// mustToken wraps webIdentityTokenWithClaims for call sites that pass fixed,
// well-formed claims — a marshal failure there means a test itself is
// malformed, not a runtime condition.
func mustToken(claims map[string]any) string {
	tok, err := webIdentityTokenWithClaims(claims)
	if err != nil {
		panic(fmt.Sprintf("iam_access_control: mustToken: %v", err))
	}
	return tok
}

// newLoopbackOIDCURL returns a random loopback-IP-based OIDC provider URL.
// Every trust-policy test in this file that needs to observe an "Allowed"
// decision (see the file doc comment) federates a loopback provider so
// evaluation deterministically fails at the network-dependent signature step
// instead of hanging or attempting real internet access. A random address,
// rather than a fixed one like 127.0.0.1, keeps concurrently-running
// subtests from colliding on the same provider identity.
func newLoopbackOIDCURL() string {
	return fmt.Sprintf("https://127.%d.%d.%d", 1+rand.Intn(254), 1+rand.Intn(254), 1+rand.Intn(254))
}

// newFederatedRole creates a fresh OIDC provider at a random loopback URL
// (see newLoopbackOIDCURL) with the given ClientIDList, then a role whose
// trust policy is buildTrust(providerArn, providerURL) — buildTrust is
// handed both so it can reference the provider as a Federated principal and
// build "<host>:<claim>"-style Condition keys (via trimProviderScheme).
// rolePolicies (may be nil) are attached as the role's inline *permission*
// policies; several tests in this file deliberately vary these (empty,
// permissive, deny-all) while holding the trust policy fixed, to
// demonstrate that a role's permission policy has no bearing on whether it
// can be assumed — only its trust policy does (see
// IAMAccessControl_RolePermissionPolicyDoesNotAffectAssumptionDecision).
func newFederatedRole(root *iam.Client, clientIDs []string, buildTrust func(providerArn, providerURL string) string, rolePolicies map[string]string) (roleArn, providerURL string, cleanup func(), err error) {
	providerURL = newLoopbackOIDCURL()
	out, err := createOIDCProvider(root, &iam.CreateOpenIDConnectProviderInput{
		Url:            aws.String(providerURL),
		ClientIDList:   clientIDs,
		ThumbprintList: []string{validOIDCThumbprint},
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("create provider: %w", err)
	}
	providerArn := aws.ToString(out.OpenIDConnectProviderArn)

	roleName := "ac-role-" + genRandString(12)
	trust := buildTrust(providerArn, providerURL)
	if _, err := createIAMRole(root, &iam.CreateRoleInput{RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trust)}); err != nil {
		deleteOIDCProvider(root, providerArn)
		return "", "", nil, fmt.Errorf("create role: %w", err)
	}

	for name, doc := range rolePolicies {
		if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
			RoleName: aws.String(roleName), PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
		}); err != nil {
			deleteIAMRoleAndPolicies(root, roleName)
			deleteOIDCProvider(root, providerArn)
			return "", "", nil, fmt.Errorf("attach role policy %q: %w", name, err)
		}
	}

	roleArn = "arn:aws:iam::" + testAccountID + ":role/" + roleName
	cleanup = func() {
		deleteIAMRoleAndPolicies(root, roleName)
		deleteOIDCProvider(root, providerArn)
	}
	return roleArn, providerURL, cleanup, nil
}

// wantTrustAllowed asserts that assuming roleArn with token reaches the
// network-dependent signature-verification stage — this suite's
// deterministic, black-box-observable proxy for "trust policy evaluation
// returned Allowed" (see the file doc comment). roleArn's trust policy must
// federate a loopback-URL provider (see newLoopbackOIDCURL/newFederatedRole)
// for the network step to fail deterministically instead of hanging or
// attempting real internet access.
func wantTrustAllowed(s *S3Conf, roleArn, token string) error {
	_, err := assumeRoleWithWebIdentity(s, roleArn, "ac-session-"+genRandString(8), token, 0)
	return checkIAMApiErr(err, iamerr.InvalidIdentityTokenIDPCommunicationError())
}

// wantTrustDeniedNoPrincipal asserts assumption fails the way it does when
// no statement's Federated principal resolves to a provider that actually
// exists (policy.NoPrincipal) — the same AccessDenied outcome AWS also uses
// for a role that doesn't exist at all, never confirming or denying which.
func wantTrustDeniedNoPrincipal(s *S3Conf, roleArn, token string) error {
	_, err := assumeRoleWithWebIdentity(s, roleArn, "ac-session-"+genRandString(8), token, 0)
	return checkIAMApiErr(err, iamerr.AccessDeniedAssumeRoleWithWebIdentity())
}

// wantTrustDeniedExplicit asserts assumption fails via an explicit Deny
// statement (policy.ExplicitlyDenied) — also AccessDenied, but reached via a
// different evaluation path than wantTrustDeniedNoPrincipal (a real,
// existing, issuer-matching provider whose statement actively denies, not an
// unresolvable principal).
func wantTrustDeniedExplicit(s *S3Conf, roleArn, token string) error {
	_, err := assumeRoleWithWebIdentity(s, roleArn, "ac-session-"+genRandString(8), token, 0)
	return checkIAMApiErr(err, iamerr.AccessDeniedAssumeRoleWithWebIdentity())
}

// wantTrustDeniedInvalidClaims asserts assumption fails at the claims stage
// (policy.NoIssuerMatch or policy.ConditionFailed) — an existing, correctly
// Federated provider whose Condition (or, elsewhere in this package,
// audience/issuer) didn't satisfy the request.
func wantTrustDeniedInvalidClaims(s *S3Conf, roleArn, token string) error {
	_, err := assumeRoleWithWebIdentity(s, roleArn, "ac-session-"+genRandString(8), token, 0)
	return checkIAMApiErr(err, iamerr.InvalidIdentityTokenClaims())
}

// federatedConditionCase is one row of a table-driven trust-policy Condition
// test: a JWT claim (merged over the base iss/aud/sub/exp claims
// runFederatedConditionCases always supplies) paired with the Condition
// block a role's trust policy scopes, and whether that combination should
// let evaluation reach the network stage (wantTrustAllowed's proxy for
// "Allowed") or fail with InvalidIdentityTokenClaims.
type federatedConditionCase struct {
	name        string
	claims      map[string]any
	condition   func(host string) json.RawMessage
	wantAllowed bool
}

// runFederatedConditionCases runs each case against its own fresh
// provider/role (see newFederatedRole), always using defaultTestAudience so
// a case's outcome is driven solely by its own condition/claim, never an
// incidental audience mismatch.
func runFederatedConditionCases(root *iam.Client, s *S3Conf, cases []federatedConditionCase) error {
	for _, tc := range cases {
		if err := func() error {
			roleArn, providerURL, cleanup, err := newFederatedRole(root, defaultTestAudience, func(providerArn, providerURL string) string {
				return trustDoc(trustStatement{
					Effect:    "Allow",
					Principal: map[string]any{"Federated": providerArn},
					Action:    "sts:AssumeRoleWithWebIdentity",
					Condition: tc.condition(trimProviderScheme(providerURL)),
				})
			}, nil)
			if err != nil {
				return err
			}
			defer cleanup()

			claims := map[string]any{"iss": providerURL, "aud": defaultTestAudience[0], "sub": "user1", "exp": 9999999999}
			for k, v := range tc.claims {
				claims[k] = v
			}
			token := mustToken(claims)

			if tc.wantAllowed {
				return wantTrustAllowed(s, roleArn, token)
			}
			return wantTrustDeniedInvalidClaims(s, roleArn, token)
		}(); err != nil {
			return fmt.Errorf("%s: %w", tc.name, err)
		}
	}
	return nil
}

// callerSourceIP returns the IP address the gateway will observe as
// aws:SourceIp for requests made through s's configured endpoint — derived
// from the endpoint's own host rather than assumed, since loopback
// connections use the destination address as their source (no NAT), and the
// integration harness always points s's endpoint at a literal loopback IP
// (see runiamtests.sh). Returns an error rather than guessing if the
// endpoint's host isn't a literal IP, so an IP-condition test fails loudly
// instead of silently asserting against the wrong address.
func callerSourceIP(s *S3Conf) (string, error) {
	u, err := url.Parse(s.endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint %q: %w", s.endpoint, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("endpoint %q has no host", s.endpoint)
	}
	return host, nil
}
