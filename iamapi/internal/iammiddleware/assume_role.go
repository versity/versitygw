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

package iammiddleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/policy"
	"github.com/versity/versitygw/iamapi/types"
)

// AuthorizeAssumeRole reports whether identity may assume role.
//
// Two policies decide, and they are not symmetric. The role's trust policy
// is a resource-based policy on the role; the caller's identity policies
// (and, for a session, its session policy) are the other side. Within one
// account a resource-based grant naming the caller is enough by itself,
// while one naming only the account hands the decision to the account's own
// IAM:
//
//   - A session whose role no longer exists, deleted or deleted and
//     recreated, is refused before either policy is read. It still
//     authenticates, but nothing else is meant to succeed for it, and a
//     trust policy naming every principal would otherwise let it mint fresh
//     credentials and outlive the deletion of its role.
//   - A Deny on either side ends it.
//   - A trust Allow naming the caller's user ARN, its session ARN, or every
//     principal is sufficient alone.
//   - A trust Allow naming the role a calling session assumed needs no
//     identity-policy Allow, but the session's session policy, if any, must
//     allow the action too.
//   - A trust Allow naming the account requires the caller's identity
//     policies to allow sts:AssumeRole on the role, and likewise the session
//     policy.
//
// externalID and roleSessionName are the request's own values, visible to
// both sides as sts:ExternalId and sts:RoleSessionName.
func AuthorizeAssumeRole(ctx fiber.Ctx, identity types.Identity, role *types.Role, externalID, roleSessionName string) bool {
	// identity.Role is set for a session only while the role it was minted
	// against still exists.
	if identity.Session != nil && identity.Role == nil {
		return false
	}

	condCtx := requestConditionContext(ctx, identity, "AssumeRole", role.Tags)
	condCtx["sts:RoleSessionName"] = []string{roleSessionName}
	if externalID != "" {
		condCtx["sts:ExternalId"] = []string{externalID}
	}

	trust := policy.EvaluateAssumeRoleTrust(role.AssumeRolePolicyDocument, assumeRoleCaller(identity), condCtx)
	if trust == policy.TrustDenied {
		return false
	}

	identityDecision, sessionDecision, hasSessionPolicy := AuthorizeSplit(identity, policy.RequestContext{
		Action:    policy.AssumeRoleAction,
		Resource:  role.Arn,
		Condition: condCtx,
	})
	if identityDecision == policy.DecisionDeny || sessionDecision == policy.DecisionDeny {
		return false
	}
	sessionAllows := !hasSessionPolicy || sessionDecision == policy.DecisionAllow

	switch trust {
	case policy.TrustDirect:
		return true
	case policy.TrustRole:
		return sessionAllows
	case policy.TrustAccount:
		return identityDecision == policy.DecisionAllow && sessionAllows
	default:
		return false
	}
}

// assumeRoleCaller describes identity in the forms a trust policy's AWS
// principal can name. AuthorizeAssumeRole has already refused a session that
// outlived its role. Checking identity.Role again here still keeps such a
// session from being named by its old ARNs, so it can never pick up trust
// granted to a later role of the same name.
func assumeRoleCaller(identity types.Identity) policy.AssumeRoleCaller {
	caller := policy.AssumeRoleCaller{AccountID: iamutil.DefaultAccountID}
	switch {
	case identity.User != nil:
		caller.UserArn = identity.User.Arn
	case identity.Session != nil && identity.Role != nil:
		caller.RoleArn = identity.Role.Arn
		caller.SessionArn = CallerArn(identity)
	}
	return caller
}
