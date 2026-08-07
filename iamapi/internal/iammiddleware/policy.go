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
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/policy"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/httpctx"
)

// iamActionPrefix is the policy-action vendor prefix for every action this
// middleware evaluates. It's only ever wired into the "iam" service
// pipeline — GetCallerIdentity and AssumeRoleWithWebIdentity
// (the two "sts" actions sharing this endpoint) never reach it, matching
// real AWS where sts:GetCallerIdentity requires no identity-based policy
// grant at all and AssumeRoleWithWebIdentity has no identity yet to check.
const iamActionPrefix = "iam:"

// VerifyIAMPolicy authorizes an IAM action against the caller identity
// VerifyIAMAuth already resolved and stored via
// httpctx.ContextKeyCallerIdentity. Root bypasses this entirely.
// A long-term user is authorized by its own inline policies.
// A session is authorized by its assumed role's inline policies,
// additionally filtered by its own session policy if one was supplied — the
// session policy can only narrow, never widen, what the role otherwise
// allows: Effective permissions = Role identity-based permissions ∩ Session
// policy permissions.
//
// Authorization is evaluated as a full request context — action, resource,
// and condition — rather than action alone: store resolves the actual
// target resource's ARN (for actions naming an existing user/role/OIDC
// provider) so a Resource-scoped statement only grants what it names, and
// requestConditionContext supplies the request's aws:SourceIp/aws:username/
// aws:PrincipalArn/aws:CurrentTime/aws:EpochTime values for a statement's
// Condition block.
func VerifyIAMPolicy(store IdentityStore) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		identity, _ := httpctx.ContextKeyCallerIdentity.Get(ctx).(types.Identity)
		if identity.IsRoot {
			return nil
		}

		action, _ := iamutil.RequestParam(ctx, "Action")
		fullAction := iamActionPrefix + action

		resourceArn, resourceTags := resourceForAction(ctx, store, action)
		reqCtx := policy.RequestContext{
			Action:    fullAction,
			Resource:  resourceArn,
			Condition: requestConditionContext(ctx, identity, action, resourceTags),
		}

		if !authorizeRequest(identity, reqCtx) {
			return iamerr.AccessDeniedIAMAction(callerArn(identity), fullAction)
		}

		// A rename/path-move is a two-resource transition: AWS's UpdateUser
		// docs require permission on both the source object (checked above,
		// via UserName) and the target object the user is being moved to.
		if action == "UpdateUser" {
			if target := updateUserTargetResource(ctx, store); target != "" {
				targetCtx := reqCtx
				targetCtx.Resource = target
				if !authorizeRequest(identity, targetCtx) {
					return iamerr.AccessDeniedIAMAction(callerArn(identity), fullAction)
				}
			}
		}

		return nil
	}
}

// authorizeRequest reports whether reqCtx is allowed by identity's own
// inline policies and, for a session with a session policy attached, the
// narrowing session policy as well.
func authorizeRequest(identity types.Identity, reqCtx policy.RequestContext) bool {
	if !policy.EvaluateIdentityPolicies(identity.IdentityPolicies, reqCtx) {
		return false
	}
	if identity.Session != nil && identity.SessionPolicy != "" {
		sessionPolicy := []types.PolicyEntry{{PolicyDocument: identity.SessionPolicy}}
		if !policy.EvaluateIdentityPolicies(sessionPolicy, reqCtx) {
			return false
		}
	}
	return true
}

// resourceForAction resolves the ARN action targets and, when that ARN names
// an existing resource, the tags currently stored on it
// — matching AWS's resource-type classification for each IAM API: a List
// action (or any action this doesn't specifically recognize) has no
// resource-level permissions and always evaluates against "*"; an action
// creating a new user/role/OIDC provider evaluates against the
// about-to-be-created resource's ARN, built from the request's own
// Path/Name parameters exactly as the corresponding controller method
// builds it, with no tags (the resource doesn't exist yet — aws:RequestTag
// is the applicable key for a Create action, see addRequestTagContext); an
// action naming an existing user/role by name evaluates against that
// entity's real, currently-stored Arn and Tags (resolved via store, since a
// custom Path means the caller-supplied name alone doesn't determine the
// ARN); an OIDC provider action already carries the exact target ARN as a
// request parameter, and its Tags are resolved via a single store lookup
// alongside it.
//
// A lookup failure (unknown name, or the request simply omits it) resolves
// to ("", nil), which only a wildcard Resource statement matches — the
// request still reaches the controller afterward, which reports the
// specific NoSuchEntity/MissingValue error if authorization happens to pass
// on a wildcard grant, or AccessDenied first if it doesn't.
func resourceForAction(ctx fiber.Ctx, store IdentityStore, action string) (string, []types.Tag) {
	switch action {
	case "CreateUser":
		return newUserResource(ctx), nil
	case "GetUser":
		return getUserResource(ctx, store)
	case "DeleteUser", "UpdateUser", "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey",
		"ListAccessKeys", "PutUserPolicy", "GetUserPolicy", "DeleteUserPolicy", "ListUserPolicies":
		return existingUserResource(ctx, store)
	case "GetAccessKeyLastUsed":
		return accessKeyOwnerResource(ctx, store)
	case "CreateRole":
		return newRoleResource(ctx), nil
	case "GetRole", "DeleteRole", "UpdateAssumeRolePolicy", "PutRolePolicy", "GetRolePolicy", "DeleteRolePolicy", "ListRolePolicies":
		return existingRoleResource(ctx, store)
	case "CreateOpenIDConnectProvider":
		return newOIDCProviderResource(ctx), nil
	case "GetOpenIDConnectProvider", "DeleteOpenIDConnectProvider", "AddClientIDToOpenIDConnectProvider",
		"RemoveClientIDFromOpenIDConnectProvider", "UpdateOpenIDConnectProviderThumbprint":
		arn, _ := iamutil.RequestParam(ctx, "OpenIDConnectProviderArn")
		if arn == "" {
			return "", nil
		}
		provider, err := store.GetOIDCProvider(ctx.Context(), arn)
		if err != nil {
			return arn, nil
		}
		return arn, provider.Tags
	default:
		return "*", nil
	}
}

func newUserResource(ctx fiber.Ctx) string {
	userName, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok || userName == "" {
		return "*"
	}
	path, ok := iamutil.RequestParam(ctx, "Path")
	if !ok || path == "" {
		path = iamutil.DefaultUserPath
	}
	return iamutil.BuildUserArn(iamutil.DefaultAccountID, path, userName)
}

// existingUserResource resolves UserName to its stored Arn and Tags. An
// empty UserName resolves to ("", nil), the same lookup-failure fallback
// used elsewhere — none of this group's actions actually accept an omitted
// UserName (the controller layer requires it), so this only guards against
// a malformed request reaching here.
func existingUserResource(ctx fiber.Ctx, store IdentityStore) (string, []types.Tag) {
	userName, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok || userName == "" {
		return "", nil
	}
	user, err := store.GetUser(ctx.Context(), userName)
	if err != nil {
		return "", nil
	}
	return user.Arn, user.Tags
}

// getUserResource resolves GetUser's target: the named user's stored Arn and
// Tags, or — when UserName is omitted, matching the controller's (and real
// IAM's) "look up the caller's own identity" behavior — the calling user's
// own Arn and Tags. A session (assumed role) has no self IAM user to
// resolve, so it falls back to ("", nil), the same lookup-failure fallback
// used elsewhere.
func getUserResource(ctx fiber.Ctx, store IdentityStore) (string, []types.Tag) {
	userName, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok || userName == "" {
		identity, _ := httpctx.ContextKeyCallerIdentity.Get(ctx).(types.Identity)
		if identity.User != nil {
			return identity.User.Arn, identity.User.Tags
		}
		return "", nil
	}
	user, err := store.GetUser(ctx.Context(), userName)
	if err != nil {
		return "", nil
	}
	return user.Arn, user.Tags
}

// accessKeyOwnerResource resolves GetAccessKeyLastUsed's target: unlike the
// rest of this group, the request carries no UserName at all, only the
// AccessKeyId being queried, so the resource-level check is against the IAM
// user that owns that key, matching real IAM's resource-type classification
// for this action.
func accessKeyOwnerResource(ctx fiber.Ctx, store IdentityStore) (string, []types.Tag) {
	accessKeyID, ok := iamutil.RequestParam(ctx, "AccessKeyId")
	if !ok || accessKeyID == "" {
		return "", nil
	}
	user, err := store.GetUserByAccessKeyID(ctx.Context(), accessKeyID)
	if err != nil {
		return "", nil
	}
	return user.Arn, user.Tags
}

// updateUserTargetResource resolves the destination ARN an UpdateUser
// request would relocate UserName to, so the caller for a rename/path-move
// can be required to hold permission on the target object as well as the
// source (matching the UpdateUser API's documented requirement). It returns
// "" when the request doesn't actually relocate the user (neither NewPath
// nor NewUserName supplied) or when the source user can't be resolved, the
// same fallback used elsewhere when a lookup fails.
func updateUserTargetResource(ctx fiber.Ctx, store IdentityStore) string {
	newPath, _ := iamutil.RequestParam(ctx, "NewPath")
	newUserName, _ := iamutil.RequestParam(ctx, "NewUserName")
	if newPath == "" && newUserName == "" {
		return ""
	}
	userName, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok || userName == "" {
		return ""
	}
	user, err := store.GetUser(ctx.Context(), userName)
	if err != nil {
		return ""
	}
	finalPath := user.Path
	if newPath != "" {
		finalPath = newPath
	}
	finalUserName := user.UserName
	if newUserName != "" {
		finalUserName = newUserName
	}
	return iamutil.BuildUserArn(iamutil.DefaultAccountID, finalPath, finalUserName)
}

func newRoleResource(ctx fiber.Ctx) string {
	roleName, ok := iamutil.RequestParam(ctx, "RoleName")
	if !ok || roleName == "" {
		return "*"
	}
	path, ok := iamutil.RequestParam(ctx, "Path")
	if !ok || path == "" {
		path = iamutil.DefaultUserPath
	}
	return iamutil.BuildRoleArn(iamutil.DefaultAccountID, path, roleName)
}

func existingRoleResource(ctx fiber.Ctx, store IdentityStore) (string, []types.Tag) {
	roleName, ok := iamutil.RequestParam(ctx, "RoleName")
	if !ok || roleName == "" {
		return "*", nil
	}
	role, err := store.GetRole(ctx.Context(), roleName)
	if err != nil {
		return "", nil
	}
	return role.Arn, role.Tags
}

func newOIDCProviderResource(ctx fiber.Ctx) string {
	rawURL, ok := iamutil.RequestParam(ctx, "Url")
	if !ok || rawURL == "" {
		return "*"
	}
	url, err := iamutil.ValidateOIDCProviderURL(rawURL)
	if err != nil {
		return ""
	}
	return iamutil.BuildOIDCProviderArn(iamutil.DefaultAccountID, url)
}

// requestConditionContext builds the "aws:<GlobalKey>"-keyed context a
// statement's Condition block is evaluated against: aws:CurrentTime and
// aws:EpochTime (the request's evaluation time, always available - needed
// for Date/Numeric time-based conditions to be usable at all), aws:SourceIp
// (the caller's address), aws:SecureTransport (whether the connection is
// TLS - AWS documents this key as present on every request, not just TLS
// ones), and — for a non-root identity — aws:PrincipalArn, aws:PrincipalAccount
// (this gateway is single-account, so it's always DefaultAccountID), and
// aws:userid together with, for a long-term user only, aws:username (AWS
// sets both simultaneously for an IAM user principal; a session has no
// aws:username, only aws:userid in IAM's own "<RoleID>:<RoleSessionName>"
// form). For the three actions that accept a Tags parameter at creation
// time, aws:RequestTag/<key> (one per supplied tag) and aws:TagKeys (every
// supplied key) are populated the same way the controller itself parses
// Tags, so a tag-scoped Condition is enforceable against the resource about
// to be created.
//
// resourceTags are the tags currently stored on the resource
// resourceForAction resolved, if any — populated as both iam:ResourceTag/<key>
// (IAM's own documented resource-tag key) and aws:ResourceTag/<key> (the
// generic cross-service key AWS also exposes for a tagged resource), so a
// Condition written against either form sees the resource's real tags
// instead of always evaluating as absent. aws:PrincipalTag/<key> is
// populated from the caller's own tags: the User's, for a long-term user, or
// the assumed Role's, for a session (AWS's own behavior when no session
// tags were supplied at AssumeRole time — this gateway has no session-tag
// parameter, so the role's tags are the session's tags for its whole
// lifetime).
func requestConditionContext(ctx fiber.Ctx, identity types.Identity, action string, resourceTags []types.Tag) map[string][]string {
	condCtx := map[string][]string{}
	now := time.Now().UTC()
	condCtx["aws:CurrentTime"] = []string{now.Format(time.RFC3339)}
	condCtx["aws:EpochTime"] = []string{strconv.FormatInt(now.Unix(), 10)}
	condCtx["aws:SecureTransport"] = []string{strconv.FormatBool(ctx.Secure())}
	if ip := ctx.IP(); ip != "" {
		condCtx["aws:SourceIp"] = []string{ip}
	}
	if arn := callerArn(identity); arn != "" {
		condCtx["aws:PrincipalArn"] = []string{arn}
		condCtx["aws:PrincipalAccount"] = []string{iamutil.DefaultAccountID}
	}
	switch {
	case identity.User != nil:
		condCtx["aws:username"] = []string{identity.User.UserName}
		condCtx["aws:userid"] = []string{identity.User.UserID}
		addPrincipalTagContext(condCtx, identity.User.Tags)
	case identity.Session != nil:
		condCtx["aws:userid"] = []string{identity.Session.RoleID + ":" + identity.Session.RoleSessionName}
		if identity.Role != nil {
			addPrincipalTagContext(condCtx, identity.Role.Tags)
		}
	}

	for _, tag := range resourceTags {
		condCtx["iam:ResourceTag/"+tag.Key] = []string{tag.Value}
		condCtx["aws:ResourceTag/"+tag.Key] = []string{tag.Value}
	}

	switch action {
	case "CreateUser", "CreateRole", "CreateOpenIDConnectProvider":
		addRequestTagContext(condCtx, ctx)
	}

	return condCtx
}

// addPrincipalTagContext populates aws:PrincipalTag/<key> from tags, the
// calling principal's own tags.
func addPrincipalTagContext(condCtx map[string][]string, tags []types.Tag) {
	for _, tag := range tags {
		condCtx["aws:PrincipalTag/"+tag.Key] = []string{tag.Value}
	}
}

// addRequestTagContext populates aws:RequestTag/<key> and aws:TagKeys from
// the request's Tags parameter, parsed the same way the controller parses it
// for the actual create call. A parse failure (e.g. a malformed tag) is left
// unpopulated rather than surfaced here — the controller performs the same
// parse independently and will reject the request with the specific
// tag-validation error afterward, so no create can succeed with tags that
// silently evaded a tag-scoped Condition.
func addRequestTagContext(condCtx map[string][]string, ctx fiber.Ctx) {
	tags, err := iamutil.ParseTags(ctx)
	if err != nil || len(tags) == 0 {
		return
	}
	keys := make([]string, 0, len(tags))
	for _, tag := range tags {
		condCtx["aws:RequestTag/"+tag.Key] = []string{tag.Value}
		keys = append(keys, tag.Key)
	}
	condCtx["aws:TagKeys"] = keys
}

// callerArn identifies identity the way real IAM error messages do: the
// user's own Arn, or the assumed-role session Arn.
func callerArn(identity types.Identity) string {
	if identity.Session != nil {
		return iamutil.BuildAssumedRoleArn(iamutil.DefaultAccountID, identity.Session.RoleName, identity.Session.RoleSessionName)
	}
	if identity.User != nil {
		return identity.User.Arn
	}
	return ""
}
