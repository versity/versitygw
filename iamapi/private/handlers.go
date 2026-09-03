// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package private

import (
	"encoding/json"
	"maps"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/policy"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/sigv4auth"
)

// handleVersion reports what this build speaks. It is root-signed like every
// other endpoint here, which is what lets the gateway's startup probe verify
// its own credential and its mTLS transport in the same round trip that
// verifies the protocol — a rotated gateway credential is a far more common
// misconfiguration than a version skew, and an unauthenticated probe would
// report success right through one.
func (p *PrivateAPI) handleVersion(ctx fiber.Ctx) error {
	return ctx.JSON(VersionResponse{
		Protocol:      ProtocolVersion,
		MinClient:     MinClientProtocol,
		ServerVersion: p.serverVersion,
		AccountID:     iamutil.DefaultAccountID,
	})
}

func (p *PrivateAPI) handleDeriveSigningKey(ctx fiber.Ctx) error {
	var req DeriveSigningKeyRequest
	if err := json.Unmarshal(ctx.Body(), &req); err != nil {
		return errMalformedRequestBody
	}

	identity, secret, err := resolvePrivateIdentity(ctx.Context(), p.store, req.AccessKeyID, req.SessionToken)
	if err != nil {
		return mapResolveError(err)
	}

	derivedKey := sigv4auth.DeriveKey(secret, req.Date, req.Region, req.Service)

	resp := DeriveSigningKeyResponse{
		DerivedKey:   derivedKey,
		PrincipalArn: iammiddleware.CallerArn(*identity),
	}
	// The role ARN comes from the session rather than from the role the
	// store holds now: a session outliving its role keeps authenticating,
	// and it still belongs to the role it was minted against.
	if identity.Session != nil {
		resp.RoleArn = identity.Session.RoleArn
	}

	return ctx.JSON(resp)
}

// recordDataPlaneUsage records this S3 request as a use of the credential
// that made it — an access key's GetAccessKeyLastUsed metadata, a session's
// role's RoleLastUsed, or both for a session (its role is what AWS reports,
// and a session has no long-term key of its own). It is the data-plane
// counterpart of what iammiddleware.VerifyIAMAuth records for the IAM/STS
// control plane, and is deliberately here rather than on derive-signing-key:
// this endpoint is only reached once the gateway has verified the request's
// signature, so an unauthenticated caller who merely knows an access key id
// cannot refresh — or, since it would supply the credential scope, poison —
// another identity's last-used record.
//
// Everything about it is best-effort: failures are logged and dropped, and a
// gateway too old to send Region/Service records nothing at all rather than
// storing a blank service or region.
func (p *PrivateAPI) recordDataPlaneUsage(ctx fiber.Ctx, identity types.Identity, req EvaluatePolicyRequest) {
	if req.Region == "" || req.Service == "" {
		return
	}

	now := time.Now().UTC()
	if identity.User != nil {
		if err := p.store.RecordAccessKeyUsage(ctx.Context(), req.AccessKeyID, req.Service, req.Region, now); err != nil {
			debuglogger.Logf("failed to record access key last-used metadata for %q: %v", req.AccessKeyID, err)
		}
	}
	// identity.Role is set only when the session's role still exists and is
	// still the one the session was minted against, so a session outliving
	// its role records nothing rather than attributing its use to a
	// same-named replacement — same rule as the control plane.
	if identity.Role != nil {
		if err := p.store.RecordRoleUsage(ctx.Context(), identity.Role.RoleName, req.Region, now); err != nil {
			debuglogger.Logf("failed to record role last-used metadata for %q: %v", identity.Role.RoleName, err)
		}
	}
}

// handleResolveIdentity answers "does this access key exist, and what
// principal is it" for a batch of access key ids, returning no credential
// material at all — see ResolveIdentityResponse for why that is what makes
// answering for a session, with no session token, safe.
func (p *PrivateAPI) handleResolveIdentity(ctx fiber.Ctx) error {
	var req ResolveIdentityRequest
	if err := json.Unmarshal(ctx.Body(), &req); err != nil {
		return errMalformedRequestBody
	}

	resolved := resolveIdentityMetadata(ctx.Context(), p.store, req.AccessKeyIDs)

	identities := make([]ResolvedIdentity, len(resolved))
	for i, r := range resolved {
		if !r.Found {
			continue
		}
		identities[i] = ResolvedIdentity{
			Found:        true,
			Kind:         identityKindWireValue(r.Kind),
			PrincipalArn: r.PrincipalArn,
		}
	}

	return ctx.JSON(ResolveIdentityResponse{Identities: identities})
}

// handleResolvePrincipals answers, for each string a bucket policy names as
// a Principal, whether it resolves to something that exists — reporting only
// the ones that do not, so a valid policy's principals disclose nothing.
func (p *PrivateAPI) handleResolvePrincipals(ctx fiber.Ctx) error {
	var req ResolvePrincipalsRequest
	if err := json.Unmarshal(ctx.Body(), &req); err != nil {
		return errMalformedRequestBody
	}

	invalid := []string{}
	for _, principal := range req.Principals {
		resolves, err := principalResolves(ctx.Context(), p.store, iamutil.DefaultAccountID, principal)
		if err != nil {
			// A store fault, not a verdict on the principal — errorHandler
			// renders it as a 500 so the gateway reports the service as
			// broken rather than the policy as malformed.
			return err
		}
		if !resolves {
			invalid = append(invalid, principal)
		}
	}

	return ctx.JSON(ResolvePrincipalsResponse{Invalid: invalid})
}

// identityKindWireValue converts identityKind to its wire representation.
func identityKindWireValue(k identityKind) string {
	if k == identityKindSession {
		return KindSession
	}
	return KindUser
}

func (p *PrivateAPI) handleEvaluatePolicy(ctx fiber.Ctx) error {
	var req EvaluatePolicyRequest
	if err := json.Unmarshal(ctx.Body(), &req); err != nil {
		return errMalformedRequestBody
	}

	identity, _, err := resolvePrivateIdentity(ctx.Context(), p.store, req.AccessKeyID, req.SessionToken)
	if err != nil {
		return mapResolveError(err)
	}

	p.recordDataPlaneUsage(ctx, *identity, req)

	condition := conditionContextFor(*identity, req.Condition)

	decisions := make([][]string, len(req.Resources))
	sessionDecisions := make([][]string, len(req.Resources))
	hasSessionPolicy := false

	for i, resource := range req.Resources {
		perAction := make([]string, len(req.Actions))
		perActionSession := make([]string, len(req.Actions))
		for j, action := range req.Actions {
			identityDecision, sessionDecision, hasSession := iammiddleware.AuthorizeSplit(*identity, policy.RequestContext{
				Action:    action,
				Resource:  resource,
				Condition: condition,
			})
			perAction[j] = decisionWireValue(identityDecision)
			perActionSession[j] = decisionWireValue(sessionDecision)
			hasSessionPolicy = hasSession
		}
		decisions[i] = perAction
		sessionDecisions[i] = perActionSession
	}

	resp := EvaluatePolicyResponse{
		Decisions:    decisions,
		PrincipalArn: iammiddleware.CallerArn(*identity),
	}
	if hasSessionPolicy {
		resp.HasSessionPolicy = true
		resp.SessionDecisions = sessionDecisions
	}

	return ctx.JSON(resp)
}

// conditionContextFor combines the request-derived condition keys the S3
// gateway observed (source IP, time, transport) with the identity-derived
// keys only this service can know (aws:PrincipalArn, aws:username, …).
//
// Every key in an identity or resource namespace is dropped from the
// gateway's contribution first, then this side's own values are laid over
// the remainder. Filtering rather than merging matters: an
// override-on-collision merge would leave any key this service happens
// *not* to set — aws:PrincipalTag/x for an untagged role, say — under the
// gateway's control, which is precisely what a StringNotEquals-guarded
// Allow keys off. The gateway authenticates as root, so this is defense in
// depth rather than a trust boundary, but the layering costs nothing.
func conditionContextFor(identity types.Identity, requestKeys map[string][]string) map[string][]string {
	condition := make(map[string][]string, len(requestKeys))
	for k, v := range requestKeys {
		if isIdentityConditionKey(k) {
			continue
		}
		condition[k] = v
	}
	maps.Copy(condition, iammiddleware.IdentityConditionContext(identity))
	return condition
}

// isIdentityConditionKey reports whether key names the caller or the
// resource, and so may only be set by this service. Matching is
// case-insensitive because policy condition-key lookup is
// (iamapi/policy.lookupContextValues) — a caller must not be able to smuggle
// "AWS:PrincipalArn" past a case-sensitive filter.
func isIdentityConditionKey(key string) bool {
	for _, prefix := range iammiddleware.IdentityConditionKeyPrefixes {
		if strings.EqualFold(key, prefix) ||
			(strings.HasSuffix(prefix, "/") && len(key) > len(prefix) && strings.EqualFold(key[:len(prefix)], prefix)) {
			return true
		}
	}
	return false
}

// decisionWireValue converts policy.Decision to its wire representation.
func decisionWireValue(d policy.Decision) string {
	switch d {
	case policy.DecisionAllow:
		return DecisionAllow
	case policy.DecisionDeny:
		return DecisionDeny
	default:
		return DecisionNoMatch
	}
}
