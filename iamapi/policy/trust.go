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

package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/internal/condition"
)

// trustPrincipalKeys are the only keys IAM accepts inside a trust policy
// statement's Principal object. CanonicalUser is deliberately not accepted
// since it identifies an S3 canonical user id, the legacy S3 user
// identifier, which is not planned to be supported here.
var trustPrincipalKeys = map[string]bool{
	"AWS":       true,
	"Service":   true,
	"Federated": true,
}

const cognitoFederatedProvider = "cognito-identity.amazonaws.com"

// azureSentinelProviderURL is Microsoft Sentinel's registered OIDC provider
// Url (scheme stripped) — a shared provider like the ones in
// sharedOIDCProviderRequiredClaim, but its required identity-provider
// control is not a claim on the token at all: AWS requires the trust
// statement's Condition to scope sts:RoleSessionName (a global STS
// condition key, see policy.go's requestConditionContext and
// webidentity.go's WebIdentityContext.RoleSessionName) instead of a
// "<url>:<claim>" key, so it's handled as its own case in
// validateSharedProviderTenancy rather than fitting the shared map.
const azureSentinelProviderURL = "sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d"

// azureSentinelRequiredKey is the condition key azureSentinelProviderURL's
// trust statements must scope.
const azureSentinelRequiredKey = "sts:RoleSessionName"

// oidcProviderArnInfix is the fixed separator between the account segment
// and the provider Url in an OIDC provider ARN, matching
// iamutil.BuildOIDCProviderArn's "arn:aws:iam::<account>:oidc-provider/<url>"
// shape (this package can't import iamutil to reuse its ARN parser: iamutil
// already imports policy).
const oidcProviderArnInfix = ":oidc-provider/"

// sharedOIDCProviderRequiredClaim maps a known shared-audience OIDC issuer's
// hostname (a registered provider's Url, scheme already stripped) to the
// claim suffix a trust statement federating it must scope with a Condition.
// AWS added this requirement for popular CI/CD OIDC issuers because their
// audience is commonly left at a single shared, non-secret default (e.g.
// "sts.amazonaws.com"): unlike a private or self-hosted provider, whose Url
// alone is already tenant-specific, the audience here doesn't distinguish
// one organization's/repo's token from any other's identically-configured
// one, so the trust policy must scope its tenancy claim itself.
//
// Sourced from AWS's own published table of shared OIDC providers and their
// required claims:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html
// Amazon Cognito and Microsoft Sentinel are handled as
// their own special cases in validateSharedProviderTenancy rather than this
// map: Cognito's federated-principal value isn't an OIDC provider ARN at
// all, and Sentinel's required control is a global STS key, not a claim.
// IBM Turbonomic SaaS is a documented shared provider too, but AWS's own
// table declines to give it a fixed Url ("periodically updates their OIDC
// Issuer URL with new versions of the platform") — there is no stable
// hostname to key a map entry on, so it's deliberately omitted here.
var sharedOIDCProviderRequiredClaim = map[string]string{
	"token.actions.githubusercontent.com":                "sub", // GitHub Actions
	"vstoken.actions.githubusercontent.com":              "sub", // GitHub vstoken
	"oidc-configuration.audit-log.githubusercontent.com": "sub", // GitHub audit log streaming
	"gitlab.com":              "sub", // GitLab.com (SaaS)
	"agent.buildkite.com":     "sub", // Buildkite
	"app.terraform.io":        "sub", // HCP Terraform / Terraform Cloud
	"oidc.codefresh.io":       "sub", // Codefresh SaaS
	"studio.datachain.ai/api": "sub", // DVC Studio
	"scalr.io":                "sub", // Scalr
	"tokens.cloud.shisho.dev": "sub", // Shisho Cloud
	"proidc.upbound.io":       "sub", // Upbound
	"api.pulumi.com/oidc":     "aud", // Pulumi Cloud
	"sandboxes.cloud":         "aud", // sandboxes.cloud
	"oidc.vercel.com":         "aud", // Vercel global endpoint
}

// validServicePrincipals are the only Service principal values the gateway
// recognizes. Real AWS validates Service against its live catalog of
// ~300+ service principals; the gateway only exposes S3, STS, and IAM
// APIs, so those are the only services that could plausibly ever assume a
// role here.
var validServicePrincipals = map[string]bool{
	"s3.amazonaws.com":  true,
	"sts.amazonaws.com": true,
	"iam.amazonaws.com": true,
}

// MaxTrustPolicyBytes is IAM's ACLSizePerRole quota: a role has exactly one
// trust policy, so unlike inline identity policies (which sum across all of
// a user's/role's named policies) this is a plain length check against the
// single AssumeRolePolicyDocument/PolicyDocument value.
const MaxTrustPolicyBytes = 2048

var (
	errTrustInvalidJSON              = iamerr.MalformedPolicyDocument("This policy contains invalid Json")
	errTrustInvalidVersion           = iamerr.MalformedPolicyDocument("The policy must contain a valid version string")
	errTrustEmptyStatement           = iamerr.MalformedPolicyDocument("Could not parse the policy: Statement is empty!")
	errTrustDuplicateSid             = iamerr.MalformedPolicyDocument("The Statement Ids in the policy are not unique")
	errTrustMissingEffect            = iamerr.MalformedPolicyDocument("Missing required field Effect")
	errTrustMissingPrincipal         = iamerr.MalformedPolicyDocument("Missing required field Principal")
	errTrustEmptyPrincipal           = iamerr.MalformedPolicyDocument("Missing required field Principal cannot be empty!")
	errTrustPrincipalNotObject       = iamerr.MalformedPolicyDocument("Principal must be a JSON object.")
	errTrustAllowNotPrincipal        = iamerr.MalformedPolicyDocument("Allow with NotPrincipal is not allowed.")
	errTrustNotPrincipalForbidden    = iamerr.MalformedPolicyDocument("AssumeRole policy must not contain NotPrincipal field.")
	errTrustMissingAction            = iamerr.MalformedPolicyDocument("Missing required field Action")
	errTrustNonSTSAction             = iamerr.MalformedPolicyDocument("AssumeRole policy may only specify STS AssumeRole actions.")
	errTrustResourceForbidden        = iamerr.MalformedPolicyDocument("Has prohibited field Resource")
	errTrustNotResourceForbidden     = iamerr.MalformedPolicyDocument("AssumeRole policy must not contain resources.")
	errTrustCognitoConditionRequired = iamerr.MalformedPolicyDocument("A condition block must be present for the Cognito provider")
	errTrustSyntax                   = iamerr.MalformedPolicyDocument("Syntax error in policy.")
)

// ParseTrust parses raw as an IAM role trust-policy document (the value of
// AssumeRolePolicyDocument / UpdateAssumeRolePolicy's PolicyDocument) and
// checks it against trust-policy grammar: Principal is required (the
// opposite of an identity policy), Action/NotAction values must carry the
// "sts:" prefix, and Resource/NotResource are forbidden.
func ParseTrust(raw string) error {
	var doc Document
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return errTrustInvalidJSON
	}
	return doc.ValidateTrust()
}

// ValidateTrust checks d against IAM's trust-policy document grammar: a
// valid Version if present, a non-empty Statement (single object or
// array), document-wide unique Sids, and per statement, the rules enforced
// by Statement.ValidateTrust.
func (d Document) ValidateTrust() error {
	if d.Version != "" && d.Version != Version2008 && d.Version != Version2012 {
		return errTrustInvalidVersion
	}
	if len(d.Statement) == 0 {
		return errTrustEmptyStatement
	}

	seenSids := make(map[string]struct{}, len(d.Statement))
	for _, stmt := range d.Statement {
		if err := stmt.ValidateTrust(); err != nil {
			return err
		}
		if stmt.Sid != "" {
			if _, ok := seenSids[stmt.Sid]; ok {
				return errTrustDuplicateSid
			}
			seenSids[stmt.Sid] = struct{}{}
		}
	}

	return nil
}

// ValidateTrust checks s against IAM trust-policy statement grammar: a
// valid Effect, a required Principal (never NotPrincipal), an Action or
// NotAction with only "sts:"-prefixed values, no Resource/NotResource, and -
// if present - a Condition block whose operators are all recognized (see
// condition.ShapeValid, shared with the identity-policy side; condition
// *keys* and operand *values* are deliberately not validated here, matching
// AWS behavior).
func (s Statement) ValidateTrust() error {
	switch s.Effect {
	case "Allow", "Deny":
	case "":
		return errTrustMissingEffect
	default:
		return iamerr.MalformedPolicyDocument(fmt.Sprintf("Invalid effect: %s", s.Effect))
	}

	if len(s.NotPrincipal) > 0 {
		if s.Effect == "Allow" {
			return errTrustAllowNotPrincipal
		}
		return errTrustNotPrincipalForbidden
	}
	if err := s.validateTrustPrincipal(); err != nil {
		return err
	}

	if !condition.ShapeValid(s.Condition) {
		return errTrustSyntax
	}

	if len(s.Action) > 0 && len(s.NotAction) > 0 {
		// Same exclusivity identity policies already enforce (Statement.Validate):
		// AWS documents Action and NotAction as mutually exclusive within a
		// single statement, and real policy simulation rejects a document
		// combining them with InvalidInput  - a trust statement isn't
		// exempt just because its evaluator (statementCoversAction) happens
		// to have well-defined single-field behavior.
		return errTrustSyntax
	}
	if len(s.Action) == 0 && len(s.NotAction) == 0 {
		return errTrustMissingAction
	}
	for _, action := range s.Action {
		if !strings.HasPrefix(action, "sts:") {
			return errTrustNonSTSAction
		}
	}
	for _, action := range s.NotAction {
		if !strings.HasPrefix(action, "sts:") {
			return errTrustNonSTSAction
		}
	}

	if len(s.Resource) > 0 {
		return errTrustResourceForbidden
	}
	if len(s.NotResource) > 0 {
		return errTrustNotResourceForbidden
	}

	return nil
}

// validateTrustPrincipal checks s.Principal against trust-policy grammar:
// required, a JSON object (not a bare string or array), non-empty, with
// only AWS/Service/Federated keys, plus the Cognito-specific Condition
// requirement. Real AWS additionally validates that AWS/Service values
// resolve to real accounts/services against its live catalog; the gateway
// has no such catalog for AWS account/ARN values and validates those shape
// only. Service values are the exception — they're checked against
// validServicePrincipals, since the gateway only exposes S3, STS, and IAM
// APIs and so only those services could ever assume a role here.
func (s Statement) validateTrustPrincipal() error {
	raw := s.Principal
	if len(raw) == 0 {
		return errTrustMissingPrincipal
	}

	var principal map[string]StringOrSlice
	if err := json.Unmarshal(raw, &principal); err != nil {
		var asString string
		if err := json.Unmarshal(raw, &asString); err == nil {
			return errTrustPrincipalNotObject
		}
		return errTrustSyntax
	}

	if len(principal) == 0 {
		return errTrustEmptyPrincipal
	}

	for key, values := range principal {
		if !trustPrincipalKeys[key] {
			return iamerr.MalformedPolicyDocument(fmt.Sprintf("Invalid principal in policy: %q", key))
		}
		if key == "Service" {
			for _, v := range values {
				if !validServicePrincipals[v] {
					return iamerr.MalformedPolicyDocument(fmt.Sprintf("Invalid principal in policy: %q:%q", strings.ToUpper(key), v))
				}
			}
		}
	}

	return validateSharedProviderTenancy(s, principal["Federated"])
}

// validateSharedProviderTenancy rejects a trust statement that federates a
// known shared-audience provider (Cognito Identity Pools, or a registered
// OIDC provider whose Url is in sharedOIDCProviderRequiredClaim) without a
// Condition that scopes the provider's tenant-identifying claim to a
// specific, non-wildcard value — see sharedOIDCProviderRequiredClaim's
// doc comment for why the audience alone isn't enough for these providers.
// A Federated value that doesn't match either shape (a private/self-hosted
// OIDC provider, or a value too malformed to resolve to a real provider at
// all) imposes no extra requirement here; those are unaffected by this
// check.
func validateSharedProviderTenancy(s Statement, federated []string) error {
	for _, v := range federated {
		if v == cognitoFederatedProvider {
			if !conditionScopesClaim(s.Condition, cognitoFederatedProvider+":aud") {
				return errTrustCognitoConditionRequired
			}
			continue
		}

		url, ok := oidcProviderURLFromFederatedArn(v)
		if !ok {
			continue
		}

		if url == azureSentinelProviderURL {
			if !conditionScopesClaim(s.Condition, azureSentinelRequiredKey) {
				return iamerr.MalformedPolicyDocument(fmt.Sprintf(
					"The trust policy trusts shared OpenID Connect provider %q without a Condition scoping %q to your own tenant.", url, azureSentinelRequiredKey))
			}
			continue
		}

		claim, known := sharedOIDCProviderRequiredClaim[url]
		if !known {
			continue
		}
		key := url + ":" + claim
		if !conditionScopesClaim(s.Condition, key) {
			return iamerr.MalformedPolicyDocument(fmt.Sprintf(
				"The trust policy trusts shared OpenID Connect provider %q without a Condition scoping %q to your own tenant.", url, key))
		}
	}
	return nil
}

// oidcProviderURLFromFederatedArn extracts the provider Url from a Federated
// principal ARN shaped like "arn:aws:iam::<account>:oidc-provider/<url>",
// reporting ok=false for any value not shaped like an OIDC provider ARN at
// all — a bare federation identifier
// (e.g. "cognito-identity.amazonaws.com") or a malformed value, both handled
// elsewhere (this is deliberately a lightweight shape check, not full ARN
// validation: an actually-malformed ARN is caught later, when the runtime
// AssumeRoleWithWebIdentity path resolves it against real registered
// providers and finds nothing).
func oidcProviderURLFromFederatedArn(value string) (string, bool) {
	_, url, ok := strings.Cut(value, oidcProviderArnInfix)
	if !ok || url == "" {
		return "", false
	}
	return url, true
}

// conditionScopesClaim reports whether raw (a statement's Condition block)
// contains a positive String-family comparison (StringEquals, StringLike, or
// StringEqualsIgnoreCase — optionally ForAllValues/ForAnyValue-qualified;
// their Not-negated counterparts don't count, since excluding one value
// doesn't scope to a tenant) against key (matched case-insensitively, same
// as identity-policy condition keys) with at least one value that actually
// scopes the claim. For StringLike specifically — the one operator here
// where '*'/'?' are wildcards, not literal characters — a value consisting
// entirely of wildcard characters (e.g. "*", "**", "?", "*?*") is rejected
// even though it's non-empty: AWS documents that a shared provider's
// tenancy claim "must not consist only of wildcard characters", since
// a pattern with no literal character left after stripping '*'/'?' matches
// every possible value just as completely as a bare "*" does. StringEquals
// and StringEqualsIgnoreCase don't treat '*'/'?' as wildcards at all, so
// only the plain "empty or exactly '*'" check applies to them. A block that
// fails to parse reports false, same as an absent one —
// condition.ShapeValid/condition.Evaluate are responsible for rejecting or
// fail-closing a block this can't understand; this check only ever adds a
// stricter write-time requirement on top of that.
func conditionScopesClaim(raw json.RawMessage, key string) bool {
	if len(raw) == 0 {
		return false
	}
	block, err := condition.Parse(raw)
	if err != nil {
		return false
	}
	for operator, kvs := range block {
		op, ok := condition.ParseOperatorName(operator)
		if !ok {
			continue
		}
		switch op.Base {
		case "StringEquals", "StringLike", "StringEqualsIgnoreCase":
		default:
			continue
		}
		for k, values := range kvs {
			if !strings.EqualFold(k, key) {
				continue
			}
			for _, v := range values {
				if v == "" || v == "*" {
					continue
				}
				if op.Base == "StringLike" && !hasNonWildcardCharacter(v) {
					continue
				}
				return true
			}
		}
	}
	return false
}

// hasNonWildcardCharacter reports whether v contains at least one character
// other than the StringLike wildcards '*' (any run of characters) and '?'
// (any single character) — i.e. whether it scopes to anything narrower than
// "every possible value".
func hasNonWildcardCharacter(v string) bool {
	for _, r := range v {
		if r != '*' && r != '?' {
			return true
		}
	}
	return false
}
