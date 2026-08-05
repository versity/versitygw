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
	"strconv"
	"time"

	"github.com/versity/versitygw/debuglogger"
)

// AssumeRoleWithWebIdentityAction is the sts action name role trust
// statements must (directly, or via a wildcard) authorize for
// AssumeRoleWithWebIdentity to succeed.
const AssumeRoleWithWebIdentityAction = "sts:AssumeRoleWithWebIdentity"

// WebIdentityMatch is the outcome of evaluating a role's trust policy
// against an authenticated web identity federation attempt. The distinct
// NoPrincipal/NoIssuerMatch/ConditionFailed cases exist because AWS reports
// two different errors depending on which one occurs: NoPrincipal (no
// Federated principal in the trust policy resolves to a provider that
// actually exists) is reported as AccessDenied identically to a
// nonexistent role, while NoIssuerMatch and ConditionFailed (an existing,
// referenced provider's signing keys and claims were checked and didn't
// satisfy the request) are both reported as InvalidIdentityToken.
type WebIdentityMatch int

const (
	NoPrincipal WebIdentityMatch = iota
	NoIssuerMatch
	ConditionFailed
	ExplicitlyDenied
	Allowed
)

// ProviderLookup resolves a Federated principal ARN to the scheme-stripped
// Url of the OIDC provider it names, reporting ok=false for any ARN that
// doesn't correspond to a provider that actually exists.
type ProviderLookup func(federatedArn string) (url string, ok bool)

// WebIdentityContext carries the token values needed to evaluate a trust
// statement's Condition block, keyed the way AWS's own condition context
// keys are: "<provider-url>:<claim-name>".
type WebIdentityContext struct {
	ProviderURL string
	// Audience is the token's effective audience: azp when present,
	// otherwise the token's single aud value. Mapped to <provider-url>:aud.
	Audience string
	// OriginalAudience is the token's actual aud claim value(s), only ever
	// set when azp is present (and therefore differs from Audience) —
	// mapped to <provider-url>:oaud. This matters for Google hybrid
	// clients, where aud names the backend project and azp names the
	// actual OAuth client that requested the token.
	OriginalAudience []string
	Subject          string
	// Claims holds every other top-level string/string-array claim from
	// the token, for Condition keys beyond aud/sub (e.g. a custom "amr"
	// or "groups" claim). Values are pre-normalized to []string.
	Claims map[string][]string

	// The remaining fields are request-scoped, not token-scoped: unlike
	// Claims/Audience/Subject (all read from the presented JWT), these carry
	// the same global request facts identity-policy Condition evaluation
	// already sees (iammiddleware.requestConditionContext) so a trust
	// statement's explicit Deny can be scoped by them too - a
	// broad-Allow-plus-Deny trust policy must see the same request facts an
	// Allow does, not treat the key as always absent.

	// SourceIP is the caller's address, mapped to aws:SourceIp.
	SourceIP string
	// Secure is whether the connection is TLS, mapped to
	// aws:SecureTransport - AWS documents this key as present on every
	// request, not just TLS ones.
	Secure bool
	// Now is the request's evaluation time, mapped to aws:CurrentTime and
	// aws:EpochTime.
	Now time.Time
	// RoleSessionName is the caller-supplied RoleSessionName parameter,
	// mapped to sts:RoleSessionName.
	RoleSessionName string
}

// conditionContext builds the map a trust statement's Condition block is
// evaluated against: "<provider-url>:<claim>" keys from the token itself,
// plus the request-scoped global keys identity-policy evaluation already
// exposes — aws:SourceIp, aws:SecureTransport, aws:CurrentTime,
// aws:EpochTime, and sts:RoleSessionName — so an explicit Deny conditioned
// on any of these sees the same facts an Allow would.
func (w WebIdentityContext) conditionContext() map[string][]string {
	ctxVars := make(map[string][]string, len(w.Claims)+8)
	for claim, values := range w.Claims {
		ctxVars[w.ProviderURL+":"+claim] = values
	}
	if w.Audience != "" {
		ctxVars[w.ProviderURL+":aud"] = []string{w.Audience}
	}
	if len(w.OriginalAudience) > 0 {
		ctxVars[w.ProviderURL+":oaud"] = w.OriginalAudience
	}
	if w.Subject != "" {
		ctxVars[w.ProviderURL+":sub"] = []string{w.Subject}
	}
	if w.SourceIP != "" {
		ctxVars["aws:SourceIp"] = []string{w.SourceIP}
	}
	ctxVars["aws:SecureTransport"] = []string{strconv.FormatBool(w.Secure)}
	if !w.Now.IsZero() {
		ctxVars["aws:CurrentTime"] = []string{w.Now.Format(time.RFC3339)}
		ctxVars["aws:EpochTime"] = []string{strconv.FormatInt(w.Now.Unix(), 10)}
	}
	if w.RoleSessionName != "" {
		ctxVars["sts:RoleSessionName"] = []string{w.RoleSessionName}
	}
	return ctxVars
}

// EvaluateWebIdentityTrust evaluates document (a role's
// AssumeRolePolicyDocument) against wctx, resolving each statement's
// Federated principal(s) via lookup.
//
// The evaluation order mirrors AWS's observed behavior: first, whether any
// statement's Federated principal resolves to a provider that actually
// exists (regardless of whether its Url matches the token) determines
// NoPrincipal vs the later cases; only among statements whose provider
// exists AND whose Url matches wctx.ProviderURL does the token's Condition
// get evaluated. An explicit Deny statement matching the same provider,
// action and condition overrides an otherwise-matching Allow.
func EvaluateWebIdentityTrust(document string, lookup ProviderLookup, wctx WebIdentityContext) (WebIdentityMatch, string) {
	var doc Document
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		debuglogger.Logf("role trust policy document failed to parse: %v", err)
		return NoPrincipal, ""
	}
	// CreateRole/UpdateAssumeRolePolicy already reject a trust document that
	// wouldn't pass ValidateTrust at write time, but a document stored
	// before that validation existed could still fail it. Assign no meaning
	// to a document AWS itself would reject — NoPrincipal is the same safe
	// default an unresolvable Federated principal produces, reported as
	// AccessDenied identically to a nonexistent role.
	if err := doc.ValidateTrust(); err != nil {
		debuglogger.Logf("role trust policy document failed validation: %v", err)
		return NoPrincipal, ""
	}

	ctxVars := wctx.conditionContext()

	anyExistingPrincipal := false
	anyIssuerMatch := false
	var allowedProviderArn string
	allowed := false
	denied := false

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
			continue
		}
		if !statementCoversAction(stmt, AssumeRoleWithWebIdentityAction) {
			continue
		}

		for _, federatedArn := range federatedPrincipals(stmt.Principal) {
			url, ok := lookup(federatedArn)
			if !ok {
				continue
			}
			anyExistingPrincipal = true
			if url != wctx.ProviderURL {
				continue
			}
			anyIssuerMatch = true

			matched, condOk := evaluateCondition(stmt.Condition, ctxVars, doc.Version)
			if !condOk {
				debuglogger.Logf("web identity trust evaluation: statement condition could not be evaluated, denying")
				denied = true
				continue
			}
			if !matched {
				continue
			}

			if stmt.Effect == "Deny" {
				denied = true
				continue
			}
			allowed = true
			allowedProviderArn = federatedArn
		}
	}

	switch {
	case denied:
		debuglogger.Logf("web identity trust evaluation: explicitly denied by trust policy")
		return ExplicitlyDenied, ""
	case allowed:
		return Allowed, allowedProviderArn
	case anyIssuerMatch:
		debuglogger.Logf("web identity trust evaluation: provider %q matched but condition block did not", wctx.ProviderURL)
		return ConditionFailed, ""
	case anyExistingPrincipal:
		debuglogger.Logf("web identity trust evaluation: no trust statement's provider matches issuer %q", wctx.ProviderURL)
		return NoIssuerMatch, ""
	default:
		debuglogger.Logf("web identity trust evaluation: no trust statement resolves to an existing provider")
		return NoPrincipal, ""
	}
}

// federatedPrincipals extracts a statement's Principal.Federated value(s),
// tolerating both a bare string and an array (empty/absent on any parse
// failure, since a statement whose Principal doesn't parse simply matches
// nothing here — CreateRole/UpdateAssumeRolePolicy already reject any
// trust policy that wouldn't parse this way).
func federatedPrincipals(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var principal map[string]StringOrSlice
	if err := json.Unmarshal(raw, &principal); err != nil {
		return nil
	}
	return principal["Federated"]
}

// statementCoversAction reports whether stmt's Action/NotAction authorizes
// action.
func statementCoversAction(stmt Statement, action string) bool {
	if len(stmt.Action) > 0 {
		return matchAny(stmt.Action, action)
	}
	if len(stmt.NotAction) > 0 {
		return !matchAny(stmt.NotAction, action)
	}
	return false
}

func matchAny(patterns []string, action string) bool {
	for _, p := range patterns {
		if matchActionPattern(p, action) {
			return true
		}
	}
	return false
}

// matchActionPattern matches action against pattern, a case-insensitive
// IAM-style glob ('*' any run of characters, '?' any single character) —
// e.g. "sts:*" or "sts:AssumeRole*" both match "sts:AssumeRoleWithWebIdentity".
func matchActionPattern(pattern, action string) bool {
	return globMatch(toLowerASCII(pattern), toLowerASCII(action))
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// globMatch implements the small wildcard grammar IAM Action/Resource
// patterns use: '*' matches any run of characters (including none), '?'
// matches exactly one character, everything else matches literally.
func globMatch(pattern, s string) bool {
	var pi, si, star, match int
	star = -1
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			match = si
			pi++
		case star != -1:
			pi = star + 1
			match++
			si = match
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
