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

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/condition"
)

// MaxSessionPolicyBytes is the maximum length, in bytes, of the optional
// inline session policy document AssumeRoleWithWebIdentity's Policy
// parameter accepts, matching AWS's documented quota for that parameter.
const MaxSessionPolicyBytes = 2048

// RequestContext carries the request-scoped values an identity-policy
// statement is evaluated against, matching AWS's treatment of authorization
// as a full request-context decision (action, resource, and condition —
// principal is already fixed by which documents are passed in) rather than
// the action name alone.
type RequestContext struct {
	// Action is the "<service>:<Action>" string being authorized, e.g.
	// "iam:GetRole".
	Action string
	// Resource is the ARN of the specific resource the action targets
	// (e.g. a role's own Arn for GetRole, or "*" for an action AWS
	// classifies as resource-less, such as a List action).
	Resource string
	// Condition is the "aws:<GlobalKey>"-keyed context (aws:SourceIp,
	// aws:username, aws:PrincipalArn, aws:userid, ...) a statement's
	// Condition block is evaluated against.
	Condition map[string][]string
}

// Decision is the tri-state result of evaluating a set of identity policy
// documents. A caller combining this with another policy source (e.g. an S3
// bucket policy) needs this distinction, not a plain bool, to implement
// AWS's real cross-policy precedence: an explicit Deny from either source
// wins outright over an Allow from the other, but a NoMatch from one source
// leaves the other free to grant access on its own.
type Decision int

const (
	// DecisionNoMatch means no statement in any document matched reqCtx at
	// all — neither an Allow nor a Deny.
	DecisionNoMatch Decision = iota
	// DecisionAllow means at least one statement matched with Effect Allow,
	// and no statement matched with Effect Deny.
	DecisionAllow
	// DecisionDeny means a statement matched with Effect Deny, or the
	// evaluation failed closed (unparseable/invalid document, or a
	// Condition that couldn't be evaluated).
	DecisionDeny
)

// EvaluateIdentityPolicies reports how documents (each a user's or role's
// inline policy entry) decide reqCtx, using IAM's evaluation semantics: a
// statement must cover the action, the resource, and (if present) its
// Condition block to be considered at all; a matching explicit Deny
// statement makes the whole evaluation DecisionDeny regardless of any Allow
// found elsewhere (in the same or another document); absent an explicit
// deny, at least one covering Allow statement is required for DecisionAllow
// — an identity with no matching statement at all gets DecisionNoMatch, not
// DecisionAllow.
//
// A document that fails to parse, or a statement whose Condition block
// can't be evaluated, returns DecisionDeny
// rather than being skipped: PutUserPolicy/PutRolePolicy already reject any
// policy document that wouldn't parse or whose Condition uses an
// unrecognized operator, so this only matters for documents written before
// that validation existed - and for exactly that legacy-data case, we can't
// rule out a hidden Deny inside the part we can't evaluate, so the safe
// outcome is to deny rather than silently proceed as if it wasn't there.
func EvaluateIdentityPolicies(documents []types.PolicyEntry, reqCtx RequestContext) Decision {
	allowed := false

	for _, entry := range documents {
		var doc Document
		if err := json.Unmarshal([]byte(entry.PolicyDocument), &doc); err != nil {
			debuglogger.Logf("identity policy document failed to parse: %v", err)
			return DecisionDeny
		}
		// PutUserPolicy/PutRolePolicy already reject a document that
		// wouldn't pass Validate (e.g. both Action and NotAction on one
		// statement) at write time, but a document stored before that
		// validation existed — or reaching storage through a migration,
		// backup restore, or out-of-band write — could still fail it. Assign
		// no meaning to a document AWS itself would reject rather than
		// evaluating it anyway: re-check it here, at the security boundary,
		// not just at ingress.
		if err := doc.Validate(); err != nil {
			debuglogger.Logf("identity policy document failed validation: %v", err)
			return DecisionDeny
		}

		for _, stmt := range doc.Statement {
			if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
				continue
			}
			if !statementCoversAction(stmt, reqCtx.Action) {
				continue
			}
			if !statementCoversResource(stmt, reqCtx.Resource, reqCtx.Condition, doc.Version) {
				continue
			}
			matched, ok := condition.Evaluate(stmt.Condition, reqCtx.Condition, doc.Version)
			if !ok {
				debuglogger.Logf("identity policy evaluation: statement condition could not be evaluated, denying")
				return DecisionDeny
			}
			if !matched {
				continue
			}

			if stmt.Effect == "Deny" {
				debuglogger.Logf("identity policy evaluation: action %q on resource %q explicitly denied", reqCtx.Action, reqCtx.Resource)
				return DecisionDeny
			}
			allowed = true
		}
	}

	if allowed {
		return DecisionAllow
	}
	return DecisionNoMatch
}

// statementCoversResource reports whether stmt's Resource/NotResource
// authorizes resource. Matching is case-sensitive (unlike action matching):
// ARNs are case-sensitive. version is the enclosing document's Version
// element: each pattern has policy variables (e.g. "${aws:username}")
// substituted from ctxVars before matching only when version is exactly
// Version2012 — AWS documents policy variables as requiring the
// 2012-10-17 policy version; a document with no Version, or the older
// 2008-10-17, matches Resource patterns containing "${...}" as the literal
// text instead, the same as real AWS. A statement with neither Resource nor
// NotResource never matches — Validate already requires every statement to
// carry one, so this only matters for documents written before that
// validation existed.
func statementCoversResource(stmt Statement, resource string, ctxVars map[string][]string, version string) bool {
	if len(stmt.Resource) > 0 {
		return matchAnyResource(stmt.Resource, resource, ctxVars, version)
	}
	if len(stmt.NotResource) > 0 {
		return !matchAnyResource(stmt.NotResource, resource, ctxVars, version)
	}
	return false
}

func matchAnyResource(patterns []string, resource string, ctxVars map[string][]string, version string) bool {
	for _, p := range patterns {
		pattern := p
		if version == Version2012 {
			pattern = condition.SubstitutePolicyVariables(p, ctxVars)
		}
		if condition.GlobMatch(pattern, resource) {
			return true
		}
	}
	return false
}
