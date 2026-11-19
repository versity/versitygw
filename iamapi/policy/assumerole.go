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
	"github.com/versity/versitygw/internal/condition"
)

// AssumeRoleAction is the sts action name a role trust statement must
// authorize for AssumeRole to succeed, and the action the caller's own
// identity policies are evaluated against.
const AssumeRoleAction = "sts:AssumeRole"

// WildcardPrincipal is the AWS principal value that names every principal.
const WildcardPrincipal = "*"

// TrustGrant is how far a role's trust policy goes towards letting a caller
// assume the role. The values are ordered: a stronger grant needs less from
// the caller's own policies than a weaker one, so when several statements
// apply the strongest decides.
type TrustGrant int

const (
	// TrustDenied means a Deny statement applies to the caller. Nothing in
	// the caller's own policies can override it.
	TrustDenied TrustGrant = iota
	// TrustNone means no statement applies to the caller at all.
	TrustNone
	// TrustAccount means an Allow names the account. That only delegates:
	// the account's own IAM decides, so the caller's identity policies must
	// allow the action as well.
	TrustAccount
	// TrustRole means an Allow names the role the calling session assumed.
	// It needs no identity-policy Allow, but the session's own session
	// policy, if it has one, still has to permit the action.
	TrustRole
	// TrustDirect means an Allow names the caller itself: its user ARN, its
	// session ARN, or every principal. It is sufficient on its own.
	TrustDirect
)

// AssumeRoleCaller identifies an authenticated AssumeRole caller in each
// form a trust statement's AWS principal can name it by.
type AssumeRoleCaller struct {
	AccountID string
	// UserArn is set for a long-term IAM user.
	UserArn string
	// RoleArn and SessionArn are set for an assumed-role session whose role
	// still exists. A session that has outlived its role is named by
	// neither: only a wildcard or account principal still covers it here,
	// though the IAM service refuses such a session before evaluating
	// trust at all.
	RoleArn    string
	SessionArn string
}

// EvaluateAssumeRoleTrust evaluates document (a role's
// AssumeRolePolicyDocument) for an sts:AssumeRole call by caller, with
// ctxVars as the request's condition context.
//
// Only a statement's AWS principals are consulted; a Service or Federated
// principal never names an IAM caller. A statement whose Condition cannot be
// evaluated denies outright, since it could be a Deny that would have
// applied.
func EvaluateAssumeRoleTrust(document string, caller AssumeRoleCaller, ctxVars map[string][]string) TrustGrant {
	var doc Document
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		debuglogger.Logf("role trust policy document failed to parse: %v", err)
		return TrustNone
	}
	if err := doc.ValidateTrust(); err != nil {
		debuglogger.Logf("role trust policy document failed validation: %v", err)
		return TrustNone
	}

	grant := TrustNone
	for _, stmt := range doc.Statement {
		if !statementCoversAction(stmt, AssumeRoleAction) {
			continue
		}
		match := caller.match(principalValues(stmt.Principal, "AWS"))
		if match == TrustNone {
			continue
		}

		matched, ok := condition.Evaluate(stmt.Condition, ctxVars, doc.Version)
		if !ok {
			debuglogger.Logf("assume role trust evaluation: statement condition could not be evaluated, denying")
			return TrustDenied
		}
		if !matched {
			continue
		}
		if stmt.Effect == "Deny" {
			debuglogger.Logf("assume role trust evaluation: explicitly denied by trust policy")
			return TrustDenied
		}
		grant = max(grant, match)
	}
	return grant
}

// TrustAWSPrincipals returns every value document's statements name under
// their Principal's AWS key, in order of appearance, or nil when document
// does not parse.
func TrustAWSPrincipals(document string) []string {
	var doc Document
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil
	}
	var principals []string
	for _, stmt := range doc.Statement {
		principals = append(principals, principalValues(stmt.Principal, "AWS")...)
	}
	return principals
}

// match reports the strongest way principals, a statement's AWS principal
// values, name c: TrustNone when none of them does.
func (c AssumeRoleCaller) match(principals []string) TrustGrant {
	grant := TrustNone
	for _, principal := range principals {
		switch {
		case principal == WildcardPrincipal,
			c.UserArn != "" && principal == c.UserArn,
			c.SessionArn != "" && principal == c.SessionArn:
			return TrustDirect
		case c.RoleArn != "" && principal == c.RoleArn:
			grant = max(grant, TrustRole)
		case principal == c.AccountID, principal == accountRootArn(c.AccountID):
			grant = max(grant, TrustAccount)
		}
	}
	return grant
}

func accountRootArn(accountID string) string {
	return "arn:aws:iam::" + accountID + ":root"
}
