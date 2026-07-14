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
	"slices"
	"strings"

	"github.com/versity/versitygw/iamapi/iamerr"
)

// trustPrincipalKeys are the only keys IAM accepts inside a trust policy
// statement's Principal object. CanonicalUser is deliberately not accepted
// here (see errTrustInvalidPrincipalKey) since it identifies an S3 canonical
// user id which is the legacy s3 user identifier and is not planned to support
var trustPrincipalKeys = map[string]bool{
	"AWS":       true,
	"Service":   true,
	"Federated": true,
}

const cognitoFederatedProvider = "cognito-identity.amazonaws.com"

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
// NotAction with only "sts:"-prefixed values, and no Resource/NotResource.
// Condition is not modeled or validated(not supported at the moment)
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

	requiresCondition := false
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
		if key == "Federated" && slices.Contains(values, cognitoFederatedProvider) {
			requiresCondition = true
		}
	}

	if requiresCondition && len(s.Condition) == 0 {
		return errTrustCognitoConditionRequired
	}

	return nil
}
