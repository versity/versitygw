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

package types

// Identity is the caller identity the auth middleware resolves for a
// request, shared across the auth middleware, the policy middleware, and
// controllers (GetCallerIdentity) so the access key only ever needs to be
// resolved once per request.
//
// Exactly one of IsRoot, User, or Session is set:
//   - IsRoot: the configured root credential. Bypasses policy evaluation
//     entirely, matching real AWS's root user.
//   - User: a long-term (AKIA…) IAM user credential. IdentityPolicies holds
//     that user's own inline policy documents.
//   - Session: a temporary (ASIA…) credential minted by
//     AssumeRoleWithWebIdentity. Role is the assumed role; IdentityPolicies
//     holds the role's inline policy documents, and SessionPolicy — if
//     non-empty — is an additional filter that can only narrow, never
//     widen, what the role otherwise allows (Effective permissions = Role
//     identity-based permissions ∩ Session policy permissions).
type Identity struct {
	IsRoot  bool
	User    *User
	Role    *Role
	Session *Session

	// IdentityPolicies are the inline policies to evaluate for
	// authorization: the User's own policies, or the assumed Role's
	// policies for a Session. Unset (nil) when IsRoot.
	IdentityPolicies []PolicyEntry

	// SessionPolicy is the session's own inline policy document (the
	// AssumeRoleWithWebIdentity Policy parameter), or "" if none was
	// supplied. Only ever set alongside Session.
	SessionPolicy string
}
