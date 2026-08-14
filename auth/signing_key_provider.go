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

package auth

import "github.com/versity/versitygw/internal/sigv4auth"

// SigningKeyProvider is implemented by IAM backends that can compute a
// SigV4 derived signing key (kSigning) without ever revealing the account's
// underlying secret to this process — currently only the standalone IAM
// service client (IAMServiceStandalone). Callers that resolve an
// IAMService's derived key type-assert for this interface first and fall
// back to fetching the account's secret via GetUserAccount and deriving the
// key locally (sigv4auth.DeriveKey) when it isn't implemented, so every
// other backend (internal, LDAP, Vault, IPA, S3) is unaffected.
//
// date/region/service are the request's credential-scope components
// (yyyymmdd/region/service, matching sigv4auth.DeriveKey's parameters).
// sessionToken is the request's X-Amz-Security-Token, required when access
// is a temporary (ASIA…) key and empty otherwise.
//
// The returned Account never has Secret populated. Returns ErrNoSuchUser if
// access does not exist (matching IAMService.GetUserAccount), or
// ErrInvalidSessionToken if the token is missing, wrong, or paired with a
// permanent access key.
type SigningKeyProvider interface {
	DeriveSigningKey(access, sessionToken, date, region, service string) ([]byte, Account, error)
}

// PolicyEvaluation is what a PolicyEvaluator reports for a batch of
// resources and actions evaluated together in a single request.
//
// Decisions[i][j] is the tri-state decision for resources[i] and actions[j],
// in the order both were given to EvaluatePolicy. PrincipalArn is the
// (best-effort) resolved principal ARN, shared across the whole batch since
// one call always evaluates a single identity — it is used only to build an
// AWS-shaped Deny message, and is "" when it can't be resolved, in which
// case the caller falls back to the access key.
//
// SessionDecisions is the same matrix evaluated against the caller's session
// policy alone, meaningful only when HasSessionPolicy is set. A session
// policy filters everything the session can do, including what the bucket
// policy grants it, so it cannot be folded into Decisions — which describe
// only the identity (user or role) policies.
type PolicyEvaluation struct {
	Decisions        [][]policyDecision
	SessionDecisions [][]policyDecision
	HasSessionPolicy bool
	PrincipalArn     string
}

// PolicyEvaluator is implemented by IAM backends that enforce IAM identity
// (user/role/session) policies against S3 requests — currently only the
// standalone IAM service client. VerifyAccess type-asserts for this
// interface and, when present, combines its tri-state decision with the
// bucket's own policy/ACL decision using AWS's real precedence: an explicit
// Deny from either source wins outright, otherwise either source's Allow is
// independently sufficient; backends without it are unaffected — there is
// no identity-policy layer for them.
//
// The full actions × resources matrix is evaluated in a single batched
// request rather than one round trip per cell. Both dimensions are really
// used: a copy checks several actions (its source's and destination's), and
// a batch delete checks several resources (one object ARN per key, up to
// 1000 of them). A round trip per cell would multiply request latency for
// no benefit, since one request can carry the whole matrix.
//
// condition carries only the condition keys the gateway itself can observe
// from the request (aws:SourceIp, aws:CurrentTime, aws:SecureTransport, …);
// the identity-derived keys are filled in by the implementation, which is
// the only side that knows who the access key belongs to.
type PolicyEvaluator interface {
	EvaluatePolicy(access, sessionToken string, actions []Action, resources []string, condition map[string][]string) (PolicyEvaluation, error)
}

// ResolveDerivedKey resolves access's SigV4 derived signing key (kSigning)
// and account metadata for date/region/service. root is special-cased
// locally — its secret is already known to this process either way, so
// there's no reason to round-trip it through iam. Otherwise, if iam
// implements SigningKeyProvider, the key is fetched from it directly and
// the account's secret never enters this process; otherwise iam's account
// is resolved via GetUserAccount and the key is derived locally from its
// secret, preserving today's behavior for every backend that doesn't
// implement SigningKeyProvider (internal, LDAP, Vault, IPA, S3).
//
// sessionToken is the request's X-Amz-Security-Token, or "" when it carries
// none. A temporary (ASIA…) access key, or a token paired with a permanent
// one, is only meaningful to a SigningKeyProvider backend: no other backend
// can mint a session, so for them either shape is rejected as
// ErrInvalidSessionToken rather than silently resolving to something else.
func ResolveDerivedKey(iam IAMService, root Account, access, sessionToken, date, region, service string) ([]byte, Account, error) {
	if access == root.Access {
		if sessionToken != "" {
			return nil, Account{}, ErrInvalidSessionToken
		}
		return sigv4auth.DeriveKey(root.Secret, date, region, service), root, nil
	}
	if skp, ok := iam.(SigningKeyProvider); ok {
		return skp.DeriveSigningKey(access, sessionToken, date, region, service)
	}
	if sessionToken != "" || sigv4auth.IsTempAccessKeyID(access) {
		return nil, Account{}, ErrInvalidSessionToken
	}
	account, err := iam.GetUserAccount(access)
	if err != nil {
		return nil, Account{}, err
	}
	return sigv4auth.DeriveKey(account.Secret, date, region, service), account, nil
}
