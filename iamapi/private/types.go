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

// DeriveSigningKeyRequest is the derive-signing-key request body. Date,
// Region, and Service are the request's credential-scope components
// (yyyymmdd/region/service), matching sigv4auth.DeriveKey's parameters.
//
// SessionToken is required when AccessKeyID is a temporary (ASIA…) key and
// must be absent otherwise. It is what makes resolving a session here safe:
// without it, anyone who learned a session's access key id could ask for
// that session's signing key.
type DeriveSigningKeyRequest struct {
	AccessKeyID  string `json:"accessKeyId"`
	SessionToken string `json:"sessionToken,omitempty"`
	Date         string `json:"date"`
	Region       string `json:"region"`
	Service      string `json:"service"`
}

// DeriveSigningKeyResponse carries the derived signing key (kSigning) —
// never the underlying secret.
type DeriveSigningKeyResponse struct {
	DerivedKey []byte `json:"derivedKey"`
}

// EvaluatePolicyRequest is the evaluate-policy request body
type EvaluatePolicyRequest struct {
	AccessKeyID  string              `json:"accessKeyId"`
	SessionToken string              `json:"sessionToken,omitempty"`
	Actions      []string            `json:"actions"`
	Resources    []string            `json:"resources"`
	Condition    map[string][]string `json:"condition,omitempty"`
}

// ResolveIdentityRequest asks whether each access key id exists and what
// principal it names. It carries no session token because the response
// carries no credential material
type ResolveIdentityRequest struct {
	AccessKeyIDs []string `json:"accessKeyIds"`
}

// ResolveIdentityResponse answers ResolveIdentityRequest positionally: one
// entry per requested access key id, in the same order, with Found false
// for one that doesn't resolve. It deliberately carries no secret, no
// derived key and no policy — only that makes it safe to answer for a
// temporary (ASIA…) key with no session token, since knowing a session
// exists grants nothing.
type ResolveIdentityResponse struct {
	Identities []ResolvedIdentity `json:"identities"`
}

// ResolvedIdentity is one ResolveIdentityResponse entry. Kind is
// KindUser or KindSession.
type ResolvedIdentity struct {
	Found        bool   `json:"found"`
	Kind         string `json:"kind,omitempty"`
	PrincipalArn string `json:"principalArn,omitempty"`
}

// Kind values for ResolvedIdentity.Kind — strings on the wire for the same
// reason the Decision values below are: self-documenting, and immune to
// iota drift between the independently-built gateway and IAM service.
const (
	KindUser    = "user"
	KindSession = "session"
)

// Decision values for each entry of EvaluatePolicyResponse.Decisions.
// Deliberately strings, not policy.Decision's int: self-documenting on the
// wire, and immune to iota drift between the S3 gateway and standalone IAM
// service — two independently-built processes speaking this protocol.
const (
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DecisionNoMatch = "no_match"
)

// EvaluatePolicyResponse carries the full tri-state result for the whole
// requested matrix — not just whether each cell is allowed — so the S3
// gateway can distinguish an explicit Deny (which must override an
// otherwise-allowing bucket policy) from a plain NoMatch (which doesn't),
// and can build an AWS-shaped denial message.
//
// Decisions[i][j] is the decision for the request's Resources[i] and
// Actions[j], in the order both were sent. PrincipalArn is the resolved
// identity's own ARN, best-effort: "" when it can't be resolved (e.g. a
// session whose role no longer exists), in which case the caller falls back
// to the access key. It is shared by the whole batch — one request always
// evaluates against a single identity.
// SessionDecisions is the same matrix evaluated against the caller's
// session policy alone, and HasSessionPolicy says whether one applied — the
// caller must ignore SessionDecisions when it is false. They are reported
// separately from Decisions rather than folded into them because a session
// policy filters *everything*, including permissions the S3 gateway's own
// bucket policy grants, which this service knows nothing about. See
// iammiddleware.AuthorizeSplit.
type EvaluatePolicyResponse struct {
	Decisions        [][]string `json:"decisions"`
	SessionDecisions [][]string `json:"sessionDecisions,omitempty"`
	HasSessionPolicy bool       `json:"hasSessionPolicy,omitempty"`
	PrincipalArn     string     `json:"principalArn,omitempty"`
}
