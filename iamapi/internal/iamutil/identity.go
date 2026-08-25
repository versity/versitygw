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

package iamutil

import (
	"context"
	"errors"
	"time"

	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/sigv4auth"
)

// ErrIdentityNotFound and ErrInvalidSessionToken are returned by
// ResolveSessionByToken and ResolveUserIdentity, so a caller that needs to
// know *which* failure occurred — the standalone-IAM private endpoints, and
// iammiddleware's own sigv4 pipeline, which turn them into S3's own
// InvalidAccessKeyId and InvalidToken respectively — can distinguish them.
//
// The public IAM control plane deliberately collapses both into a single
// InvalidClientTokenId: an unauthenticated caller must not learn whether an
// access key exists.
var (
	ErrIdentityNotFound    = errors.New("identity not found")
	ErrInvalidSessionToken = errors.New("invalid session token")
)

// IdentityStore resolves an access key id to the session or long-term user
// that owns it, and resolves named resources for policy evaluation.
// storage.Storer satisfies this directly.
type IdentityStore interface {
	GetSession(ctx context.Context, accessKeyID string) (*types.Session, error)
	GetRole(ctx context.Context, roleName string) (*types.Role, error)
	GetUserByAccessKeyID(ctx context.Context, accessKeyID string) (*types.User, error)
	GetUser(ctx context.Context, username string) (*types.User, error)
	GetOIDCProvider(ctx context.Context, arn string) (*types.OIDCProvider, error)
	RecordAccessKeyUsage(ctx context.Context, accessKeyID, service, region string, when time.Time) error
}

// ResolveSessionByToken resolves a temporary (ASIA…) access key to the
// session that owns it, requiring token to match the session's stored
// SessionToken. The empty-token rejection and the constant-time comparison
// both live here rather than in any caller: this is the only function that
// may turn a session access key id into a secret, so no caller can be
// written that skips them.
//
// It does not itself verify a SigV4 signature — request-pipeline callers do
// that next, so a stolen or guessed access key id plus token is never
// sufficient on its own.
func ResolveSessionByToken(ctx context.Context, store IdentityStore, accessKeyID, token string) (*types.Identity, string, error) {
	// No token means there is nothing to resolve the access key against, so
	// the key is reported as simply not existing rather than as a bad token
	// — matching real S3, which answers InvalidAccessKeyId for a temporary
	// access key presented with no X-Amz-Security-Token, and InvalidToken
	// only once a token is actually present and wrong.
	if token == "" {
		return nil, "", ErrIdentityNotFound
	}

	session, err := store.GetSession(ctx, accessKeyID)
	if err != nil {
		return nil, "", ErrIdentityNotFound
	}

	if !sigv4auth.SecureCompare(token, session.SessionToken) {
		return nil, "", ErrInvalidSessionToken
	}

	// A signature-valid, unexpired session still authenticates even if its
	// role has since been deleted — real STS credentials are self-contained
	// and don't re-check role existence on every call. What such a session
	// can no longer do is get any IAM action past the policy middleware:
	// with Role/IdentityPolicies left unset, EvaluateIdentityPolicies denies
	// by default, same effective outcome as an explicit rejection here would
	// have had for every pipeline except GetCallerIdentity, which needs
	// none of this and must keep working regardless.
	//
	// The reloaded role must also still be the *same* role the session was
	// originally minted against — RoleID and Arn, both captured in the
	// session at AssumeRoleWithWebIdentity time, must match the freshly
	// loaded role's own values. Without this check, deleting a role and
	// recreating one of the same name (necessarily getting a new RoleID)
	// would let every pre-existing session for the old role silently
	// inherit whatever policies the new role happens to carry.
	identity := &types.Identity{
		Session:       session,
		SessionPolicy: session.Policy,
	}
	if role, err := store.GetRole(ctx, session.RoleName); err == nil &&
		role.RoleID == session.RoleID && role.Arn == session.RoleArn {
		identity.Role = role
		identity.IdentityPolicies = role.Policies.Inline
	}
	return identity, session.SecretAccessKey, nil
}

// ResolveUserIdentity resolves accessKeyID to its long-term (AKIA…) IAM user
// and secret, reporting the ErrIdentityNotFound/ErrInvalidSessionToken
// sentinels rather than an opaque API error — callers on the public control
// plane that want the opaque error do that translation themselves.
//
// Temporary (ASIA…) session access keys are rejected here: resolving one
// safely requires validating its security token, which this function has no
// parameter for. A caller that can supply a token uses ResolveSessionByToken
// instead. Silently resolving a session's secret from its access key id
// alone, with no token check at all, would let anyone who merely knows the
// id impersonate the session.
func ResolveUserIdentity(ctx context.Context, store IdentityStore, accessKeyID string) (*types.Identity, string, error) {
	if sigv4auth.IsTempAccessKeyID(accessKeyID) {
		return nil, "", ErrInvalidSessionToken
	}

	user, err := store.GetUserByAccessKeyID(ctx, accessKeyID)
	if err != nil {
		return nil, "", ErrIdentityNotFound
	}

	var keyEntry *types.AccessKeyEntry
	for i := range user.AccessKeys {
		if user.AccessKeys[i].AccessKeyId == accessKeyID {
			keyEntry = &user.AccessKeys[i]
			break
		}
	}
	if keyEntry == nil || keyEntry.Status != AccessKeyStatusActive {
		return nil, "", ErrIdentityNotFound
	}

	identity := &types.Identity{
		User:             user,
		IdentityPolicies: user.Policies.Inline,
	}
	return identity, keyEntry.SecretAccessKey, nil
}
