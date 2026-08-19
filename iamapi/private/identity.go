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
	"context"

	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/sigv4auth"
)

// resolvePrivateIdentity resolves accessKeyID — long-term (AKIA…) or
// temporary (ASIA…) — to its identity and secret, for the S3 gateway to
// authenticate and authorize one of its own data-plane callers.
//
// sessionToken is required for, and only meaningful to, a temporary access
// key; it is what makes resolving a session here safe (see
// iamutil.ResolveSessionByToken). Errors are the iamutil.ErrIdentityNotFound
// / iamutil.ErrInvalidSessionToken sentinels, so the caller can report which
// failure occurred.
func resolvePrivateIdentity(ctx context.Context, store iamutil.IdentityStore, accessKeyID, sessionToken string) (*types.Identity, string, error) {
	if sigv4auth.IsTempAccessKeyID(accessKeyID) {
		return iamutil.ResolveSessionByToken(ctx, store, accessKeyID, sessionToken)
	}
	if sessionToken != "" {
		// A token alongside a permanent credential is always a caller
		// error, and accepting it silently would mask a misrouted request.
		return nil, "", iamutil.ErrInvalidSessionToken
	}
	return iamutil.ResolveUserIdentity(ctx, store, accessKeyID)
}

// identityKind labels what sort of principal an access key belongs to, for
// callers that need to tell an ephemeral session apart from a long-term user
// without holding a session token.
type identityKind string

const (
	identityKindUser    identityKind = "user"
	identityKindSession identityKind = "session"
)

// resolveIdentityMetadata answers "does this access key exist, and what
// principal is it" for each of accessKeyIDs, returning nothing that could
// authenticate anyone — no secret, no derived key, no policy. That is what
// makes it safe to resolve a temporary (ASIA…) key here with no session
// token: knowing a session exists grants nothing, whereas knowing its secret
// grants everything.
//
// It backs the S3 gateway's IAMService.GetUserAccount, whose only real
// consumer is auth.CheckIfAccountsExist — validating the principals named in
// a bucket policy or ACL, one batch per PutBucketPolicy/PutBucketAcl.
// Results are positional: one entry per input, with Found false for keys
// that don't resolve, rather than an error for the whole batch.
func resolveIdentityMetadata(ctx context.Context, store iamutil.IdentityStore, accessKeyIDs []string) []identityMetadata {
	out := make([]identityMetadata, len(accessKeyIDs))
	for i, accessKeyID := range accessKeyIDs {
		if sigv4auth.IsTempAccessKeyID(accessKeyID) {
			session, err := store.GetSession(ctx, accessKeyID)
			if err != nil {
				continue
			}
			out[i] = identityMetadata{
				Found:        true,
				Kind:         identityKindSession,
				PrincipalArn: iamutil.BuildAssumedRoleArn(iamutil.DefaultAccountID, session.RoleName, session.RoleSessionName),
			}
			continue
		}

		identity, _, err := iamutil.ResolveUserIdentity(ctx, store, accessKeyID)
		if err != nil {
			continue
		}
		out[i] = identityMetadata{
			Found:        true,
			Kind:         identityKindUser,
			PrincipalArn: iammiddleware.CallerArn(*identity),
		}
	}
	return out
}

// identityMetadata is one resolveIdentityMetadata result. The zero value
// means "no such access key".
type identityMetadata struct {
	Found        bool
	Kind         identityKind
	PrincipalArn string
}
