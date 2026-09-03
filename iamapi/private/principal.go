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
	"errors"
	"strings"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
)

// accountIDLen is the length of an AWS account id, and the length the bare
// account-id principal form must have.
const accountIDLen = 12

// principalResolves reports whether principal names an identity that exists
// right now, in the form an S3 bucket policy's Principal element may take.
// It is the write-time check behind PutBucketPolicy: a statement naming
// something that cannot be resolved is rejected rather than stored as one
// that can never match.
//
// The accepted forms, all scoped to accountID — this service serves exactly
// one account, and an ARN naming another cannot name anything it knows:
//
//	arn:aws:iam::<account>:root            the account itself
//	<account>                              the same, in the bare account-id form
//	arn:aws:iam::<account>:user<path><name>  an existing IAM user
//	arn:aws:iam::<account>:role<path><name>  an existing IAM role
//	arn:aws:sts::<account>:assumed-role/<role>/<session>
//	                                       any session of an existing role
//
// A user's or role's ARN embeds its IAM path, so an ARN that omits the path
// of a path-bearing identity does not resolve — the comparison below is
// against the identity's own stored ARN, which enforces that, and the
// case-sensitivity of the whole string, without either being a rule of its
// own.
//
// The session name in an assumed-role ARN is not checked for EXISTENCE —
// it names a session that need not have been minted yet, and commonly
// won't have been when the policy is written — but it must still be a
// session name that could exist: the same grammar
// AssumeRoleWithWebIdentity enforces on RoleSessionName. Without that,
// "assumed-role/reader/*" would be stored as a statement that no session
// can ever match, since a caller's session ARN carries a literal name and
// nothing here pattern-matches.
//
// Everything else — a wildcard inside an ARN, a group/policy/
// instance-profile ARN, another partition, another account, an access key
// id — does not resolve. Wildcards in particular: only a whole Principal of
// "*" is special, and that never reaches here.
func principalResolves(ctx context.Context, store iamutil.IdentityStore, accountID, principal string) (bool, error) {
	if principal == accountID && isAccountID(principal) {
		return true, nil
	}

	resource, ok := principalArnResource(principal, "iam", accountID)
	if ok {
		switch {
		case resource == "root":
			return true, nil
		case strings.HasPrefix(resource, "user/"):
			user, err := store.GetUser(ctx, lastArnSegment(resource))
			if err != nil {
				return false, ignoreNoSuchEntity(err)
			}
			return user != nil && user.Arn == principal, nil
		case strings.HasPrefix(resource, "role/"):
			role, err := store.GetRole(ctx, lastArnSegment(resource))
			if err != nil {
				return false, ignoreNoSuchEntity(err)
			}
			return role != nil && role.Arn == principal, nil
		}
		return false, nil
	}

	resource, ok = principalArnResource(principal, "sts", accountID)
	if !ok || !strings.HasPrefix(resource, "assumed-role/") {
		return false, nil
	}
	// An assumed-role ARN is arn:aws:sts::<acct>:assumed-role/<role>/<session>
	// with exactly those two segments: unlike the role's own ARN it never
	// carries the role's path, so a third segment is not a deeper path but a
	// malformed principal.
	roleName, sessionName, found := strings.Cut(strings.TrimPrefix(resource, "assumed-role/"), "/")
	if !found || roleName == "" {
		return false, nil
	}
	if err := iamutil.ValidateRoleSessionName(sessionName); err != nil {
		return false, nil
	}
	role, err := store.GetRole(ctx, roleName)
	if err != nil {
		return false, ignoreNoSuchEntity(err)
	}
	// Role lookup is case-insensitive, so compare against the ARN a session
	// of that role would actually authenticate as. Without this a
	// wrong-case role name would be accepted and then match nothing — the
	// same reason the user and role branches above compare the stored ARN
	// rather than trusting the lookup.
	return role != nil && iamutil.BuildAssumedRoleArn(accountID, role.RoleName, sessionName) == principal, nil
}

// ignoreNoSuchEntity returns nil for the store's "this identity does not
// exist" error — the answer principalResolves is asking for — and err
// itself for anything else, which is a fault in the service rather than a
// verdict on the principal.
func ignoreNoSuchEntity(err error) error {
	var apiErr iamerr.Error
	if errors.As(err, &apiErr) && apiErr.Code == "NoSuchEntity" {
		return nil
	}
	return err
}

// principalArnResource splits principal into the resource part of an
// arn:aws:<service>::<accountID>:<resource> ARN, reporting ok=false for any
// other shape. The region field must be empty, as it is in every IAM and STS
// ARN, and the partition must be "aws": this service has no other.
func principalArnResource(principal, service, accountID string) (resource string, ok bool) {
	prefix := "arn:aws:" + service + "::" + accountID + ":"
	if !strings.HasPrefix(principal, prefix) {
		return "", false
	}
	resource = strings.TrimPrefix(principal, prefix)
	if resource == "" {
		return "", false
	}
	return resource, true
}

// lastArnSegment returns the identity name from an ARN resource such as
// "user/team/sub/alice" — the last segment, everything before it being the
// identity's IAM path.
func lastArnSegment(resource string) string {
	if idx := strings.LastIndex(resource, "/"); idx >= 0 {
		return resource[idx+1:]
	}
	return resource
}

// isAccountID reports whether s is an AWS account id: exactly twelve
// digits.
func isAccountID(s string) bool {
	if len(s) != accountIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
