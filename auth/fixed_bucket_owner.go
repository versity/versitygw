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

// FixedBucketOwner is implemented by IAM backends that give every bucket the
// same owner instead of the account that created it — currently only the
// standalone IAM service client, which has no per-user ownership to express:
// every account is a plain RoleUser, they cannot be enumerated, and access is
// decided by IAM policy rather than by ACL.
//
// Backends that do not implement it keep per-creator ownership as before.
type FixedBucketOwner interface {
	BucketOwner() Account
}

// ResolveFixedBucketOwner reports the account that owns every bucket when iam
// fixes ownership, and false when ownership follows the creator instead.
func ResolveFixedBucketOwner(iam IAMService) (Account, bool) {
	fbo, ok := iam.(FixedBucketOwner)
	if !ok {
		return Account{}, false
	}

	return fbo.BucketOwner(), true
}

// rootIdentity returns the account a storage backend should see for a request
// signed with the gateway's root credentials. The S3 request path knows root
// only by its access key and secret, so root would otherwise reach the
// backend with the zero uid/gid — which the posix backend's --chuid/--chgid
// then tries to chown to, an operation an unprivileged gateway can never
// perform.
//
// An IAM backend that fixes bucket ownership to root also defines the POSIX
// identity root owns those buckets with, so take it from there: root's own
// object writes then land with the same ownership as the buckets root owns.
// Backends that do not fix ownership resolve a real per-account uid/gid for
// every other account and keep root exactly as it was.
//
// The same backend is also the one that knows root's principal ARN, which
// the S3 request path likewise cannot derive: root is the only identity
// resolved locally rather than through the IAM service, so without this it
// would reach bucket-policy matching unnamed and a statement naming the
// account root ARN would miss it.
func rootIdentity(iam IAMService, root Account) Account {
	owner, fixed := ResolveFixedBucketOwner(iam)
	if !fixed || owner.Access != root.Access {
		return root
	}

	root.UserID = owner.UserID
	root.GroupID = owner.GroupID
	root.ProjectID = owner.ProjectID
	root.Arn = owner.Arn
	return root
}
