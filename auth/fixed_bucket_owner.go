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
