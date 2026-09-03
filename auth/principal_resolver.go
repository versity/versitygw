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

// PrincipalResolver is implemented by IAM backends whose identities are
// named by AWS-style principal ARNs — currently only the standalone IAM
// service client. Its presence is what switches a bucket policy's Principal
// element from naming access key ids to naming ARNs, the way real S3 does.
//
// Every other backend (internal, LDAP, Vault, IPA, S3, single) has no ARNs
// to name anything by: its accounts are access keys and nothing else. Those
// backends do not implement this, and their bucket policies keep naming
// access key ids exactly as before.
type PrincipalResolver interface {
	// ResolvePrincipals returns the subset of principals that do not name
	// anything — the write-time check behind PutBucketPolicy, mirroring
	// ResolveAccounts' "return what does not exist" contract for access
	// keys. The wildcard "*" is handled by the caller and never reaches
	// here.
	ResolvePrincipals(principals []string) ([]string, error)
}
