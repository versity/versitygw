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

package sigv4auth

import "crypto/subtle"

// SecureCompare reports whether a and b are equal, comparing in time
// independent of their shared-prefix length. Used for authentication
// secrets — a computed SigV4 signature against the one the caller supplied,
// or a session token against its stored value — where an ordinary ==
// comparison's early-exit on the first differing byte could, in principle,
// leak prefix-match information to a sufficiently patient and precise
// remote timing attacker. A length mismatch is reported as unequal without
// running the constant-time comparison at all: subtle.ConstantTimeCompare
// requires equal-length inputs, and the length of a fixed-format
// signature/token is not itself secret.
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
