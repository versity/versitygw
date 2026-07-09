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

package iamutil

import (
	"net/url"
	"strings"
)

// EncodePolicyDocument RFC 3986 percent-encodes a policy document string
// the way real IAM encodes the PolicyDocument element of GetUserPolicy (and
// will for GetRolePolicy) responses: every character outside the unreserved
// set is percent-encoded, with the space character encoded as %20 rather
// than the "+" that url.QueryEscape alone would produce.
func EncodePolicyDocument(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
