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

package utils

import (
	"context"

	"github.com/versity/versitygw/rdma/rcdial"
)

// V3DescriptorKey is the user-value key the hipobj-rc-v3 middleware
// stores the parsed token under; it lives here so the controllers
// can read the logical transfer length without importing the
// middleware (which would cycle).
const V3DescriptorKey = "hipv3.rdma.descriptor"

// V3LogicalLength returns the transfer length of a stored v3 token,
// if the request carries one. The controllers use it as the logical
// object/part length: an RDMA PUT has an empty HTTP body (Content-
// Length 0), so the HTTP header cannot supply it.
func V3LogicalLength(ctx context.Context) (int64, bool) {
	if ctx == nil {
		return 0, false
	}
	v := ctx.Value(V3DescriptorKey)
	tok, ok := v.(rcdial.Token)
	if !ok || tok.Length == 0 {
		return 0, false
	}
	return int64(tok.Length), true
}
