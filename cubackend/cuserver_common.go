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

package cubackend

import (
	"github.com/versity/versitygw/rdma"
)

// CuServerOpts configures the CuServer backend.
type CuServerOpts struct {
	// RDMAIP is the server IP address for the RDMA interface.
	RDMAIP string
	// RDMAPort is the server port for the RDMA interface.
	RDMAPort uint16

	// Pool configuration
	PoolBufSize  int // Size of each RDMA buffer (default: 1 GiB)
	PoolBufCount int // Number of RDMA buffers to pre-allocate (default: 4)

	// RDMATunables configures low-level RDMA connection parameters applied
	// before the session starts. If nil, cuObjServer library defaults are
	// used. Use rdma.DefaultRDMATunables() as a starting point.
	RDMATunables *rdma.RDMATunables
}
