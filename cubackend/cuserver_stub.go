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

//go:build !(linux && amd64 && cgo)

package cubackend

// Package backend provides the cuObject-accelerated storage backend.
// This file is a stub for platforms without RDMA support.

import (
	"fmt"

	"github.com/versity/versitygw/backend"
)

// CuServer is a non-functional stub on platforms without RDMA support.
type CuServer struct {
	backend.BackendUnsupported
}

// New always returns an unsupported-platform error on this build.
func New(opts CuServerOpts, be backend.Backend) (*CuServer, error) {
	return nil, fmt.Errorf("cuserver: RDMA backend not supported on this platform")
}
