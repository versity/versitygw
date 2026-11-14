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

package hipv3backend

import (
	"context"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/cumiddleware"
	"github.com/versity/versitygw/rdma/rcdial"
)

// Server decorates a backend with the hipobj-rc-v3 data path for
// PutObject, UploadPart, and GetObject. Requests without a stored v3
// descriptor delegate to the wrapped backend unchanged.
type Server struct {
	backend.Backend
	dialer rcdial.Dialer
	cfg    Config
}

// Config carries the adapter's limits; zero values take the rcdial
// defaults.
type Config struct {
	rcdial.Config
	// MaxStaging bounds the transfer size the adapter accepts. A
	// token asking for more is rejected before any dial.
	MaxStaging uint64
}

// DefaultMaxStaging matches the adapter constructor's fallback.
const DefaultMaxStaging = 1 << 30 // 1 GiB

// New wraps be with the v3 data path over the given dialer.
func New(be backend.Backend, dialer rcdial.Dialer, cfg Config) *Server {
	if cfg.MaxStaging == 0 {
		cfg.MaxStaging = DefaultMaxStaging
	}
	if dialer == nil {
		dialer = rcdial.NewDialer(cfg.Config)
	}
	return &Server{Backend: be, dialer: dialer, cfg: cfg}
}

// descriptorOf fetches the parsed token the middleware stored on the
// request context.
func descriptorOf(ctx context.Context) (rcdial.Token, bool) {
	return cumiddleware.GetV3Descriptor(ctx)
}
