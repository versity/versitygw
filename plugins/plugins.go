// Copyright 2025 Versity Software
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

package plugins

import "github.com/versity/versitygw/backend"

// BackendPlugin defines an interface for creating backend
// implementation instances.
// Plugins implementing this interface can be built as shared
// libraries using Go's plugin system (to build use `go build -buildmode=plugin`).
// The shared library should export an instance of
// this interface in a variable named `Backend`.
type BackendPlugin interface {
	// New creates and initializes a new backend.Backend instance.
	// The config parameter specifies the path of the file containing
	// the configuration for the backend.
	//
	// Implementations of this method should perform the necessary steps to
	// establish a connection to the underlying storage system or service
	// (e.g., network storage system, distributed storage system, cloud storage)
	//  and configure it according to the provided configuration.
	New(config string) (backend.Backend, error)
}
