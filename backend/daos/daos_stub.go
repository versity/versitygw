// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

//go:build !(linux && cgo && daos)

package daos

import "fmt"

// New reports that the DFS client is not linked into this build. It does not
// connect. pool, container, and sysName are accepted so the command line has
// one signature in every build.
func New(pool, container, sysName string) (*Daos, error) {
	return nil, fmt.Errorf("daos backend requires -tags daos on Linux with cgo")
}
