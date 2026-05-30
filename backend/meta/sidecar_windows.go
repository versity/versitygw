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

//go:build windows

package meta

import "os"

// fileIno returns 0 on Windows because Windows does not expose POSIX inodes
// via the standard syscall interface.  tmpSidecarID falls back to the
// path-based identifier, which is always unique on Windows because
// CreateTemp generates uniquely-named files.
func fileIno(_ *os.File) uint64 {
	return 0
}

// pathIno returns 0 on Windows; POSIX inodes are not available.
func pathIno(_ string) uint64 {
	return 0
}
