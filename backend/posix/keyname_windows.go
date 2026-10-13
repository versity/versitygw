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

package posix

import "path/filepath"

// encodeKeysDefault stores the keys under names that are valid on Windows.
const encodeKeysDefault = true

// isReservedName reports whether Windows opens a device for the path element
// name, which has no path separator or colon. A device name with an extension,
// such as NUL.txt, is a device on Windows 10 but not on Windows 11, which
// filepath.IsLocal asks the system about.
func isReservedName(name string) bool {
	return !filepath.IsLocal(name)
}
