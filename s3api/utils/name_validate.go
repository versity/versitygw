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

package utils

import (
	"strings"

	"github.com/versity/versitygw/backend"
)

// IsObjectNameValid reports whether name can name an object of be. A name
// made of slashes only can't. S3 takes "." and ".." segments as part of
// the key, so a name holding them can only when be stores it as a key of
// its own: a backend storing objects as files would resolve the segments
// to another object, or to a path outside the bucket.
func IsObjectNameValid(name string, be backend.Backend) bool {
	if strings.Trim(name, "/") == "" {
		return false
	}

	return !hasDotSegment(name) || be.StoresDotSegmentKeys()
}

// hasDotSegment reports whether name holds a "." or ".." segment.
func hasDotSegment(name string) bool {
	for seg := range strings.SplitSeq(name, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}
