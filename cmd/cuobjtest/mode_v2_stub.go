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

//go:build (linux && amd64 && (!cgo || !hipobj || cuobjclient_host)) || !linux || !amd64

package main

// runV2Mode is unreachable on stub builds: main gates -v2 behind a
// hasV2Mode check, so the stub never runs. It exists only to keep
// the call site compiling on builds without the hipobj tag.
func runV2Mode(size int) {
	fatalf("cuobjtest: -v2 requires CGO_ENABLED=1 and the hipobj build tag (libhipobj linked)")
}

// hasV2Mode reports whether this binary carries the hipobj-backed
// v2 client mode.
const hasV2Mode = false
