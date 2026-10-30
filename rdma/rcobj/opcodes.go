// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
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

package rcobj

import (
	"net/url"
	"strings"
)

// Error codes mirrored from hipobj.h. Defined in a build-tag-free
// file so callers compare OpError codes under the cgo and stub
// builds alike.
const (
	OpSuccess            = 0
	OpInvalidValue       = 1
	OpNotInitialized     = 2
	OpAlreadyInitialized = 3
	OpRdmaError          = 4
	OpS3Error            = 5
	OpBufNotRegistered   = 6
	OpBufAlreadyReg      = 7
	OpNicNotFound        = 8
	OpDmabufNotSupported = 9
	OpSizeTooLarge       = 10
	OpInternalError      = 11
	OpNotSupported       = 12
	OpBusy               = 13
)

// escapeKeyPath percent-escapes each path segment of an object
// key, preserving the slashes that separate them. Object names may
// contain characters the URL grammar treats as syntax (query,
// fragment, percent) so raw concatenation would address a
// different object than the one named.
func escapeKeyPath(key string) string {
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// probeObjectPath builds the escaped path of the admission probe
// object.
func probeObjectPath(bucket, key string) string {
	return "/" + bucket + "/" + escapeKeyPath(key)
}

// objectTarget is the x-amz-rdma-target path for a bucket/key/query
// triple. The key is escaped the same way as the admission probe so
// a key containing %, ?, or # addresses the same object on PREPARE
// and READY as it does on the probe.
func objectTarget(bucket, key, query string) string {
	t := "/" + bucket + "/" + escapeKeyPath(key)
	if query != "" {
		t += "?" + query
	}
	return t
}
