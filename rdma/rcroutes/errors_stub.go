// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

//go:build !(linux && amd64 && cgo)

package rcroutes

import "errors"

// errRouteNotImplemented marks the platform-stub answer of the
// control routes.
type errRouteNotImplemented struct{}

func (errRouteNotImplemented) Error() string {
	return "RDMA not supported on this platform"
}

// isRouteNotImplemented reports whether the platform stub answered
// the request.
func isRouteNotImplemented(err error) bool {
	var ni errRouteNotImplemented
	return errors.As(err, &ni)
}

// isRouteBadRequest reports whether err is a malformed-request
// class error. The stub never classifies request errors because it
// answers before validation.
func isRouteBadRequest(err error) bool { return false }

// isRouteNotFound reports whether err identifies an unknown
// session. Never true on the stub.
func isRouteNotFound(err error) bool { return false }

// isRouteConflict reports whether err is a session-state conflict.
// Never true on the stub.
func isRouteConflict(err error) bool { return false }

// isRouteLimit reports whether err was caused by a resource
// limit. Never true on the stub.
func isRouteLimit(err error) bool { return false }

// isRouteBadGateway reports whether the RC wire transfer failed.
// Never true on the stub.
func isRouteBadGateway(err error) bool { return false }

// isRouteUnavailable reports whether the RC service refused
// admission. Never true on the stub.
func isRouteUnavailable(err error) bool { return false }
