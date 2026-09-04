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

//go:build linux && amd64 && cgo

package rcroutes

import (
	"errors"

	"github.com/versity/versitygw/rdma/rcserver"
)

// This file keeps the Linux-only error classifiers next to the
// shared terminal serializer in errors.go. The marker types below
// carry only the intended protocol class; the HTTP status and XML
// body are decided in one place.

// errRouteBadRequest marks a malformed control request (invalid
// header value, bad argument).
type errRouteBadRequest struct{}

func (errRouteBadRequest) Error() string { return "invalid RDMA control request" }

// errRouteUnavailable marks admission refusal during shutdown.
type errRouteUnavailable struct{}

func (errRouteUnavailable) Error() string {
	return "RDMA service is shutting down"
}

// isRouteBadRequest reports whether err is a malformed-request
// class error: an invalid header value from the route handlers or
// a rejected argument, short transfer, or oversized value from
// the session server.
func isRouteBadRequest(err error) bool {
	var bad errRouteBadRequest
	return errors.As(err, &bad) ||
		errors.Is(err, rcserver.ErrShort) ||
		errors.Is(err, rcserver.ErrTrunc) ||
		errors.Is(err, rcserver.ErrArg)
}

// isRouteNotFound reports whether err identifies an unknown or
// cross-principal session; both map to the same response so the
// session id is not disclosed across principals.
func isRouteNotFound(err error) bool {
	return errors.Is(err, rcserver.ErrNoSession)
}

// isRouteConflict reports whether err is a stale, duplicate, or
// wrong-state session error.
func isRouteConflict(err error) bool {
	return errors.Is(err, rcserver.ErrStale) ||
		errors.Is(err, rcserver.ErrState) ||
		errors.Is(err, rcserver.ErrDouble)
}

// isRouteLimit reports whether err was caused by a configured
// resource limit.
func isRouteLimit(err error) bool {
	return errors.Is(err, rcserver.ErrLimit)
}

// isRouteBadGateway reports whether the RC wire transfer failed.
func isRouteBadGateway(err error) bool {
	return errors.Is(err, rcserver.ErrWire)
}

// isRouteUnavailable reports whether the RC service refused
// admission or is shutting down.
func isRouteUnavailable(err error) bool {
	var unavail errRouteUnavailable
	return errors.As(err, &unavail)
}
