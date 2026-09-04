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
	"fmt"
	"net/http"
	"testing"

	"github.com/versity/versitygw/rdma/rcserver"
)

// This file verifies the mapping from session-server failures to
// protocol error responses. It runs where the Linux session
// server links; the s3api package exercises the shared
// serializer through the production S3 server on every platform.

func TestRouteErrorProtocolMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
		want int
	}{
		{
			name: "invalid header is 400",
			err:  invalidHeader(hdrProtocol, "bogus"),
			code: "InvalidRdmaRequest",
			want: http.StatusBadRequest,
		},
		{
			name: "unknown session is 404",
			err:  rcserver.ErrNoSession,
			code: "NoSuchRdmaSession",
			want: http.StatusNotFound,
		},
		{
			name: "owner mismatch answers as unknown session",
			err:  fmt.Errorf("session owner mismatch: %w", rcserver.ErrNoSession),
			code: "NoSuchRdmaSession",
			want: http.StatusNotFound,
		},
		{
			name: "stale session is 409",
			err:  rcserver.ErrStale,
			code: "RdmaSessionConflict",
			want: http.StatusConflict,
		},
		{
			name: "duplicate borrow is 409",
			err:  fmt.Errorf("peer busy: %w", rcserver.ErrDouble),
			code: "RdmaSessionConflict",
			want: http.StatusConflict,
		},
		{
			name: "wrong session state is 409",
			err:  rcserver.ErrState,
			code: "RdmaSessionConflict",
			want: http.StatusConflict,
		},
		{
			name: "resource limit is 429",
			err:  rcserver.ErrLimit,
			code: "RdmaResourceLimit",
			want: http.StatusTooManyRequests,
		},
		{
			name: "wire failure is 502",
			err:  rcserver.ErrWire,
			code: "RdmaTransferFailed",
			want: http.StatusBadGateway,
		},
		{
			name: "short transfer is 400",
			err:  rcserver.ErrShort,
			code: "InvalidRdmaRequest",
			want: http.StatusBadRequest,
		},
		{
			name: "value too long is 400",
			err:  rcserver.ErrTrunc,
			code: "InvalidRdmaRequest",
			want: http.StatusBadRequest,
		},
		{
			name: "invalid argument is 400",
			err:  rcserver.ErrArg,
			code: "InvalidRdmaRequest",
			want: http.StatusBadRequest,
		},
		{
			name: "admission refusal is 503",
			err:  errNotAdmitted(),
			code: "RdmaServiceUnavailable",
			want: http.StatusServiceUnavailable,
		},
		{
			name: "unexpected error is 500",
			err:  errors.New("boom"),
			code: "InternalError",
			want: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeError(tt.err)
			if got.HTTPStatusCode != tt.want {
				t.Fatalf("status = %d, want %d", got.HTTPStatusCode, tt.want)
			}
			if got.Code != tt.code {
				t.Fatalf("code = %q, want %q", got.Code, tt.code)
			}
		})
	}
}
