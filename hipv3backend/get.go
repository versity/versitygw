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

package hipv3backend

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// GetObject serves a v3 GET: resolve the object (or range) through
// the wrapped backend, gate the resolved length against the token
// and the staging limit, push the bytes to the client's memory
// region with an RDMA WRITE, and return a bodyless response whose
// reply header reports 200 for a full object or 206 for a range. On
// any failure the reply header stays absent. Requests without a v3
// descriptor delegate unchanged.
func (s *Server) GetObject(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	tok, ok := descriptorOf(ctx)
	if !ok {
		return s.Backend.GetObject(ctx, in)
	}
	if !s.dialer.TransportSupported() {
		return nil, errUnsupported()
	}
	if tok.Length == 0 || tok.Length > s.cfg.MaxStaging {
		return nil, s3err.APIError{
			Code:           "InvalidRequest",
			Description:    "hipobj-rc-v3 transfer length out of range",
			HTTPStatusCode: 400,
		}
	}
	res, err := s.Backend.GetObject(ctx, in)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	ranged := res.ContentRange != nil && *res.ContentRange != ""
	size := derefI64(res.ContentLength)
	if uint64(size) != tok.Length {
		debuglogger.Logf("hipv3: GET length mismatch: object/range %d, token %d", size, tok.Length)
		return nil, s3RangeLengthError()
	}
	// The staging limit bounds the read too, so an inconsistent
	// backend stream cannot grow the allocation past it.
	staged, err := io.ReadAll(io.LimitReader(res.Body, int64(s.cfg.MaxStaging)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(staged)) != tok.Length {
		debuglogger.Logf("hipv3: GET body length %d differs from resolved %d", len(staged), size)
		return nil, s3RangeLengthError()
	}

	conn, err := s.dialer.Dial(tok)
	if err != nil {
		debuglogger.Logf("hipv3: dial %s failed: %v", tok.ListenAddr(), err)
		return nil, rdmaTransferFailed("dial", err)
	}
	defer conn.Close()
	n, err := conn.Write(staged, tok.RKey, tok.RemoteAddr)
	if err != nil {
		debuglogger.Logf("hipv3: RDMA WRITE of %d bytes failed after %d: %v", tok.Length, n, err)
		return nil, rdmaTransferFailed("write", err)
	}
	if uint64(n) != tok.Length {
		debuglogger.Logf("hipv3: short RDMA WRITE: got %d of %d bytes", n, tok.Length)
		return nil, rdmaTransferFailed("write", errors.New("short transfer"))
	}

	// Bodyless framing: the data went over RDMA, the HTTP response
	// carries headers only.
	res.Body = io.NopCloser(bytes.NewReader(nil))
	zero := int64(0)
	res.ContentLength = &zero
	status := 200
	if ranged {
		status = 206
	}
	SetReply(ctx, status, tok.Length)
	debuglogger.Logf("hipv3: GET %q via RDMA WRITE of %d bytes (status %d)",
		deref(in.Key), tok.Length, status)
	return res, nil
}

// s3RangeLengthError is the defined non-success for a token whose
// length disagrees with the resolved object/range: the client would
// silently accept a truncated object (it compares the reply count
// against its own requested size), so mismatch must fail closed.
func s3RangeLengthError() error {
	return s3err.APIError{
		Code: "InvalidRequest",
		Description: "hipobj-rc-v3 token length does not match " +
			"the resolved object or range length",
		HTTPStatusCode: 400,
	}
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
