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
	"github.com/versity/versitygw/cumiddleware"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/rdma/rcdial"
)

// GetObject serves a v3 GET: read the object (or range) through the
// wrapped backend, gate the resolved length against the token, push
// the bytes to the client's memory region with an RDMA WRITE, and
// return a bodyless response. Requests without a v3 descriptor
// delegate unchanged.
func (s *Server) GetObject(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	tok, ok := descriptorOf(ctx)
	if !ok {
		return s.Backend.GetObject(ctx, in)
	}
	res, err := s.Backend.GetObject(ctx, in)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	size := derefI64(res.ContentLength)
	if res.ContentRange != nil && *res.ContentRange != "" {
		// The resolved range length is what the token must match.
		if size == 0 {
			return nil, s3RangeLengthError()
		}
	}
	if uint64(size) != tok.Length {
		debuglogger.Logf("hipv3: GET length mismatch: object/range %d, token %d", size, tok.Length)
		return nil, s3RangeLengthError()
	}
	staged, err := io.ReadAll(res.Body)
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
	debuglogger.Logf("hipv3: GET %q via RDMA WRITE of %d bytes", deref(in.Key), tok.Length)
	return res, nil
}

// s3RangeLengthError is the defined non-success for a token whose
// length disagrees with the resolved object/range: the client would
// silently accept a truncated object (it compares the reply count
// against its own requested size), so mismatch must fail closed.
func s3RangeLengthError() error {
	return errLengthMismatch{}
}

type errLengthMismatch struct{}

func (errLengthMismatch) Error() string {
	return "hipobj-rc-v3 token length does not match the resolved object or range length"
}

// ReplyHeader exposes the value the response layer stamps on a
// successful transfer.
func ReplyHeader(bytes uint64) string {
	return rcdial.FormatReply(200, bytes)
}

var _ = cumiddleware.HeaderRDMAv3Reply

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
