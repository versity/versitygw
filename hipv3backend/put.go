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
	"github.com/versity/versitygw/rdma/rcdial"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// PutObject serves a bodyless v3 PUT: pull the object bytes from the
// client's memory region with an RDMA READ, verify any request
// checksum over the staged bytes, then hand the wrapped backend a
// fresh reader whose length is the token's. Requests without a v3
// descriptor delegate unchanged.
func (s *Server) PutObject(ctx context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	tok, ok := descriptorOf(ctx)
	if !ok {
		return s.Backend.PutObject(ctx, po)
	}
	staged, err := s.readStaging(ctx, tok)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := verifyChecksums(staged, &po); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	logical := int64(len(staged))
	po.Body = bytes.NewReader(staged)
	po.ContentLength = &logical
	out, err := s.Backend.PutObject(ctx, po)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	debuglogger.Logf("hipv3: PUT %q via RDMA READ of %d bytes", deref(po.Key), logical)
	return out, nil
}

// UploadPart serves a bodyless v3 part upload the same way.
func (s *Server) UploadPart(ctx context.Context, up *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	tok, ok := descriptorOf(ctx)
	if !ok {
		return s.Backend.UploadPart(ctx, up)
	}
	staged, err := s.readStaging(ctx, tok)
	if err != nil {
		return nil, err
	}
	logical := int64(len(staged))
	up.Body = io.NopCloser(bytes.NewReader(staged))
	if up.ContentLength == nil {
		up.ContentLength = new(int64)
	}
	*up.ContentLength = logical
	out, err := s.Backend.UploadPart(ctx, up)
	if err != nil {
		return nil, err
	}
	debuglogger.Logf("hipv3: UploadPart %q part %d via RDMA READ of %d bytes",
		deref(up.Key), derefUint32(up.PartNumber), logical)
	return out, nil
}

// readStaging bounds, dials, and pulls tok.Length bytes from the
// client's region into freshly allocated staging memory.
func (s *Server) readStaging(ctx context.Context, tok rcdial.Token) ([]byte, error) {
	if tok.Length == 0 || tok.Length > s.cfg.MaxStaging {
		return nil, s3err.APIError{
			Code:           "InvalidRequest",
			Description:    "hipobj-rc-v3 transfer length out of range",
			HTTPStatusCode: 400,
		}
	}
	conn, err := s.dialer.Dial(tok)
	if err != nil {
		debuglogger.Logf("hipv3: dial %s failed: %v", tok.ListenAddr(), err)
		return nil, rdmaTransferFailed("dial", err)
	}
	defer conn.Close()
	staging := make([]byte, tok.Length)
	n, err := conn.Read(staging, tok.RKey, tok.RemoteAddr)
	if err != nil {
		debuglogger.Logf("hipv3: RDMA READ of %d bytes failed after %d: %v", tok.Length, n, err)
		return nil, rdmaTransferFailed("read", err)
	}
	if uint64(n) != tok.Length {
		debuglogger.Logf("hipv3: short RDMA READ: got %d of %d bytes", n, tok.Length)
		return nil, rdmaTransferFailed("read", errors.New("short transfer"))
	}
	return staging, nil
}

// checksumPairs maps the staged-verify step onto the request's
// checksum fields. Only the algorithms the input carries are
// verified; the HashReader compares at EOF and returns the normal
// BadDigest checksum error on mismatch, failing before the backend
// sees any data.
func verifyChecksums(staged []byte, po *s3response.PutObjectInput) error {
	pairs := []struct {
		expected *string
		ht       utils.HashType
	}{
		{po.ChecksumCRC32, utils.HashTypeCRC32},
		{po.ChecksumCRC32C, utils.HashTypeCRC32C},
		{po.ChecksumCRC64NVME, utils.HashTypeCRC64NVME},
		{po.ChecksumSHA1, utils.HashTypeSha1},
		{po.ChecksumSHA256, utils.HashTypeSha256},
		{po.ChecksumSHA512, utils.HashTypeSha512},
		{po.ChecksumXXHASH64, utils.HashTypeXXHASH64},
		{po.ChecksumXXHASH3, utils.HashTypeXXHASH3},
		{po.ChecksumXXHASH128, utils.HashTypeXXHASH128},
	}
	for _, p := range pairs {
		if p.expected == nil || *p.expected == "" {
			continue
		}
		hr, err := utils.NewHashReader(bytes.NewReader(staged), *p.expected, p.ht)
		if err != nil {
			return s3err.APIError{
				Code:           "InvalidRequest",
				Description:    err.Error(),
				HTTPStatusCode: 400,
			}
		}
		if _, err := io.Copy(io.Discard, hr); err != nil {
			return err
		}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefUint32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}
