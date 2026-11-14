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

// errUnsupported maps to the documented 501: the request is a valid
// v3 transfer but this build carries no RDMA transport.
func errUnsupported() error {
	return s3err.APIError{
		Code:           "NotImplemented",
		Description:    "hipobj-rc-v3 requires a gateway built with the rdma transport",
		HTTPStatusCode: 501,
	}
}

// PutObject serves a bodyless v3 PUT: pull the object bytes from the
// client's memory region with an RDMA READ, verify any request
// checksum over the staged bytes, then hand the wrapped backend a
// fresh reader whose length is the token's. On complete success the
// reply header is recorded for the response layer. Requests without
// a v3 descriptor delegate unchanged.
func (s *Server) PutObject(ctx context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	tok, ok := descriptorOf(ctx)
	if !ok {
		return s.Backend.PutObject(ctx, po)
	}
	if !s.dialer.TransportSupported() {
		return s3response.PutObjectOutput{}, errUnsupported()
	}
	staged, err := s.readStaging(tok)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := verifyChecksums(staged, checksumFieldsOf(&po, nil)); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	logical := int64(len(staged))
	po.Body = bytes.NewReader(staged)
	po.ContentLength = &logical
	out, err := s.Backend.PutObject(ctx, po)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	SetReply(ctx, 200, uint64(logical))
	debuglogger.Logf("hipv3: PUT %q via RDMA READ of %d bytes", deref(po.Key), logical)
	return out, nil
}

// UploadPart serves a bodyless v3 part upload the same way, sharing
// the complete checksum verification.
func (s *Server) UploadPart(ctx context.Context, up *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	tok, ok := descriptorOf(ctx)
	if !ok {
		return s.Backend.UploadPart(ctx, up)
	}
	if !s.dialer.TransportSupported() {
		return nil, errUnsupported()
	}
	staged, err := s.readStaging(tok)
	if err != nil {
		return nil, err
	}
	if err := verifyChecksums(staged, checksumFieldsOf(nil, up)); err != nil {
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
	SetReply(ctx, 200, uint64(logical))
	debuglogger.Logf("hipv3: UploadPart %q part %d via RDMA READ of %d bytes",
		deref(up.Key), derefInt32(up.PartNumber), logical)
	return out, nil
}

// readStaging bounds, dials, and pulls tok.Length bytes from the
// client's region. The staging buffer is owned by the connection for
// the duration of the READ only; the returned copy is ordinary Go
// memory.
func (s *Server) readStaging(tok rcdial.Token) ([]byte, error) {
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
	raw, free, err := conn.Read(tok.Length, tok.RKey, tok.RemoteAddr)
	if err != nil {
		debuglogger.Logf("hipv3: RDMA READ of %d bytes failed: %v", tok.Length, err)
		return nil, rdmaTransferFailed("read", err)
	}
	defer free()
	if uint64(len(raw)) != tok.Length {
		debuglogger.Logf("hipv3: short RDMA READ: got %d of %d bytes", len(raw), tok.Length)
		return nil, rdmaTransferFailed("read", errors.New("short transfer"))
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// checksumFieldsOf projects either upload input's checksum fields
// onto the shared verification table.
func checksumFieldsOf(po *s3response.PutObjectInput, up *s3.UploadPartInput) checksumFields {
	if po != nil {
		return checksumFields{
			crc32: po.ChecksumCRC32, crc32c: po.ChecksumCRC32C,
			crc64nvme: po.ChecksumCRC64NVME, sha1: po.ChecksumSHA1,
			sha256: po.ChecksumSHA256, sha512: po.ChecksumSHA512,
			md5: po.ChecksumMD5, xxhash64: po.ChecksumXXHASH64,
			xxhash3: po.ChecksumXXHASH3, xxhash128: po.ChecksumXXHASH128,
		}
	}
	return checksumFields{
		crc32: up.ChecksumCRC32, crc32c: up.ChecksumCRC32C,
		crc64nvme: up.ChecksumCRC64NVME, sha1: up.ChecksumSHA1,
		sha256: up.ChecksumSHA256, sha512: up.ChecksumSHA512,
		md5: up.ChecksumMD5, xxhash64: up.ChecksumXXHASH64,
		xxhash3: up.ChecksumXXHASH3, xxhash128: up.ChecksumXXHASH128,
	}
}

type checksumFields struct {
	crc32, crc32c, crc64nvme     *string
	sha1, sha256, sha512, md5    *string
	xxhash64, xxhash3, xxhash128 *string
}

// verifyChecksums runs one HashReader per carried algorithm over the
// staged bytes, consuming it to EOF (the point where the comparison
// happens); a mismatch fails before the backend sees any data.
func verifyChecksums(staged []byte, f checksumFields) error {
	pairs := []struct {
		expected *string
		ht       utils.HashType
	}{
		{f.crc32, utils.HashTypeCRC32},
		{f.crc32c, utils.HashTypeCRC32C},
		{f.crc64nvme, utils.HashTypeCRC64NVME},
		{f.sha1, utils.HashTypeSha1},
		{f.sha256, utils.HashTypeSha256},
		{f.sha512, utils.HashTypeSha512},
		{f.md5, utils.HashTypeMd5},
		{f.xxhash64, utils.HashTypeXXHASH64},
		{f.xxhash3, utils.HashTypeXXHASH3},
		{f.xxhash128, utils.HashTypeXXHASH128},
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

func derefInt32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}
