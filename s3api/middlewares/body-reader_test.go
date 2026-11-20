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

package middlewares

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func TestNewChecksumReader_PreservesMetadataThroughHashReader(t *testing.T) {
	const payload = "hello"
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	sha, otherSha := sha256.Sum256([]byte(payload)), sha256.Sum256([]byte("other"))
	md, otherMd := md5.Sum([]byte(payload)), md5.Sum([]byte("other"))

	// stacks the readers the way the middlewares do: the chunk reader
	// first, then the Content-MD5 hash reader on top of it
	newReader := func(t *testing.T, contentMD5, trailer string) ChecksumReader {
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-sha256:%s\r\n\r\n", len(payload), payload, trailer)
		chunk, err := utils.NewUnsignedChunkReader(strings.NewReader(body), "x-amz-checksum-sha256", int64(len(payload)))
		require.NoError(t, err)
		md5Rdr, err := utils.NewHashReader(chunk, contentMD5, utils.HashTypeContentMD5)
		require.NoError(t, err)
		cr, ok := NewChecksumReader(chunk, md5Rdr).(ChecksumReader)
		require.True(t, ok)
		return cr
	}

	t.Run("metadata preserved", func(t *testing.T) {
		cr := newReader(t, b64(md[:]), b64(sha[:]))
		// the backends check the algorithm before reading the body
		require.Equal(t, "sha256", cr.Algorithm())
		data, err := io.ReadAll(cr)
		require.NoError(t, err)
		require.Equal(t, payload, string(data))
		require.Equal(t, b64(sha[:]), cr.Checksum())
	})

	t.Run("content-md5 mismatch", func(t *testing.T) {
		_, err := io.ReadAll(newReader(t, b64(otherMd[:]), b64(sha[:])))
		require.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrBadDigest))
	})

	t.Run("trailing checksum mismatch", func(t *testing.T) {
		_, err := io.ReadAll(newReader(t, b64(md[:]), b64(otherSha[:])))
		require.ErrorIs(t, err, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmSha256))
	})
}
