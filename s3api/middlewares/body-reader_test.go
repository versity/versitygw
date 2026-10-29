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

	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/s3api/utils"
)

func TestNewChecksumReader_PreservesMetadataThroughHashReader(t *testing.T) {
	payload := "hello"
	sha := sha256.Sum256([]byte(payload))
	trailer := base64.StdEncoding.EncodeToString(sha[:])
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-sha256:%s\r\n\r\n", len(payload), payload, trailer)

	newReader := func(t *testing.T, payload string) io.Reader {
		chunk, err := utils.NewUnsignedChunkReader(strings.NewReader(body), "x-amz-checksum-sha256", int64(len(payload)))
		require.NoError(t, err)
		md5sum := md5.Sum([]byte(payload))
		outer, err := utils.NewHashReader(chunk, base64.StdEncoding.EncodeToString(md5sum[:]), utils.HashTypeContentMD5)
		require.NoError(t, err)
		return NewChecksumReader(chunk, outer)
	}

	t.Run("metadata preserved", func(t *testing.T) {
		rdr := newReader(t, payload)
		cr, ok := rdr.(ChecksumReader)
		require.True(t, ok)
		data, err := io.ReadAll(cr)
		require.NoError(t, err)
		require.Equal(t, payload, string(data))
		require.Equal(t, "sha256", cr.Algorithm())
		require.Equal(t, trailer, cr.Checksum())
	})

	t.Run("md5 mismatch still propagates", func(t *testing.T) {
		rdr := newReader(t, "other")
		_, err := io.ReadAll(rdr)
		require.Error(t, err)
	})
}
