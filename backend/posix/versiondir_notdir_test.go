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

package posix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
)

// TestVersionDirNotDir covers reading a version directory that fails with
// ENOTDIR, which some shared filesystems return when another client removes
// the directory. It's handled like a missing version directory. A regular
// file in place of the directory produces the same error.
func TestVersionDirNotDir(t *testing.T) {
	setup := func(t *testing.T, key string) (*Posix, string, string) {
		t.Helper()
		t.Chdir(t.TempDir())
		p, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{
			ValidateBucketNames: true,
			VersioningDir:       t.TempDir(),
		})
		require.NoError(t, err)
		createTestBucket(t, p, "bucket")
		require.NoError(t, p.PutBucketVersioning(context.Background(), "bucket", types.BucketVersioningStatusEnabled))

		var body string
		if !strings.HasSuffix(key, "/") {
			body = "data"
		}
		out, err := p.PutObject(context.Background(), s3response.PutObjectInput{
			Bucket:        aws.String("bucket"),
			Key:           aws.String(key),
			Body:          strings.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		})
		require.NoError(t, err)

		versionPath := p.genObjVersionPath("bucket", p.encodeKey(key))
		require.NoError(t, os.RemoveAll(versionPath))
		require.NoError(t, os.MkdirAll(filepath.Dir(versionPath), 0o755))
		require.NoError(t, os.WriteFile(versionPath, nil, 0o644))

		return p, versionPath, out.VersionID
	}

	t.Run("list object versions", func(t *testing.T) {
		p, _, versionId := setup(t, "obj")

		res, err := p.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{
			Bucket:  aws.String("bucket"),
			MaxKeys: aws.Int32(1000),
		})
		require.NoError(t, err)
		// same result as with no version directory
		for _, v := range res.Versions {
			assert.Equal(t, versionId, aws.ToString(v.VersionId))
		}
	})

	for name, key := range map[string]string{
		"delete object version":           "obj",
		"delete directory object version": "dir/",
	} {
		t.Run(name, func(t *testing.T) {
			p, _, versionId := setup(t, key)

			_, err := p.DeleteObject(context.Background(), &s3.DeleteObjectInput{
				Bucket:    aws.String("bucket"),
				Key:       aws.String(key),
				VersionId: aws.String(versionId),
			})
			require.NoError(t, err)
			assert.NoFileExists(t, p.ObjectPath("bucket", key))
		})
	}

	t.Run("newest object version id", func(t *testing.T) {
		_, versionPath, _ := setup(t, "obj")

		id, err := newestObjVersionId(versionPath)
		require.NoError(t, err)
		assert.Empty(t, id)
	})
}
