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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestDetectStaleEtag checks that with DetectStaleEtag an object whose file
// was rewritten outside of the gateway is served with an etag made from its
// size and modification time and without its stored checksums, by
// HeadObject, GetObject, ListObjectsV2 and the conditional requests, and
// that a PUT through the gateway makes the stored etag current again.
// Without the option the stored etag is still returned.
func TestDetectStaleEtag(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		for _, detect := range []bool{false, true} {
			sub := name
			if detect {
				sub += "/detect"
			}
			t.Run(sub, func(t *testing.T) {
				p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
					storer, opts := mkMeta(t)
					opts.AbsolutePaths = true
					opts.DetectStaleEtag = detect
					return storer, opts
				})
				ctx := context.Background()
				bucket, key := "testbucket", "dir/obj"
				createTestBucket(t, p, bucket)

				put := func(body string) string {
					t.Helper()
					out, err := p.PutObject(ctx, s3response.PutObjectInput{
						Bucket:        &bucket,
						Key:           &key,
						Body:          strings.NewReader(body),
						ContentLength: aws.Int64(int64(len(body))),
					})
					require.NoError(t, err)
					return out.ETag
				}
				head := func() *s3.HeadObjectOutput {
					t.Helper()
					out, err := p.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:       &bucket,
						Key:          &key,
						ChecksumMode: types.ChecksumModeEnabled,
					})
					require.NoError(t, err)
					return out
				}

				written := put("v1")
				h := head()
				assert.Equal(t, written, aws.ToString(h.ETag))
				assert.NotNil(t, h.ChecksumCRC64NVME)

				// rewrite the file in place, the way an NFS or SMB client
				// does: the inode and its extended attributes are kept
				path := p.ObjectPath(bucket, key)
				require.NoError(t, os.WriteFile(path, []byte("v2-longer"), 0o644))
				mtime := time.Now().Add(time.Minute)
				require.NoError(t, os.Chtimes(path, mtime, mtime))

				h = head()
				assert.Equal(t, int64(len("v2-longer")), aws.ToInt64(h.ContentLength))
				if !detect {
					assert.Equal(t, written, aws.ToString(h.ETag))
					return
				}
				stale := aws.ToString(h.ETag)
				assert.NotEqual(t, written, stale)
				assert.Contains(t, stale, "-")
				assert.Nil(t, h.ChecksumCRC64NVME)

				get, err := p.GetObject(ctx, &s3.GetObjectInput{
					Bucket:       &bucket,
					Key:          &key,
					Range:        aws.String(""),
					ChecksumMode: types.ChecksumModeEnabled,
				})
				require.NoError(t, err)
				get.Body.Close()
				assert.Equal(t, stale, aws.ToString(get.ETag))
				assert.Nil(t, get.ChecksumCRC64NVME)

				// the etag the object was written with no longer matches
				_, err = p.GetObject(ctx, &s3.GetObjectInput{
					Bucket:  &bucket,
					Key:     &key,
					Range:   aws.String(""),
					IfMatch: aws.String(strings.Trim(written, `"`)),
				})
				assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrPreconditionFailed))

				list, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket:     &bucket,
					StartAfter: aws.String(""),
					MaxKeys:    aws.Int32(1000),
				})
				require.NoError(t, err)
				require.Len(t, list.Contents, 1)
				assert.Equal(t, stale, aws.ToString(list.Contents[0].ETag))

				// a PUT through the gateway records the new content
				written = put("v3")
				h = head()
				assert.Equal(t, written, aws.ToString(h.ETag))
				assert.NotNil(t, h.ChecksumCRC64NVME)
			})
		}
	}
}

// TestStaleEtagUnrecorded checks that an object without a recorded size and
// modification time, such as one written before DetectStaleEtag was set,
// keeps its stored etag.
func TestStaleEtagUnrecorded(t *testing.T) {
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true}
	})
	ctx := context.Background()
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	out, err := p.PutObject(ctx, s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          strings.NewReader("v1"),
		ContentLength: aws.Int64(2),
	})
	require.NoError(t, err)

	p.detectStaleEtag = true
	require.NoError(t, os.WriteFile(p.ObjectPath(bucket, key), []byte("v2-longer"), 0o644))
	_, stale := p.staleEtag(nil, bucket, key, nil)
	assert.False(t, stale)

	h, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	require.NoError(t, err)
	assert.Equal(t, out.ETag, aws.ToString(h.ETag))
}
