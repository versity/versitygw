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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
)

func TestPosixConditionalDelete(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := newVersionedTestPosix(t, mkMeta)
			bucket, vBucket := "bucket", "versioned"
			createTestBucket(t, p, bucket)
			createTestBucket(t, p, vBucket)
			err := p.PutBucketVersioning(ctx, vBucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}

			del := func(bucket, key string, ifMatch *string) (*s3.DeleteObjectOutput, error) {
				return p.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:  &bucket,
					Key:     &key,
					IfMatch: ifMatch,
				})
			}

			t.Run("stale etag keeps the object", func(t *testing.T) {
				for _, b := range []string{bucket, vBucket} {
					key := "stale"
					if _, err := testPut(p, b, key, []byte("data"), nil, nil); err != nil {
						t.Fatalf("put object: %v", err)
					}

					_, err := del(b, key, aws.String("00000000000000000000000000000000"))
					if !isPreconditionFailed(err) {
						t.Fatalf("%v: expected PreconditionFailed, got %v", b, err)
					}
					getTestObject(t, p, b, key)
				}
			})

			t.Run("matching etag deletes the object", func(t *testing.T) {
				for _, b := range []string{bucket, vBucket} {
					for _, ifMatch := range []func(etag string) string{
						trimEtag,
						func(etag string) string { return etag },
						func(string) string { return "*" },
						func(string) string { return `"*"` },
					} {
						key := "match"
						res, err := testPut(p, b, key, []byte("data"), nil, nil)
						if err != nil {
							t.Fatalf("put object: %v", err)
						}

						out, err := del(b, key, aws.String(ifMatch(res.ETag)))
						if err != nil {
							t.Fatalf("%v: delete with If-Match %q: %v", b, ifMatch(res.ETag), err)
						}
						if b == vBucket {
							assert.True(t, aws.ToBool(out.DeleteMarker))
						}
						_, err = p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &b, Key: &key})
						assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNoSuchKey))
					}
				}
			})

			t.Run("missing key", func(t *testing.T) {
				for _, b := range []string{bucket, vBucket} {
					for _, ifMatch := range []string{"*", "00000000000000000000000000000000"} {
						_, err := del(b, "missing", &ifMatch)
						assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNoSuchKey))
					}
				}
			})

			t.Run("current delete marker", func(t *testing.T) {
				key := "marked"
				res, err := testPut(p, vBucket, key, []byte("data"), nil, nil)
				if err != nil {
					t.Fatalf("put object: %v", err)
				}
				if _, err := del(vBucket, key, nil); err != nil {
					t.Fatalf("create delete marker: %v", err)
				}

				// the marker keeps the etag of the version it hides
				for _, ifMatch := range []string{"*", trimEtag(res.ETag)} {
					_, err := del(vBucket, key, &ifMatch)
					assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNoSuchKey))
				}

				out, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
					Bucket:  &vBucket,
					Prefix:  &key,
					MaxKeys: aws.Int32(1000),
				})
				if err != nil {
					t.Fatalf("list object versions: %v", err)
				}
				assert.Len(t, out.DeleteMarkers, 1)
				assert.Len(t, out.Versions, 1)
			})

			t.Run("delete objects evaluates each etag", func(t *testing.T) {
				keys := []string{"batch-match", "batch-stale", "batch-wildcard"}
				etags := map[string]string{}
				for _, key := range keys {
					res, err := testPut(p, bucket, key, []byte(key), nil, nil)
					if err != nil {
						t.Fatalf("put object: %v", err)
					}
					etags[key] = res.ETag
				}

				out, err := p.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: &bucket,
					Delete: &types.Delete{
						Objects: []types.ObjectIdentifier{
							{Key: aws.String("batch-match"), ETag: aws.String(etags["batch-match"])},
							{Key: aws.String("batch-stale"), ETag: aws.String(trimEtag(etags["batch-match"]))},
							{Key: aws.String("batch-wildcard"), ETag: aws.String("*")},
							{Key: aws.String("batch-missing"), ETag: aws.String("*")},
						},
					},
				})
				if err != nil {
					t.Fatalf("delete objects: %v", err)
				}

				var deleted []string
				for _, d := range out.Deleted {
					deleted = append(deleted, aws.ToString(d.Key))
				}
				assert.Equal(t, []string{"batch-match", "batch-wildcard"}, deleted)

				errCodes := map[string]string{}
				for _, e := range out.Error {
					errCodes[aws.ToString(e.Key)] = aws.ToString(e.Code)
				}
				assert.Equal(t, map[string]string{
					"batch-stale":   "PreconditionFailed",
					"batch-missing": "NoSuchKey",
				}, errCodes)

				data, _ := getTestObject(t, p, bucket, "batch-stale")
				assert.Equal(t, "batch-stale", string(data))
			})
		})
	}
}

// newVersionedTestPosix creates a Posix backend with a versioning directory,
// so that versioning can be enabled on its buckets
func newVersionedTestPosix(t *testing.T, mkMeta func(t *testing.T) (meta.MetadataStorer, PosixOpts)) *Posix {
	t.Helper()
	storer, opts := mkMeta(t)
	opts.VersioningDir = t.TempDir()
	p, err := New(t.TempDir(), storer, opts)
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	return p
}
