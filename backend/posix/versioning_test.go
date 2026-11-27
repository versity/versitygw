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
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// newUnversionedGateway creates a Posix backend over a temporary root
// directory with no versioning directory configured, i.e. gateway-level
// versioning disabled, matching the default gateway configuration.
func newUnversionedGateway(t *testing.T) *Posix {
	t.Helper()

	p, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{
		ValidateBucketNames: true,
	})
	if err != nil {
		t.Fatalf("init posix backend: %v", err)
	}
	return p
}

// TestVersioningUnconfigured covers the bucket versioning behavior when the
// gateway has no versioning directory configured: bucket validation still
// applies first, GetBucketVersioning returns an empty configuration, and
// PutBucketVersioning is rejected.
func TestVersioningUnconfigured(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	t.Run("get bucket versioning invalid bucket name", func(t *testing.T) {
		p := newUnversionedGateway(t)

		_, err := p.GetBucketVersioning(context.Background(), "bad/bucket")
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)) {
			t.Errorf("expected InvalidBucketName, got %v", err)
		}
	})

	t.Run("get bucket versioning no such bucket", func(t *testing.T) {
		p := newUnversionedGateway(t)

		_, err := p.GetBucketVersioning(context.Background(), "does-not-exist")
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)) {
			t.Errorf("expected NoSuchBucket, got %v", err)
		}
	})

	t.Run("get bucket versioning returns empty config", func(t *testing.T) {
		p := newUnversionedGateway(t)

		err := os.Mkdir(p.BucketPath("bucket"), 0o755)
		assert.NoError(t, err)

		res, err := p.GetBucketVersioning(context.Background(), "bucket")
		assert.NoError(t, err)
		assert.Nil(t, res.Status)
	})

	t.Run("put bucket versioning invalid bucket name", func(t *testing.T) {
		p := newUnversionedGateway(t)

		err := p.PutBucketVersioning(context.Background(), "bad/bucket", types.BucketVersioningStatusEnabled)
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)) {
			t.Errorf("expected InvalidBucketName, got %v", err)
		}
	})

	t.Run("put bucket versioning not configured", func(t *testing.T) {
		p := newUnversionedGateway(t)

		err := os.Mkdir(p.BucketPath("bucket"), 0o755)
		assert.NoError(t, err)

		err = p.PutBucketVersioning(context.Background(), "bucket", types.BucketVersioningStatusEnabled)
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)) {
			t.Errorf("expected VersioningNotConfigured, got %v", err)
		}
	})
}

func TestVersioningDeleteMarkerStaleSidecarClearedOnSameKeyReupload(t *testing.T) {
	root := t.TempDir()
	vdir := filepath.Join(t.TempDir(), "versions")
	sidecarDir := filepath.Join(t.TempDir(), "sidecar")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatalf("mkdir versioning dir: %v", err)
	}
	if err := os.MkdirAll(sidecarDir, 0o755); err != nil {
		t.Fatalf("mkdir sidecar: %v", err)
	}

	sc, err := meta.NewSideCar(sidecarDir)
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	p, err := New(root, sc, PosixOpts{
		ValidateBucketNames: true,
		VersioningDir:       vdir,
		SideCarDir:          sidecarDir,
	})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}

	ctx := context.Background()
	bucket, key := "bucket", "object"
	createTestBucket(t, p, bucket)
	if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}

	put := func(body string) {
		t.Helper()
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           &key,
			Body:          strings.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		})
		if err != nil {
			t.Fatalf("put object %q: %v", body, err)
		}
	}

	put("one")

	_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	assert.NoError(t, err)

	put("two")

	_, err = p.meta.RetrieveAttribute(nil, bucket, key, deleteMarkerKey)
	assert.ErrorIs(t, err, meta.ErrNoSuchKey)

	out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("get object after reupload: %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read object body: %v", err)
	}
	assert.Equal(t, "two", string(body))
}

// TestLiveObjVersionIdObjectRemoved verifies that a version id lookup for an
// object removed after the caller's stat reports NoSuchKey, not an internal
// error: the object is missing, its parent directory is missing, or its
// parent is now a file (ENOTDIR).
func TestLiveObjVersionIdObjectRemoved(t *testing.T) {
	t.Chdir(t.TempDir())
	p, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{
		ValidateBucketNames: true,
		VersioningDir:       t.TempDir(),
	})
	if err != nil {
		t.Fatalf("init posix backend: %v", err)
	}

	createTestBucket(t, p, "bucket")
	if err := os.WriteFile(p.ObjectPath("bucket", "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"gone", "gonedir/gone", "file/child"} {
		_, err := p.liveObjVersionId(context.Background(), nil, "bucket", key)
		assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNoSuchKey), key)
	}
}

// TestDeleteMarkerHoldsNoData checks that a delete marker is an empty file
// holding only the delete marker attributes: when it's created over an
// object version or over the null version, when a later put archives it and
// when it's made current again. The version it hides keeps its data and is
// current again once the delete marker is deleted.
func TestDeleteMarkerHoldsNoData(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				storer, opts := mkMeta(t)
				opts.VersioningDir = t.TempDir()
				return storer, opts
			})

			ctx := context.Background()
			bucket := "bucket"
			createTestBucket(t, p, bucket)

			setStatus := func(status types.BucketVersioningStatus) {
				t.Helper()
				if err := p.PutBucketVersioning(ctx, bucket, status); err != nil {
					t.Fatalf("put bucket versioning %v: %v", status, err)
				}
			}
			put := func(key string, body []byte) string {
				t.Helper()
				out, err := p.PutObject(ctx, s3response.PutObjectInput{
					Bucket:        &bucket,
					Key:           &key,
					Body:          bytes.NewReader(body),
					ContentLength: aws.Int64(int64(len(body))),
					ContentType:   aws.String("text/plain"),
					Metadata:      map[string]string{"foo": "bar"},
				})
				if err != nil {
					t.Fatalf("put %v: %v", key, err)
				}
				return out.VersionID
			}
			del := func(key, versionId string) string {
				t.Helper()
				input := &s3.DeleteObjectInput{Bucket: &bucket, Key: &key}
				if versionId != "" {
					input.VersionId = &versionId
				}
				out, err := p.DeleteObject(ctx, input)
				if err != nil {
					t.Fatalf("delete %v version %q: %v", key, versionId, err)
				}
				return getString(out.VersionId)
			}
			// the version versionId of key is archived at vkey in vbucket
			vbucket := filepath.Join(p.versioningDir, bucket)
			vkey := func(key, versionId string) string {
				return filepath.Join(genObjVersionKey(key), versionId)
			}
			checkDeleteMarker := func(bucket, object string, attrs ...string) {
				t.Helper()
				fi, err := os.Stat(p.ObjectPath(bucket, object))
				if err != nil {
					t.Fatalf("stat %v: %v", object, err)
				}
				if fi.Size() != 0 {
					t.Errorf("%v: expected an empty delete marker, got %v bytes", object, fi.Size())
				}
				got, err := p.meta.ListAttributes(bucket, object)
				if err != nil {
					t.Fatalf("list %v attributes: %v", object, err)
				}
				assert.ElementsMatch(t, attrs, got, object)
			}
			checkData := func(bucket, object string, want []byte) {
				t.Helper()
				got, err := os.ReadFile(p.ObjectPath(bucket, object))
				if err != nil {
					t.Fatalf("read %v: %v", object, err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%v: expected the %v bytes of the version, got %v other bytes",
						object, len(want), len(got))
				}
			}

			data := make([]byte, 256*1024)
			rand.Read(data)

			setStatus(types.BucketVersioningStatusEnabled)
			v1 := put("obj", data)
			dm := del("obj", "")
			checkDeleteMarker(bucket, "obj", deleteMarkerKey, versionIdKey)
			checkData(vbucket, vkey("obj", v1), data)

			// a put archives the delete marker, and deleting the put makes
			// the delete marker current again
			v2 := put("obj", []byte("two"))
			checkDeleteMarker(vbucket, vkey("obj", dm), deleteMarkerKey, versionIdKey)
			del("obj", v2)
			checkDeleteMarker(bucket, "obj", deleteMarkerKey, versionIdKey)

			// deleting the delete marker makes the version it hides current
			// again
			del("obj", dm)
			checkData(bucket, "obj", data)
			vId, err := p.meta.RetrieveAttribute(nil, bucket, "obj", versionIdKey)
			assert.NoError(t, err)
			assert.Equal(t, v1, string(vId))

			// with versioning suspended the null delete marker replaces the
			// null version, while an object version is archived
			setStatus(types.BucketVersioningStatusSuspended)
			put("null-obj", data)
			del("null-obj", "")
			checkDeleteMarker(bucket, "null-obj", deleteMarkerKey)

			del("obj", "")
			checkDeleteMarker(bucket, "obj", deleteMarkerKey)
			checkData(vbucket, vkey("obj", v1), data)
		})
	}
}

// TestDeleteMarkerPublishFailure covers deletes whose delete marker file
// fails to be published in place of the version, after the attributes at
// the object path were replaced. When the version's file can't be replaced,
// as when its name leaves no room for the temporary name of an overwrite,
// the version's file is made the delete marker: it keeps the version's data
// and loses its object lock settings, and the version is current again with
// all of its attributes once the delete marker is deleted. Any other publish
// error is returned, and so is a publish that leaves the object path
// without the delete marker's attributes, as a concurrent publish can.
func TestDeleteMarkerPublishFailure(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	const bucket, key = "bucket", "obj"
	ctx := context.Background()
	legalHold := []byte{1}

	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			// setup puts a version of key with data, content headers,
			// metadata, tags and a legal hold, and makes the publish of
			// the delete marker's file run link instead
			setup := func(t *testing.T, link func(p *Posix, f *tmpfile) error) (*Posix, []byte, *s3.HeadObjectOutput) {
				t.Helper()
				p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
					storer, opts := mkMeta(t)
					opts.VersioningDir = t.TempDir()
					return storer, opts
				})
				createTestBucket(t, p, bucket)
				if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
					t.Fatalf("put bucket versioning: %v", err)
				}

				data := make([]byte, 1024)
				rand.Read(data)
				_, err := p.PutObject(ctx, s3response.PutObjectInput{
					Bucket:        aws.String(bucket),
					Key:           aws.String(key),
					Body:          bytes.NewReader(data),
					ContentLength: aws.Int64(int64(len(data))),
					ContentType:   aws.String("text/plain"),
					Metadata:      map[string]string{"foo": "bar"},
					Tagging:       aws.String("key=val"),
				})
				if err != nil {
					t.Fatalf("put object: %v", err)
				}
				err = p.meta.StoreAttribute(nil, bucket, key, objectLegalHoldKey, legalHold)
				if err != nil {
					t.Fatalf("store legal hold: %v", err)
				}

				head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket:       aws.String(bucket),
					Key:          aws.String(key),
					ChecksumMode: types.ChecksumModeEnabled,
				})
				if err != nil {
					t.Fatalf("head object: %v", err)
				}

				orig := linkDeleteMarker
				t.Cleanup(func() { linkDeleteMarker = orig })
				linkDeleteMarker = func(f *tmpfile) error { return link(p, f) }
				return p, data, head
			}
			deleteObject := func(p *Posix, versionId *string) (*s3.DeleteObjectOutput, error) {
				return p.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:    aws.String(bucket),
					Key:       aws.String(key),
					VersionId: versionId,
				})
			}

			t.Run("version file can't be replaced", func(t *testing.T) {
				p, data, want := setup(t, func(*Posix, *tmpfile) error {
					return &os.LinkError{Op: "linkat", Err: syscall.ENAMETOOLONG}
				})

				del, err := deleteObject(p, nil)
				if err != nil {
					t.Fatalf("delete object: %v", err)
				}
				if del.DeleteMarker == nil || !*del.DeleteMarker {
					t.Fatalf("expected the delete to create a delete marker")
				}

				// the version's file is the delete marker
				isDel, err := p.isObjDeleteMarker(bucket, key)
				assert.NoError(t, err)
				assert.True(t, isDel, "expected the version's file to be the delete marker")
				vId, err := p.meta.RetrieveAttribute(nil, bucket, key, versionIdKey)
				assert.NoError(t, err)
				assert.Equal(t, getString(del.VersionId), string(vId))
				got, err := os.ReadFile(p.ObjectPath(bucket, key))
				assert.NoError(t, err)
				assert.True(t, bytes.Equal(data, got), "expected the delete marker to keep the version's data")
				_, err = p.meta.RetrieveAttribute(nil, bucket, key, objectLegalHoldKey)
				assert.ErrorIs(t, err, meta.ErrNoSuchKey, "expected the delete marker to have no legal hold")

				_, err = deleteObject(p, del.VersionId)
				if err != nil {
					t.Fatalf("delete the delete marker: %v", err)
				}

				// the version is current again with all of its attributes
				head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket:       aws.String(bucket),
					Key:          aws.String(key),
					ChecksumMode: types.ChecksumModeEnabled,
				})
				if err != nil {
					t.Fatalf("head the restored version: %v", err)
				}
				assert.Equal(t, getString(want.VersionId), getString(head.VersionId))
				assert.Equal(t, getString(want.ETag), getString(head.ETag))
				assert.Equal(t, getString(want.ChecksumCRC64NVME), getString(head.ChecksumCRC64NVME))
				assert.Equal(t, getString(want.ContentType), getString(head.ContentType))
				assert.Equal(t, want.Metadata, head.Metadata)
				tags, err := p.GetObjectTagging(ctx, bucket, key, "")
				assert.NoError(t, err)
				assert.Equal(t, map[string]string{"key": "val"}, tags)
				hold, err := p.meta.RetrieveAttribute(nil, bucket, key, objectLegalHoldKey)
				assert.NoError(t, err)
				assert.Equal(t, legalHold, hold)
				got, err = os.ReadFile(p.ObjectPath(bucket, key))
				assert.NoError(t, err)
				assert.True(t, bytes.Equal(data, got), "expected the restored version's data")
			})

			t.Run("other publish error", func(t *testing.T) {
				p, data, want := setup(t, func(*Posix, *tmpfile) error {
					return syscall.EIO
				})

				_, err := deleteObject(p, nil)
				assert.ErrorIs(t, err, syscall.EIO)

				// path-based metadata at the object path has been replaced
				// by then, xattrs are only set on the delete marker's file
				if name != "xattr" {
					return
				}
				isDel, err := p.isObjDeleteMarker(bucket, key)
				assert.NoError(t, err)
				assert.False(t, isDel, "expected the version to stay current")
				vId, err := p.meta.RetrieveAttribute(nil, bucket, key, versionIdKey)
				assert.NoError(t, err)
				assert.Equal(t, getString(want.VersionId), string(vId))
				hold, err := p.meta.RetrieveAttribute(nil, bucket, key, objectLegalHoldKey)
				assert.NoError(t, err)
				assert.Equal(t, legalHold, hold, "expected the current version to keep its legal hold")
				got, err := os.ReadFile(p.ObjectPath(bucket, key))
				assert.NoError(t, err)
				assert.True(t, bytes.Equal(data, got), "expected the version's data")
			})

			t.Run("concurrent publish", func(t *testing.T) {
				p, _, _ := setup(t, func(p *Posix, f *tmpfile) error {
					if err := f.link(); err != nil {
						return err
					}
					// the attributes another publish stores at the path
					if err := p.meta.DeleteAttribute(bucket, key, deleteMarkerKey); err != nil {
						return err
					}
					return p.meta.StoreAttribute(nil, bucket, key, versionIdKey, []byte("other"))
				})

				_, err := deleteObject(p, nil)
				if err == nil {
					t.Fatalf("expected the delete to fail")
				}
				assert.Contains(t, err.Error(), "concurrent publish")
			})
		})
	}
}
