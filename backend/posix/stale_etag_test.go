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
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

func newStaleEtagPosix(t *testing.T, detect, versioned bool) *Posix {
	t.Helper()
	mk := func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, DetectStaleEtag: detect}
	}
	var p *Posix
	if versioned {
		p = newVersionedTestPosix(t, mk)
	} else {
		p = newTestPosix(t, mk)
	}
	p.copyObjectThreshold = 1 << 30
	return p
}

func headEtag(t *testing.T, p *Posix, bucket, key string) *s3.HeadObjectOutput {
	t.Helper()
	out, err := p.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket:       &bucket,
		Key:          &key,
		ChecksumMode: types.ChecksumModeEnabled,
	})
	require.NoError(t, err)
	return out
}

// rewrite replaces the content of the file at path in place, the way an NFS
// or SMB client does: the inode and its extended attributes are kept. A zero
// mtime keeps the modification time the file had.
func rewrite(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	if mtime.IsZero() {
		mtime = fi.ModTime()
	}
	require.NoError(t, os.Chtimes(path, mtime, mtime))
}

func isStaleEtag(etag string) bool {
	return strings.Contains(etag, "-s")
}

// TestDetectStaleEtag checks that with DetectStaleEtag an object whose file
// was rewritten outside of the gateway is served with an etag made from its
// size and modification time and without its stored checksums, by
// HeadObject, GetObject, ListObjectsV2, ListObjectVersions and the
// conditional requests, and that a PUT through the gateway makes the stored
// etag current again. Without the option the stored etag is still returned.
func TestDetectStaleEtag(t *testing.T) {
	for _, detect := range []bool{false, true} {
		name := "default"
		if detect {
			name = "detect"
		}
		t.Run(name, func(t *testing.T) {
			p := newStaleEtagPosix(t, detect, false)
			ctx := context.Background()
			bucket, key := "testbucket", "dir/obj"
			createTestBucket(t, p, bucket)

			put, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
			require.NoError(t, err)
			written := put.ETag
			h := headEtag(t, p, bucket, key)
			assert.Equal(t, written, aws.ToString(h.ETag))
			assert.NotNil(t, h.ChecksumCRC64NVME)

			path := p.ObjectPath(bucket, key)
			rewrite(t, path, "v2-longer", time.Now().Add(time.Minute))

			h = headEtag(t, p, bucket, key)
			assert.Equal(t, int64(len("v2-longer")), aws.ToInt64(h.ContentLength))
			if !detect {
				assert.Equal(t, written, aws.ToString(h.ETag))
				return
			}
			stale := aws.ToString(h.ETag)
			assert.True(t, isStaleEtag(stale), "etag %v", stale)
			assert.Nil(t, h.ChecksumCRC64NVME)

			get, err := p.GetObject(ctx, &s3.GetObjectInput{
				Bucket:       &bucket,
				Key:          &key,
				Range:        aws.String(""),
				ChecksumMode: types.ChecksumModeEnabled,
			})
			require.NoError(t, err)
			body := new(bytes.Buffer)
			_, err = body.ReadFrom(get.Body)
			get.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, "v2-longer", body.String())
			assert.Equal(t, stale, aws.ToString(get.ETag))
			assert.Nil(t, get.ChecksumCRC64NVME)

			// the etag the object was written with no longer matches
			_, err = p.GetObject(ctx, &s3.GetObjectInput{
				Bucket:  &bucket,
				Key:     &key,
				Range:   aws.String(""),
				IfMatch: aws.String(trimEtag(written)),
			})
			assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrPreconditionFailed))
			_, err = p.GetObject(ctx, &s3.GetObjectInput{
				Bucket:      &bucket,
				Key:         &key,
				Range:       aws.String(""),
				IfNoneMatch: aws.String(trimEtag(written)),
			})
			require.NoError(t, err)

			list, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:     &bucket,
				StartAfter: aws.String(""),
				MaxKeys:    aws.Int32(1000),
			})
			require.NoError(t, err)
			require.Len(t, list.Contents, 1)
			assert.Equal(t, stale, aws.ToString(list.Contents[0].ETag))

			// the conditions of a PUT, a DELETE and a copy source use
			// the etag that is served
			_, err = testPut(p, bucket, key, []byte("x"), aws.String(trimEtag(written)), nil)
			assert.True(t, isPreconditionFailed(err), "put if-match old etag: %v", err)
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket, Key: &key, IfMatch: aws.String(trimEtag(written)),
			})
			assert.True(t, isPreconditionFailed(err), "delete if-match old etag: %v", err)
			_, err = p.CopyObject(ctx, s3response.CopyObjectInput{
				Bucket:              &bucket,
				Key:                 aws.String("copy"),
				CopySource:          aws.String(bucket + "/" + key),
				CopySourceIfMatch:   aws.String(trimEtag(written)),
				ExpectedBucketOwner: aws.String(""),
				MetadataDirective:   types.MetadataDirectiveCopy,
			})
			assert.True(t, isPreconditionFailed(err), "copy source if-match old etag: %v", err)
			_, err = p.CopyObject(ctx, s3response.CopyObjectInput{
				Bucket:              &bucket,
				Key:                 aws.String("copy"),
				CopySource:          aws.String(bucket + "/" + key),
				CopySourceIfMatch:   aws.String(trimEtag(stale)),
				ExpectedBucketOwner: aws.String(""),
				MetadataDirective:   types.MetadataDirectiveCopy,
			})
			require.NoError(t, err)

			// a PUT through the gateway records the new content
			put, err = testPut(p, bucket, key, []byte("v3"), aws.String(trimEtag(stale)), nil)
			require.NoError(t, err)
			h = headEtag(t, p, bucket, key)
			assert.Equal(t, put.ETag, aws.ToString(h.ETag))
			assert.NotNil(t, h.ChecksumCRC64NVME)
		})
	}
}

// TestDetectStaleEtagChanges checks which rewrites outside of the gateway are
// noticed: a change of the size or of the modification time is, a rewrite
// that keeps both is not.
func TestDetectStaleEtagChanges(t *testing.T) {
	for name, tc := range map[string]struct {
		body  string
		mtime time.Duration
		stale bool
	}{
		"size and mtime": {"v2-longer", time.Minute, true},
		"size only":      {"v2-longer", 0, true},
		"mtime only":     {"v2", time.Minute, true},
		"neither":        {"v2", 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := newStaleEtagPosix(t, true, false)
			bucket, key := "testbucket", "obj"
			createTestBucket(t, p, bucket)
			put, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
			require.NoError(t, err)

			var mtime time.Time
			if tc.mtime != 0 {
				mtime = time.Now().Add(tc.mtime)
			}
			rewrite(t, p.ObjectPath(bucket, key), tc.body, mtime)

			etag := aws.ToString(headEtag(t, p, bucket, key).ETag)
			assert.Equal(t, tc.stale, isStaleEtag(etag), "etag %v", etag)
			if !tc.stale {
				assert.Equal(t, put.ETag, etag)
			}
		})
	}
}

// TestDetectStaleEtagWrites checks that objects written only through the
// gateway are never stale: right after a PUT and a CompleteMultipartUpload,
// for the versions a versioned PUT archives and for a version a delete
// restores, which keep their modification time.
func TestDetectStaleEtagWrites(t *testing.T) {
	ctx := context.Background()
	p := newStaleEtagPosix(t, true, true)
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	require.NoError(t, p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled))

	_, complete := testCompleteMultipart(t, p, bucket, "mp", []byte("multipart"), nil, nil)
	mpEtag, err := complete()
	require.NoError(t, err)
	h := headEtag(t, p, bucket, "mp")
	assert.Equal(t, mpEtag, aws.ToString(h.ETag))

	var puts []s3response.PutObjectOutput
	for _, body := range []string{"v1", "v2", "v3"} {
		put, err := testPut(p, bucket, key, []byte(body), nil, nil)
		require.NoError(t, err)
		puts = append(puts, put)
		h := headEtag(t, p, bucket, key)
		assert.Equal(t, put.ETag, aws.ToString(h.ETag))
		assert.NotNil(t, h.ChecksumCRC64NVME)
	}

	versions, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key, MaxKeys: aws.Int32(1000)})
	require.NoError(t, err)
	require.Len(t, versions.Versions, 3)
	for _, v := range versions.Versions {
		for _, put := range puts {
			if put.VersionID == aws.ToString(v.VersionId) {
				assert.Equal(t, put.ETag, aws.ToString(v.ETag), "version %v", put.VersionID)
			}
		}
	}

	// deleting the latest version restores v2
	_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket, Key: &key, VersionId: &puts[2].VersionID,
	})
	require.NoError(t, err)
	h = headEtag(t, p, bucket, key)
	assert.Equal(t, puts[1].ETag, aws.ToString(h.ETag))
	assert.NotNil(t, h.ChecksumCRC64NVME)
	_, err = p.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket, Key: &key, Range: aws.String(""), IfMatch: aws.String(trimEtag(puts[1].ETag)),
	})
	require.NoError(t, err)
}

// TestDetectStaleEtagVersions checks that a version archived from an object
// changed outside of the gateway, and the object a delete restores from it,
// stay stale.
func TestDetectStaleEtagVersions(t *testing.T) {
	ctx := context.Background()
	p := newStaleEtagPosix(t, true, true)
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	require.NoError(t, p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled))

	v1, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
	require.NoError(t, err)
	rewrite(t, p.ObjectPath(bucket, key), "v1-changed", time.Now().Add(time.Minute))
	stale := aws.ToString(headEtag(t, p, bucket, key).ETag)
	require.True(t, isStaleEtag(stale))

	v2, err := testPut(p, bucket, key, []byte("v2"), nil, nil)
	require.NoError(t, err)
	versions, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key, MaxKeys: aws.Int32(1000)})
	require.NoError(t, err)
	for _, v := range versions.Versions {
		if aws.ToString(v.VersionId) == v1.VersionID {
			assert.Equal(t, stale, aws.ToString(v.ETag))
			assert.Equal(t, int64(len("v1-changed")), aws.ToInt64(v.Size))
		}
	}

	_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: &v2.VersionID})
	require.NoError(t, err)
	h := headEtag(t, p, bucket, key)
	assert.Equal(t, stale, aws.ToString(h.ETag))
	assert.Nil(t, h.ChecksumCRC64NVME)
}

// TestDetectStaleEtagParts checks that an object made by a multipart upload
// and rewritten outside of the gateway is served as a single part.
func TestDetectStaleEtagParts(t *testing.T) {
	ctx := context.Background()
	p := newStaleEtagPosix(t, true, false)
	bucket, key := "testbucket", "mp"
	createTestBucket(t, p, bucket)
	uploadID, parts := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	_, _, err := p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, key, uploadID, parts))
	require.NoError(t, err)
	h, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key, PartNumber: aws.Int32(1)})
	require.NoError(t, err)
	assert.Equal(t, int32(2), aws.ToInt32(h.PartsCount))

	rewrite(t, p.ObjectPath(bucket, key), "sixteen bytes!!!", time.Now().Add(time.Minute))

	h, err = p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key, PartNumber: aws.Int32(1)})
	require.NoError(t, err)
	assert.Equal(t, int64(16), aws.ToInt64(h.ContentLength))
	assert.Nil(t, h.PartsCount)
	_, err = p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key, PartNumber: aws.Int32(2)})
	assert.Error(t, err)

	get, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, PartNumber: aws.Int32(1)})
	require.NoError(t, err)
	body := new(bytes.Buffer)
	_, err = body.ReadFrom(get.Body)
	get.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "sixteen bytes!!!", body.String())
	assert.Nil(t, get.PartsCount)
	_, err = p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, PartNumber: aws.Int32(2)})
	assert.Error(t, err)

	// a 304 doesn't report the parts either
	h, err = p.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket, Key: &key, PartNumber: aws.Int32(1), IfNoneMatch: aws.String(trimEtag(aws.ToString(h.ETag))),
	})
	assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNotModified))
	if h != nil {
		assert.Nil(t, h.PartsCount)
	}
}

// TestDetectStaleEtagSymlink checks that a listing decides whether a
// symlinked object is stale from the file it points to, as HeadObject does.
func TestDetectStaleEtagSymlink(t *testing.T) {
	ctx := context.Background()
	p := newStaleEtagPosix(t, true, false)
	bucket := "testbucket"
	createTestBucket(t, p, bucket)
	_, err := testPut(p, bucket, "target", []byte("v1"), nil, nil)
	require.NoError(t, err)
	require.NoError(t, os.Symlink("target", p.ObjectPath(bucket, "link")))
	rewrite(t, p.ObjectPath(bucket, "target"), "v1-changed", time.Now().Add(time.Minute))

	head := aws.ToString(headEtag(t, p, bucket, "link").ETag)
	require.True(t, isStaleEtag(head))
	list, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: &bucket, StartAfter: aws.String(""), MaxKeys: aws.Int32(1000),
	})
	require.NoError(t, err)
	for _, o := range list.Contents {
		if aws.ToString(o.Key) == "link" {
			assert.Equal(t, head, aws.ToString(o.ETag))
			assert.Equal(t, int64(len("v1-changed")), aws.ToInt64(o.Size))
		}
	}
}

// TestDetectStaleEtagSelfCopy checks that copying a stale object onto itself
// to replace its metadata records its content again, as a PUT does.
func TestDetectStaleEtagSelfCopy(t *testing.T) {
	p := newStaleEtagPosix(t, true, false)
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	_, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
	require.NoError(t, err)
	rewrite(t, p.ObjectPath(bucket, key), "v1-changed", time.Now().Add(time.Minute))

	etag, err := testCopy(p, bucket, key, key, types.MetadataDirectiveReplace, nil, nil)
	require.NoError(t, err)
	assert.False(t, isStaleEtag(etag), "etag %v", etag)
	h := headEtag(t, p, bucket, key)
	assert.Equal(t, etag, aws.ToString(h.ETag))
	assert.NotNil(t, h.ChecksumCRC64NVME)
	assert.Equal(t, "application/x-replaced", aws.ToString(h.ContentType))
}

// TestDetectStaleEtagUploadPartCopy checks that a part copied from a stale
// source gets the checksum of the source's current content, not the one
// stored for its old content, so that the object completed from it has the
// right checksum.
func TestDetectStaleEtagUploadPartCopy(t *testing.T) {
	ctx := context.Background()
	p := newStaleEtagPosix(t, true, false)
	bucket, src, dst, ref := "testbucket", "src", "dst", "ref"
	createTestBucket(t, p, bucket)
	_, err := testPut(p, bucket, src, []byte("version-one"), nil, nil)
	require.NoError(t, err)
	rewrite(t, p.ObjectPath(bucket, src), "version-two-longer", time.Now().Add(time.Minute))
	require.True(t, isStaleEtag(aws.ToString(headEtag(t, p, bucket, src).ETag)))

	// the checksum of the current content
	_, err = testPut(p, bucket, ref, []byte("version-two-longer"), nil, nil)
	require.NoError(t, err)
	want := aws.ToString(headEtag(t, p, bucket, ref).ChecksumCRC64NVME)
	require.NotEmpty(t, want)

	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket:            &bucket,
		Key:               &dst,
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc64nvme,
		ChecksumType:      types.ChecksumTypeFullObject,
	})
	require.NoError(t, err)
	part, err := p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
		Bucket:          &bucket,
		Key:             &dst,
		UploadId:        &mp.UploadId,
		PartNumber:      aws.Int32(1),
		CopySource:      aws.String(bucket + "/" + src),
		CopySourceRange: aws.String(""),
	})
	require.NoError(t, err)
	assert.Equal(t, want, aws.ToString(part.ChecksumCRC64NVME))

	_, _, err = p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, dst, mp.UploadId, []types.CompletedPart{{
		PartNumber:        aws.Int32(1),
		ETag:              part.ETag,
		ChecksumCRC64NVME: part.ChecksumCRC64NVME,
	}}))
	require.NoError(t, err)
	assert.Equal(t, want, aws.ToString(headEtag(t, p, bucket, dst).ChecksumCRC64NVME))
}

// TestDetectStaleEtagRace checks that objects written only through the
// gateway are never served as stale while they are replaced concurrently,
// and that a stale etag is never served with checksums.
func TestDetectStaleEtagRace(t *testing.T) {
	ctx := context.Background()
	p := newStaleEtagPosix(t, true, false)
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	_, err := testPut(p, bucket, key, []byte("seed"), nil, nil)
	require.NoError(t, err)

	var stop atomic.Bool
	var wg sync.WaitGroup
	var stale, staleChecksums, reads atomic.Int64
	for i := range 4 {
		wg.Go(func() {
			for n := 0; !stop.Load(); n++ {
				_, _ = testPut(p, bucket, key, bytes.Repeat([]byte{'a' + byte(i)}, 1+n%64), nil, nil)
			}
		})
	}
	check := func(etag string, checksum *string) {
		reads.Add(1)
		if isStaleEtag(etag) {
			stale.Add(1)
			if checksum != nil {
				staleChecksums.Add(1)
			}
		}
	}
	for range 6 {
		wg.Go(func() {
			for !stop.Load() {
				if h, err := p.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket: &bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled,
				}); err == nil {
					check(aws.ToString(h.ETag), h.ChecksumCRC64NVME)
				}
				if g, err := p.GetObject(ctx, &s3.GetObjectInput{
					Bucket: &bucket, Key: &key, Range: aws.String(""), ChecksumMode: types.ChecksumModeEnabled,
				}); err == nil {
					g.Body.Close()
					check(aws.ToString(g.ETag), g.ChecksumCRC64NVME)
				}
				if l, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket: &bucket, StartAfter: aws.String(""), MaxKeys: aws.Int32(10),
				}); err == nil {
					for _, o := range l.Contents {
						check(aws.ToString(o.ETag), nil)
					}
				}
			}
		})
	}
	time.Sleep(2 * time.Second)
	stop.Store(true)
	wg.Wait()
	require.NotZero(t, reads.Load())
	assert.Zero(t, stale.Load(), "%v of %v reads served a stale etag", stale.Load(), reads.Load())
	assert.Zero(t, staleChecksums.Load(), "stale etags served with checksums")
}

// TestStaleEtagUnrecorded checks that an object without a recorded size and
// modification time, such as one written before DetectStaleEtag was set,
// keeps its stored etag.
func TestStaleEtagUnrecorded(t *testing.T) {
	p := newStaleEtagPosix(t, false, false)
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	put, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
	require.NoError(t, err)

	p.detectStaleEtag = true
	rewrite(t, p.ObjectPath(bucket, key), "v2-longer", time.Now().Add(time.Minute))
	assert.Equal(t, put.ETag, aws.ToString(headEtag(t, p, bucket, key).ETag))
}

// TestDetectStaleEtagSidecar checks that the option is refused with sidecar
// metadata, which isn't kept on the inode it describes, and without
// metadata.
func TestDetectStaleEtagSidecar(t *testing.T) {
	sc, err := meta.NewSideCar(t.TempDir())
	require.NoError(t, err)
	for _, ms := range []meta.MetadataStorer{sc, meta.NoMeta{}} {
		_, err = New(t.TempDir(), ms, PosixOpts{DetectStaleEtag: true})
		assert.ErrorContains(t, err, "needs xattr metadata")
		_, err = New(t.TempDir(), ms, PosixOpts{})
		assert.NoError(t, err)
	}
}

// failEtagStatMeta fails to store etag-stat while fail is set: the value
// reserveEtagStat stores before an object is published when reserved is set,
// and the one recordEtagStat stores after otherwise.
type failEtagStatMeta struct {
	meta.MetadataStorer
	fail, reserved *atomic.Bool
}

func (m failEtagStatMeta) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	if attribute == etagStatKey && m.fail.Load() &&
		(string(value) == etagStatReserved) == m.reserved.Load() {
		return errors.New("etag-stat store failed")
	}
	return m.MetadataStorer.StoreAttribute(f, bucket, object, attribute, value)
}

// TestDetectStaleEtagRecordFails checks that a write whose etag-stat can't be
// stored fails, instead of reporting success for an object that is never
// seen as stale. When the space for it can't be reserved, the write fails
// before the object is replaced. When the record fails after, the object is
// published by then.
func TestDetectStaleEtagRecordFails(t *testing.T) {
	ctx := context.Background()
	bucket, key := "testbucket", "obj"
	setup := func(t *testing.T, reserved bool) (*Posix, []s3response.PutObjectOutput) {
		p := newStaleEtagPosix(t, true, true)
		fail, res := &atomic.Bool{}, &atomic.Bool{}
		res.Store(reserved)
		p.meta = failEtagStatMeta{MetadataStorer: p.meta, fail: fail, reserved: res}
		createTestBucket(t, p, bucket)
		require.NoError(t, p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled))
		var puts []s3response.PutObjectOutput
		for _, body := range []string{"v1", "v2"} {
			put, err := testPut(p, bucket, key, []byte(body), nil, nil)
			require.NoError(t, err)
			puts = append(puts, put)
		}
		fail.Store(true)
		return p, puts
	}
	versions := func(t *testing.T, p *Posix) int {
		out, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key, MaxKeys: aws.Int32(1000)})
		require.NoError(t, err)
		return len(out.Versions)
	}
	exists := func(p *Posix, object string) bool {
		_, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &object})
		return err == nil
	}
	deleteLatest := func(p *Posix, puts []s3response.PutObjectOutput) error {
		_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket, Key: &key, VersionId: &puts[1].VersionID,
		})
		return err
	}

	t.Run("reserve fails", func(t *testing.T) {
		t.Run("PutObject", func(t *testing.T) {
			p, _ := setup(t, true)
			_, err := testPut(p, bucket, "new", []byte("new"), nil, nil)
			assert.ErrorContains(t, err, "etag-stat store failed")
			assert.False(t, exists(p, "new"))
		})
		t.Run("archived version", func(t *testing.T) {
			p, puts := setup(t, true)
			_, err := testPut(p, bucket, key, []byte("v3"), nil, nil)
			assert.ErrorContains(t, err, "etag-stat store failed")
			// the object and its versions are left as they were
			assert.Equal(t, puts[1].ETag, aws.ToString(headEtag(t, p, bucket, key).ETag))
			assert.Equal(t, 2, versions(t, p))
		})
		t.Run("CompleteMultipartUpload", func(t *testing.T) {
			p, _ := setup(t, true)
			_, complete := testCompleteMultipart(t, p, bucket, "mp", []byte("multipart"), nil, nil)
			_, err := complete()
			assert.ErrorContains(t, err, "etag-stat store failed")
			assert.False(t, exists(p, "mp"))
		})
		t.Run("restored version", func(t *testing.T) {
			p, puts := setup(t, true)
			assert.ErrorContains(t, deleteLatest(p, puts), "etag-stat store failed")
			// the deleted version is already removed, so the restore
			// is still completed: the older version is the object, and
			// is listed once
			assert.Equal(t, puts[0].ETag, aws.ToString(headEtag(t, p, bucket, key).ETag))
			assert.Equal(t, 1, versions(t, p))
		})
	})

	t.Run("record fails", func(t *testing.T) {
		t.Run("PutObject", func(t *testing.T) {
			p, _ := setup(t, false)
			_, err := testPut(p, bucket, "new", []byte("new"), nil, nil)
			assert.ErrorContains(t, err, "etag-stat store failed")
			// published by then, with the reserved etag-stat
			assert.False(t, isStaleEtag(aws.ToString(headEtag(t, p, bucket, "new").ETag)))
		})
		t.Run("archived version", func(t *testing.T) {
			p, puts := setup(t, false)
			_, err := testPut(p, bucket, key, []byte("v3"), nil, nil)
			assert.ErrorContains(t, err, "etag-stat store failed")
			assert.Equal(t, puts[1].ETag, aws.ToString(headEtag(t, p, bucket, key).ETag))
			assert.Equal(t, 2, versions(t, p))
		})
		t.Run("CompleteMultipartUpload", func(t *testing.T) {
			p, _ := setup(t, false)
			_, complete := testCompleteMultipart(t, p, bucket, "mp", []byte("multipart"), nil, nil)
			_, err := complete()
			assert.ErrorContains(t, err, "etag-stat store failed")
			assert.True(t, exists(p, "mp"))
		})
		t.Run("restored version", func(t *testing.T) {
			p, puts := setup(t, false)
			assert.ErrorContains(t, deleteLatest(p, puts), "etag-stat store failed")
			// the restore is still completed: the older version is the
			// object, and is listed once
			assert.Equal(t, puts[0].ETag, aws.ToString(headEtag(t, p, bucket, key).ETag))
			assert.Equal(t, 1, versions(t, p))
		})
	})
}
