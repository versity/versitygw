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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// testUpload is a multipart upload created by newTestUpload.
type testUpload struct {
	p        *Posix
	bucket   string
	key      string
	uploadID string
	parts    []types.CompletedPart
	body     []byte
}

// newTestUpload creates a multipart upload of key with n parts, all but the
// last of the minimum part size.
func newTestUpload(t *testing.T, p *Posix, bucket, key string, n int) *testUpload {
	t.Helper()
	ctx := context.Background()
	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	})
	require.NoError(t, err)

	u := &testUpload{p: p, bucket: bucket, key: key, uploadID: mp.UploadId}
	for i := 1; i <= n; i++ {
		size := 5 * 1024 * 1024
		if i == n {
			size = 1024
		}
		u.uploadPart(t, int32(i), bytes.Repeat([]byte{byte('a' + i)}, size))
	}
	return u
}

// uploadPart uploads (or replaces) the part and records it for completion.
func (u *testUpload) uploadPart(t *testing.T, n int32, data []byte) {
	t.Helper()
	out, err := u.p.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        &u.bucket,
		Key:           &u.key,
		UploadId:      &u.uploadID,
		PartNumber:    aws.Int32(n),
		ContentLength: aws.Int64(int64(len(data))),
		Body:          bytes.NewReader(data),
	})
	require.NoError(t, err)

	part := types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(n)}
	if int(n) <= len(u.parts) {
		u.parts[n-1] = part
	} else {
		u.parts = append(u.parts, part)
	}
	u.body = nil
	for _, p := range u.parts {
		data, err := os.ReadFile(filepath.Join(u.dir(), fmt.Sprint(*p.PartNumber)))
		require.NoError(t, err)
		u.body = append(u.body, data...)
	}
}

func (u *testUpload) input() *s3.CompleteMultipartUploadInput {
	return &s3.CompleteMultipartUploadInput{
		Bucket:          &u.bucket,
		Key:             &u.key,
		UploadId:        &u.uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: slices.Clone(u.parts)},
	}
}

func (u *testUpload) complete() (s3response.CompleteMultipartUploadResult, string, error) {
	return u.p.CompleteMultipartUpload(context.Background(), u.input())
}

func (u *testUpload) completeWithCopy(copyFn CustomCopyFunc) (s3response.CompleteMultipartUploadResult, string, error) {
	return u.p.CompleteMultipartUploadWithCopy(context.Background(), u.input(), copyFn)
}

func (u *testUpload) abort() error {
	return u.p.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
		Bucket:   &u.bucket,
		Key:      &u.key,
		UploadId: &u.uploadID,
	})
}

// objdir is the directory of the uploads of the key.
func (u *testUpload) objdir() string {
	sum := sha256.Sum256([]byte(u.key))
	return filepath.Join(u.p.BucketPath(u.bucket), MetaTmpMultipartDir, fmt.Sprintf("%x", sum))
}

func (u *testUpload) dir() string {
	return filepath.Join(u.objdir(), u.uploadID)
}

// listed reports whether ListMultipartUploads lists the upload.
func (u *testUpload) listed(t *testing.T) bool {
	t.Helper()
	res, err := u.p.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket:     &u.bucket,
		MaxUploads: aws.Int32(1000),
	})
	require.NoError(t, err)
	for _, up := range res.Uploads {
		if up.UploadID == u.uploadID {
			return true
		}
	}
	return false
}

func assertAPIError(t *testing.T, err error, code s3err.ErrorCode) {
	t.Helper()
	want := s3err.GetAPIError(code)
	assert.True(t, errors.Is(err, want), "got %v, want %v", err, want.Code)
}

func assertNoEntry(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	assert.ErrorIs(t, err, os.ErrNotExist, "%s exists", path)
}

// copyPart is a custom copy that copies the part like the default copy and
// reports whether it is idempotent as told.
func copyPart(idempotent bool) CustomCopyFunc {
	return func(from, to *os.File) (bool, error) {
		_, err := io.Copy(to, from)
		return idempotent, err
	}
}

func TestCompleteMultipartUploadRetiresUpload(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 2)

			res, _, err := u.complete()
			require.NoError(t, err)

			data, etag := getTestObject(t, p, "bucket", "obj")
			assert.Equal(t, u.body, data)
			assert.Equal(t, *res.ETag, etag)
			assertNoEntry(t, u.dir())
			assertNoEntry(t, u.dir()+retiredUploadSuffix)
			assertNoEntry(t, u.objdir())
			assert.False(t, u.listed(t))
			assertAPIError(t, u.abort(), s3err.ErrNoSuchUpload)

			// a retry returns the published object
			again, _, err := u.complete()
			require.NoError(t, err)
			assert.Equal(t, *res.ETag, *again.ETag)
		})
	}
}

// The parts of a retired upload are removed after the publish lock is
// released.
func TestCompleteMultipartUploadRemovesPartsUnlocked(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	u := newTestUpload(t, p, "bucket", "obj", 2)

	orig := removeAllRetired
	t.Cleanup(func() { removeAllRetired = orig })
	var removals int
	removeAllRetired = func(path string) error {
		removals++
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		unlock, err := p.lockObjectPublish(ctx, "bucket", "obj")
		if assert.NoError(t, err, "publish lock held while removing %s", path) {
			unlock()
		}
		return orig(path)
	}

	_, _, err := u.complete()
	require.NoError(t, err)
	assert.Equal(t, 1, removals)
	assertNoEntry(t, u.dir()+retiredUploadSuffix)
}

// A completion that dies after publishing the object leaves the upload
// directory in place. A retry returns the published object and retires the
// upload without publishing the object again.
func TestCompleteMultipartUploadDiedBeforeRetire(t *testing.T) {
	ctx := context.Background()
	p := newVersionedTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	require.NoError(t, p.PutBucketVersioning(ctx, "bucket", types.BucketVersioningStatusEnabled))
	u := newTestUpload(t, p, "bucket", "obj", 2)
	// keeps the directory of the uploads of the key, as a completion that
	// died would have
	newTestUpload(t, p, "bucket", "obj", 1)

	res, versionID, err := u.complete()
	require.NoError(t, err)
	require.NotEmpty(t, versionID)

	// the state left by a completion that died between publishing the
	// object and retiring the upload
	require.NoError(t, os.MkdirAll(u.dir(), 0o755))
	assert.True(t, u.listed(t))

	again, againVersionID, err := u.complete()
	require.NoError(t, err)
	assert.Equal(t, *res.ETag, *again.ETag)
	assert.Equal(t, versionID, againVersionID)

	assertNoEntry(t, u.dir())
	assert.False(t, u.listed(t))
	versions, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket:  aws.String("bucket"),
		MaxKeys: aws.Int32(1000),
	})
	require.NoError(t, err)
	assert.Len(t, versions.Versions, 1)
}

// A completion that dies while removing the retired upload leaves the rest
// of it, which a retry or ListMultipartUploads removes.
func TestCompleteMultipartUploadDiedRemovingRetiredUpload(t *testing.T) {
	for _, by := range []string{"complete", "list"} {
		t.Run(by, func(t *testing.T) {
			p := newTestPosix(t, metaModes(t)["xattr"])
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 1)
			// keeps the directory of the uploads of the key, as a
			// completion that died would have
			newTestUpload(t, p, "bucket", "obj", 1)
			res, _, err := u.complete()
			require.NoError(t, err)

			retired := u.dir() + retiredUploadSuffix
			require.NoError(t, os.MkdirAll(retired, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(retired, "1"), []byte("part"), 0o644))

			switch by {
			case "complete":
				again, _, err := u.complete()
				require.NoError(t, err)
				assert.Equal(t, *res.ETag, *again.ETag)
			case "list":
				assert.False(t, u.listed(t))
			}
			assertNoEntry(t, retired)
		})
	}
}

// The claim of an upload left by a completion of an earlier version is never
// reported as a completed upload.
func TestCompleteMultipartUploadEarlierVersionClaim(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	u := newTestUpload(t, p, "bucket", "obj", 2)

	claim := u.dir() + ".0123456789abcdef0123456789abcdef-2.inprogress"
	require.NoError(t, os.Rename(u.dir(), claim))

	_, _, err := u.complete()
	assertAPIError(t, err, s3err.ErrNoSuchUpload)
	assert.False(t, u.listed(t))
	_, err = os.Stat(claim)
	assert.NoError(t, err)
}

// The upload stays listable while it is completed, and a completion that
// fails before publishing leaves it as it was.
func TestCompleteMultipartUploadLeavesUploadInPlace(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 2)

			var listed bool
			_, _, err := u.completeWithCopy(func(from, to *os.File) (bool, error) {
				listed = u.listed(t)
				// a failing idempotent copy falls back to the default copy
				return true, errors.New("no move")
			})
			require.NoError(t, err)
			assert.True(t, listed)

			data, _ := getTestObject(t, p, "bucket", "obj")
			assert.Equal(t, u.body, data)
		})
	}
}

func TestCompleteMultipartUploadConcurrentSameUpload(t *testing.T) {
	const completers = 8
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 3)

			etags := make([]string, completers)
			errs := make([]error, completers)
			var wg sync.WaitGroup
			for i := range completers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					res, _, err := u.complete()
					errs[i] = err
					if err == nil {
						etags[i] = *res.ETag
					}
				}()
			}
			wg.Wait()

			data, etag := getTestObject(t, p, "bucket", "obj")
			assert.Equal(t, u.body, data)
			for i := range completers {
				if assert.NoError(t, errs[i], "completer %d", i) {
					assert.Equal(t, etag, etags[i], "completer %d", i)
				}
			}
			assertNoEntry(t, u.dir())
			assertNoEntry(t, u.dir()+retiredUploadSuffix)
		})
	}
}

func TestCompleteMultipartUploadConcurrentSameUploadVersioned(t *testing.T) {
	const completers = 8
	ctx := context.Background()
	p := newVersionedTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	require.NoError(t, p.PutBucketVersioning(ctx, "bucket", types.BucketVersioningStatusEnabled))
	u := newTestUpload(t, p, "bucket", "obj", 3)

	versionIDs := make([]string, completers)
	errs := make([]error, completers)
	var wg sync.WaitGroup
	for i := range completers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, versionIDs[i], errs[i] = u.complete()
		}()
	}
	wg.Wait()

	for i := range completers {
		require.NoError(t, errs[i], "completer %d", i)
		assert.Equal(t, versionIDs[0], versionIDs[i], "completer %d", i)
	}
	// the completions of one process publish the object once
	versions, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket:  aws.String("bucket"),
		MaxKeys: aws.Int32(1000),
	})
	require.NoError(t, err)
	require.Len(t, versions.Versions, 1)
	assert.Equal(t, versionIDs[0], *versions.Versions[0].VersionId)
}

// A completion of an upload aborted while it is assembled fails without
// publishing the object.
func TestCompleteMultipartUploadAbortedWhileAssembled(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 2)

			var once sync.Once
			_, _, err := u.completeWithCopy(func(from, to *os.File) (bool, error) {
				once.Do(func() { require.NoError(t, u.abort()) })
				_, err := io.Copy(to, from)
				return true, err
			})
			assertAPIError(t, err, s3err.ErrNoSuchUpload)

			_, err = p.HeadObject(context.Background(), &s3.HeadObjectInput{
				Bucket: aws.String("bucket"),
				Key:    aws.String("obj"),
			})
			assertAPIError(t, err, s3err.ErrNoSuchKey)
		})
	}
}

// A completion of an upload completed by another call while it is assembled
// returns the object the other call published.
func TestCompleteMultipartUploadCompletedWhileAssembled(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 2)

			var other s3response.CompleteMultipartUploadResult
			var once sync.Once
			res, _, err := u.completeWithCopy(func(from, to *os.File) (bool, error) {
				once.Do(func() {
					var err error
					other, _, err = u.complete()
					require.NoError(t, err)
				})
				_, err := io.Copy(to, from)
				return true, err
			})
			require.NoError(t, err)
			assert.Equal(t, *other.ETag, *res.ETag)

			data, _ := getTestObject(t, p, "bucket", "obj")
			assert.Equal(t, u.body, data)
		})
	}
}

// A part replaced while the object is assembled is not copied for the part
// listed by the completion.
func TestCompleteMultipartUploadPartReplacedWhileAssembled(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			createTestBucket(t, p, "bucket")
			u := newTestUpload(t, p, "bucket", "obj", 2)
			input := u.input()

			var once sync.Once
			_, _, err := p.CompleteMultipartUploadWithCopy(context.Background(), input,
				func(from, to *os.File) (bool, error) {
					once.Do(func() { u.uploadPart(t, 2, []byte("replaced")) })
					_, err := io.Copy(to, from)
					return true, err
				})
			assertAPIError(t, err, s3err.ErrInvalidPart)
			assert.True(t, u.listed(t))

			// the upload completes with the part that replaced it
			_, _, err = u.complete()
			require.NoError(t, err)
			data, _ := getTestObject(t, p, "bucket", "obj")
			assert.Equal(t, u.body, data)
		})
	}
}

// Only the completion that creates the consumed marker reads the parts when
// they may be moved.
func TestCompleteMultipartUploadConsumedByAnother(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	u := newTestUpload(t, p, "bucket", "obj", 2)

	var concurrentErr error
	var once sync.Once
	res, _, err := u.completeWithCopy(func(from, to *os.File) (bool, error) {
		once.Do(func() { _, _, concurrentErr = u.completeWithCopy(copyPart(false)) })
		_, err := io.Copy(to, from)
		return false, err
	})
	require.NoError(t, err)
	assertAPIError(t, concurrentErr, s3err.ErrSlowDown)

	// once the object is published, a retry returns it
	again, _, err := u.completeWithCopy(copyPart(false))
	require.NoError(t, err)
	assert.Equal(t, *res.ETag, *again.ETag)
	data, _ := getTestObject(t, p, "bucket", "obj")
	assert.Equal(t, u.body, data)
}

// An upload whose parts were moved into an object that failed can't be
// completed again.
func TestCompleteMultipartUploadConsumedThenFailed(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	u := newTestUpload(t, p, "bucket", "obj", 2)

	input := u.input()
	input.IfNoneMatch = aws.String("*")
	var once sync.Once
	_, _, err := p.CompleteMultipartUploadWithCopy(context.Background(), input,
		func(from, to *os.File) (bool, error) {
			// the object created meanwhile fails the completion
			// after the parts were moved
			once.Do(func() {
				_, err := testPut(p, "bucket", "obj", []byte("other"), nil, nil)
				require.NoError(t, err)
			})
			_, err := io.Copy(to, from)
			return false, err
		})
	assert.True(t, isPreconditionFailed(err), "got %v", err)

	assertNoEntry(t, u.dir())
	assertNoEntry(t, u.dir()+retiredUploadSuffix)
	assert.False(t, u.listed(t))
	_, _, err = u.completeWithCopy(copyPart(false))
	assertAPIError(t, err, s3err.ErrNoSuchUpload)
}

// An upload whose parts weren't moved by a failed completion can be
// completed again.
func TestCompleteMultipartUploadNotConsumedThenFailed(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	u := newTestUpload(t, p, "bucket", "obj", 2)

	input := u.input()
	input.IfNoneMatch = aws.String("*")
	var once sync.Once
	_, _, err := p.CompleteMultipartUploadWithCopy(context.Background(), input,
		func(from, to *os.File) (bool, error) {
			once.Do(func() {
				_, err := testPut(p, "bucket", "obj", []byte("other"), nil, nil)
				require.NoError(t, err)
			})
			_, err := io.Copy(to, from)
			return true, err
		})
	assert.True(t, isPreconditionFailed(err), "got %v", err)

	assertNoEntry(t, filepath.Join(u.dir(), uploadConsumedName))
	assert.True(t, u.listed(t))
	_, _, err = u.completeWithCopy(copyPart(false))
	require.NoError(t, err)
	data, _ := getTestObject(t, p, "bucket", "obj")
	assert.Equal(t, u.body, data)
}

// A completion that dies after moving parts leaves the consumed marker. The
// upload can't be completed, but it is listed and can be aborted.
func TestCompleteMultipartUploadDiedWhileConsuming(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	createTestBucket(t, p, "bucket")
	u := newTestUpload(t, p, "bucket", "obj", 2)

	require.NoError(t, p.markUploadConsumed(u.dir()))

	_, _, err := u.completeWithCopy(copyPart(false))
	assertAPIError(t, err, s3err.ErrSlowDown)
	assert.True(t, u.listed(t))

	parts, err := p.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket:   aws.String("bucket"),
		Key:      aws.String("obj"),
		UploadId: &u.uploadID,
		MaxParts: aws.Int32(1000),
	})
	require.NoError(t, err)
	assert.Len(t, parts.Parts, 2)

	require.NoError(t, u.abort())
	assertNoEntry(t, u.dir())
	assert.False(t, u.listed(t))
}
