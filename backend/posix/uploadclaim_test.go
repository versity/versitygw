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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// claimWaitCheck is how long a call waiting for the owner of a claim is
// checked not to return.
const claimWaitCheck = 100 * time.Millisecond

func TestCompleteMultipartUploadConcurrentSameUpload(t *testing.T) {
	const completers = 8
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newVersionedTestPosix(t, mkMeta)
			ctx := context.Background()
			bucket := "testbucket"
			key := "obj"
			createTestBucket(t, p, bucket)
			err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}

			body := []byte("concurrent completes of one upload")
			uploadID, parts := startTestUpload(t, p, bucket, key, body)

			type outcome struct {
				etag, versionID string
				err             error
			}
			outcomes := make([]outcome, completers)
			var wg sync.WaitGroup
			for i := range completers {
				wg.Go(func() {
					res, versionID, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
					outcomes[i] = outcome{aws.ToString(res.ETag), versionID, err}
				})
			}
			wg.Wait()

			for i, o := range outcomes {
				if o.err != nil {
					t.Fatalf("complete %d: %v", i, o.err)
				}
				if o.etag != outcomes[0].etag || o.versionID != outcomes[0].versionID {
					t.Fatalf("complete %d returned etag %q version %q, complete 0 etag %q version %q",
						i, o.etag, o.versionID, outcomes[0].etag, outcomes[0].versionID)
				}
			}
			if outcomes[0].versionID == "" {
				t.Fatal("completes returned no version id")
			}

			out, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket:  &bucket,
				Prefix:  &key,
				MaxKeys: aws.Int32(1000),
			})
			if err != nil {
				t.Fatalf("list object versions: %v", err)
			}
			if len(out.Versions) != 1 {
				t.Fatalf("got %d versions, want 1", len(out.Versions))
			}
			data, _ := getTestObject(t, p, bucket, key)
			if !bytes.Equal(data, body) {
				t.Fatal("object data differs from the uploaded part")
			}
		})
	}
}

func TestCompleteMultipartUploadWaitsForClaimOwner(t *testing.T) {
	tests := []struct {
		name string
		// ifNoneMatch is sent by the waiting call, and objectWhileWaiting
		// is put at the key while it waits
		ifNoneMatch        *string
		objectWhileWaiting bool
	}{
		{name: "completes the upload the owner failed to complete"},
		{name: "returns its own result", ifNoneMatch: aws.String("*"), objectWhileWaiting: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for mode, mkMeta := range metaModes(t) {
				t.Run(mode, func(t *testing.T) {
					p := newTestPosix(t, mkMeta)
					ctx := context.Background()
					bucket := "testbucket"
					key := "obj"
					createTestBucket(t, p, bucket)

					body := []byte("owner fails")
					uploadID, parts := startTestUpload(t, p, bucket, key, body)

					// the owner claims the upload
					claim, err := p.lockUploadClaim(ctx, bucket, uploadID, true)
					if err != nil {
						t.Fatalf("lock upload claim: %v", err)
					}
					claimDir := claimTestUpload(t, p, bucket, key, uploadID, parts)

					result := make(chan error, 1)
					go func() {
						_, _, err := completeTestUpload(p, bucket, key, uploadID, parts, test.ifNoneMatch)
						result <- err
					}()
					select {
					case err := <-result:
						t.Fatalf("complete returned while the owner held the claim: %v", err)
					case <-time.After(claimWaitCheck):
					}

					if test.objectWhileWaiting {
						if _, err := testPut(p, bucket, key, []byte("put"), nil, nil); err != nil {
							t.Fatalf("put object: %v", err)
						}
					}

					// the owner fails and renames the claim back
					unclaimTestUpload(t, p, bucket, key, uploadID, claimDir)
					claim.release()

					err = <-result
					if test.objectWhileWaiting {
						if !isPreconditionFailed(err) {
							t.Fatalf("complete: want 412, got %v", err)
						}
						data, _ := getTestObject(t, p, bucket, key)
						if string(data) != "put" {
							t.Fatalf("object data %q, want the object put while waiting", data)
						}
						return
					}
					if err != nil {
						t.Fatalf("complete: %v", err)
					}
					data, _ := getTestObject(t, p, bucket, key)
					if !bytes.Equal(data, body) {
						t.Fatal("object data differs from the uploaded part")
					}
				})
			}
		})
	}
}

func TestCompleteMultipartUploadStaleClaim(t *testing.T) {
	for _, lockMode := range []ObjectLockMode{ObjectLockModeFlock, ObjectLockModeFcntl, ObjectLockModeLocal} {
		t.Run(string(lockMode), func(t *testing.T) {
			if err := validateObjectLockMode(lockMode); err != nil {
				t.Skip(err)
			}
			for mode, mkMeta := range metaModes(t) {
				t.Run(mode, func(t *testing.T) {
					p := newTestPosix(t, withObjectLockMode(mkMeta, lockMode))
					bucket := "testbucket"
					key := "obj"
					createTestBucket(t, p, bucket)

					body := []byte("completed by a process that died")
					uploadID, parts := startTestUpload(t, p, bucket, key, body)
					claimTestUpload(t, p, bucket, key, uploadID, parts)

					res, _, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
					if err != nil {
						t.Fatalf("complete: %v", err)
					}
					data, etag := getTestObject(t, p, bucket, key)
					if !bytes.Equal(data, body) {
						t.Fatal("object data differs from the uploaded part")
					}
					if etag != aws.ToString(res.ETag) {
						t.Fatalf("object etag %q, complete returned %q", etag, aws.ToString(res.ETag))
					}
					checkNoUploadLeft(t, p, bucket, key, uploadID)

					// a retry finds the published object
					retry, _, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
					if err != nil {
						t.Fatalf("retry complete: %v", err)
					}
					if aws.ToString(retry.ETag) != etag {
						t.Fatalf("retry etag %q, want %q", aws.ToString(retry.ETag), etag)
					}
				})
			}
		})
	}
}

func TestClaimNotUndoneWithoutSharedLock(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, withObjectLockMode(mkMeta, ObjectLockModeNone))
			bucket := "testbucket"
			key := "obj"
			createTestBucket(t, p, bucket)

			// another gateway process may be completing the upload
			uploadID, parts := startTestUpload(t, p, bucket, key, []byte("claimed elsewhere"))
			claimDir := claimTestUpload(t, p, bucket, key, uploadID, parts)

			_, _, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
			if !isSlowDown(err) {
				t.Fatalf("complete: want SlowDown, got %v", err)
			}
			err = p.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: &uploadID,
			})
			if !isSlowDown(err) {
				t.Fatalf("abort: want SlowDown, got %v", err)
			}
			if got := listTestUploads(t, p, bucket); len(got) != 0 {
				t.Fatalf("listed uploads %v, want none", got)
			}
			if _, err := os.Stat(claimDir); err != nil {
				t.Fatalf("claim was touched: %v", err)
			}
		})
	}
}

func TestStaleClaimListedAndAborted(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			ctx := context.Background()
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			listed, parts := startTestUpload(t, p, bucket, "listed", []byte("listed"))
			claimTestUpload(t, p, bucket, "listed", listed, parts)
			aborted, parts := startTestUpload(t, p, bucket, "aborted", []byte("aborted"))
			claimTestUpload(t, p, bucket, "aborted", aborted, parts)

			if got := listTestUploads(t, p, bucket); !equalKeys(got, []string{aborted, listed}) {
				t.Fatalf("listed uploads %v, want %v and %v", got, listed, aborted)
			}

			for key, uploadID := range map[string]string{"listed": listed, "aborted": aborted} {
				err := p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &key,
					UploadId: &uploadID,
				})
				if err != nil {
					t.Fatalf("abort %v: %v", key, err)
				}
				checkNoUploadLeft(t, p, bucket, key, uploadID)
			}
			if got := listTestUploads(t, p, bucket); len(got) != 0 {
				t.Fatalf("listed uploads %v after abort, want none", got)
			}
		})
	}

	t.Run("aborted without listing", func(t *testing.T) {
		p := newTestPosix(t, metaModes(t)["xattr"])
		bucket := "testbucket"
		key := "obj"
		createTestBucket(t, p, bucket)

		uploadID, parts := startTestUpload(t, p, bucket, key, []byte("aborted"))
		claimTestUpload(t, p, bucket, key, uploadID, parts)

		err := p.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
		})
		if err != nil {
			t.Fatalf("abort: %v", err)
		}
		checkNoUploadLeft(t, p, bucket, key, uploadID)
	})
}

func TestStaleClaimOfPublishedObject(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			key := "obj"
			createTestBucket(t, p, bucket)

			body := []byte("published before the process died")
			uploadID, parts := startTestUpload(t, p, bucket, key, body)
			res, _, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
			if err != nil {
				t.Fatalf("complete: %v", err)
			}
			fi, err := os.Stat(p.ObjectPath(bucket, key))
			if err != nil {
				t.Fatalf("stat object: %v", err)
			}

			// the process died after publishing, before removing its claim
			claimDir := filepath.Join(uploadsDir(p, bucket, key), claimName(t, uploadID, parts))
			if err := os.MkdirAll(claimDir, 0755); err != nil {
				t.Fatalf("create claim: %v", err)
			}
			if err := os.WriteFile(filepath.Join(claimDir, "1"), body, 0644); err != nil {
				t.Fatalf("create claim part: %v", err)
			}

			if got := listTestUploads(t, p, bucket); len(got) != 0 {
				t.Fatalf("listed uploads %v, want none", got)
			}
			retry, _, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
			if err != nil {
				t.Fatalf("retry complete: %v", err)
			}
			if aws.ToString(retry.ETag) != aws.ToString(res.ETag) {
				t.Fatalf("retry etag %q, want %q", aws.ToString(retry.ETag), aws.ToString(res.ETag))
			}
			after, err := os.Stat(p.ObjectPath(bucket, key))
			if err != nil {
				t.Fatalf("stat object: %v", err)
			}
			if !os.SameFile(fi, after) {
				t.Fatal("the object was published again")
			}
			checkNoUploadLeft(t, p, bucket, key, uploadID)
		})
	}
}

func TestStaleConsumedClaimRemoved(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			key := "obj"
			createTestBucket(t, p, bucket)

			uploadID, parts := startTestUpload(t, p, bucket, key, []byte("moved"))
			claimDir := claimTestUpload(t, p, bucket, key, uploadID, parts)
			if err := p.markClaimConsumed(claimDir); err != nil {
				t.Fatalf("mark claim consumed: %v", err)
			}

			_, _, err := completeTestUpload(p, bucket, key, uploadID, parts, nil)
			if !isNoSuchUpload(err) {
				t.Fatalf("complete: want NoSuchUpload, got %v", err)
			}
			if _, err := os.Stat(p.ObjectPath(bucket, key)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("object exists or stat failed: %v", err)
			}
			checkNoUploadLeft(t, p, bucket, key, uploadID)
			if got := listTestUploads(t, p, bucket); len(got) != 0 {
				t.Fatalf("listed uploads %v, want none", got)
			}
		})
	}
}

func TestLiveClaimNotRecovered(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	ctx := context.Background()
	bucket := "testbucket"
	key := "obj"
	createTestBucket(t, p, bucket)

	uploadID, parts := startTestUpload(t, p, bucket, key, []byte("live"))
	claim, err := p.lockUploadClaim(ctx, bucket, uploadID, true)
	if err != nil {
		t.Fatalf("lock upload claim: %v", err)
	}
	defer claim.release()
	claimDir := claimTestUpload(t, p, bucket, key, uploadID, parts)

	if got := listTestUploads(t, p, bucket); len(got) != 0 {
		t.Fatalf("listed uploads %v while the upload is being completed, want none", got)
	}

	abortCtx, cancel := context.WithTimeout(ctx, claimWaitCheck)
	defer cancel()
	err = p.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abort: want to wait for the owner, got %v", err)
	}
	if _, err := os.Stat(claimDir); err != nil {
		t.Fatalf("claim of a live owner was touched: %v", err)
	}
}

func TestStaleClaimTakeoverAcrossProcesses(t *testing.T) {
	if err := validateObjectLockMode(ObjectLockModeFlock); err != nil {
		t.Skip(err)
	}
	// flock locks of two open files of one lock file exclude each other
	// like the locks of two processes do
	root := t.TempDir()
	newPosix := func() *Posix {
		p, err := New(root, meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755, ObjectLockMode: ObjectLockModeFlock})
		if err != nil {
			t.Fatalf("new posix: %v", err)
		}
		t.Cleanup(p.Shutdown)
		return p
	}
	owner, other := newPosix(), newPosix()
	ctx := context.Background()
	bucket := "testbucket"
	key := "obj"
	createTestBucket(t, owner, bucket)

	body := []byte("taken over")
	uploadID, parts := startTestUpload(t, owner, bucket, key, body)
	claim, err := owner.lockUploadClaim(ctx, bucket, uploadID, true)
	if err != nil {
		t.Fatalf("lock upload claim: %v", err)
	}
	claimTestUpload(t, owner, bucket, key, uploadID, parts)

	result := make(chan error, 1)
	go func() {
		_, _, err := completeTestUpload(other, bucket, key, uploadID, parts, nil)
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("complete returned while the owner held the claim: %v", err)
	case <-time.After(claimWaitCheck):
	}

	// the owner dies: its lock is released and its claim stays
	claim.release()

	if err := <-result; err != nil {
		t.Fatalf("complete: %v", err)
	}
	data, _ := getTestObject(t, other, bucket, key)
	if !bytes.Equal(data, body) {
		t.Fatal("object data differs from the uploaded part")
	}
	checkNoUploadLeft(t, other, bucket, key, uploadID)
}

func withObjectLockMode(mkMeta func(t *testing.T) (meta.MetadataStorer, PosixOpts), mode ObjectLockMode) func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
	return func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		storer, opts := mkMeta(t)
		opts.ObjectLockMode = mode
		return storer, opts
	}
}

// startTestUpload creates an upload of one part.
func startTestUpload(t *testing.T, p *Posix, bucket, key string, body []byte) (string, []types.CompletedPart) {
	t.Helper()
	ctx := context.Background()
	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}
	uploadID := mp.UploadId
	part, err := p.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &uploadID,
		PartNumber:    aws.Int32(1),
		ContentLength: aws.Int64(int64(len(body))),
		Body:          bytes.NewReader(body),
	})
	if err != nil {
		t.Fatalf("upload part: %v", err)
	}
	return uploadID, []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1)}}
}

func completeTestUpload(p *Posix, bucket, key, uploadID string, parts []types.CompletedPart, ifNoneMatch *string) (s3response.CompleteMultipartUploadResult, string, error) {
	return p.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:          &bucket,
		Key:             &key,
		UploadId:        &uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
		IfNoneMatch:     ifNoneMatch,
	})
}

func uploadsDir(p *Posix, bucket, key string) string {
	return filepath.Join(p.BucketPath(bucket), MetaTmpMultipartDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
}

func claimName(t *testing.T, uploadID string, parts []types.CompletedPart) string {
	t.Helper()
	etag, err := backend.ComputeMultipartETagFromPartETags(uploadID, parts)
	if err != nil {
		t.Fatalf("compute multipart etag: %v", err)
	}
	return fmt.Sprintf("%s.%s%s", uploadID, strings.Trim(etag, "\""), inProgressSuffix)
}

// claimTestUpload renames the upload directory and its metadata the way
// CompleteMultipartUpload claims an upload, returning the claimed directory.
func claimTestUpload(t *testing.T, p *Posix, bucket, key, uploadID string, parts []types.CompletedPart) string {
	t.Helper()
	name := claimName(t, uploadID, parts)
	dir := uploadsDir(p, bucket, key)
	if err := os.Rename(filepath.Join(dir, uploadID), filepath.Join(dir, name)); err != nil {
		t.Fatalf("claim upload: %v", err)
	}
	metaDir := filepath.Join(MetaTmpMultipartDir, filepath.Base(dir))
	if err := p.meta.RenameObject(bucket, filepath.Join(metaDir, uploadID), filepath.Join(metaDir, name)); err != nil {
		t.Fatalf("claim upload metadata: %v", err)
	}
	return filepath.Join(dir, name)
}

// unclaimTestUpload renames the claimed upload back the way a failed
// CompleteMultipartUpload does.
func unclaimTestUpload(t *testing.T, p *Posix, bucket, key, uploadID, claimDir string) {
	t.Helper()
	dir := uploadsDir(p, bucket, key)
	if err := os.Rename(claimDir, filepath.Join(dir, uploadID)); err != nil {
		t.Fatalf("unclaim upload: %v", err)
	}
	metaDir := filepath.Join(MetaTmpMultipartDir, filepath.Base(dir))
	if err := p.meta.RenameObject(bucket, filepath.Join(metaDir, filepath.Base(claimDir)), filepath.Join(metaDir, uploadID)); err != nil {
		t.Fatalf("unclaim upload metadata: %v", err)
	}
}

// checkNoUploadLeft checks that neither the upload's directory, nor a claim
// of it, nor its claim lock file is left.
func checkNoUploadLeft(t *testing.T, p *Posix, bucket, key, uploadID string) {
	t.Helper()
	ents, err := os.ReadDir(uploadsDir(p, bucket, key))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read uploads: %v", err)
	}
	for _, ent := range ents {
		if strings.HasPrefix(ent.Name(), uploadID) {
			t.Fatalf("upload entry %q left", ent.Name())
		}
	}
	bucketHash := sha256.Sum256([]byte(bucket))
	lockFile := filepath.Join(p.rootdir, objLockDir, fmt.Sprintf("%x", bucketHash), uploadClaimLockDir, uploadID)
	if _, err := os.Stat(lockFile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("claim lock file left or stat failed: %v", err)
	}
}

func listTestUploads(t *testing.T, p *Posix, bucket string) []string {
	t.Helper()
	out, err := p.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket:     &bucket,
		MaxUploads: aws.Int32(1000),
	})
	if err != nil {
		t.Fatalf("list multipart uploads: %v", err)
	}
	var ids []string
	for _, up := range out.Uploads {
		ids = append(ids, up.UploadID)
	}
	return ids
}

func isNoSuchUpload(err error) bool {
	var s3e s3err.S3Error
	return errors.As(err, &s3e) && s3e.BaseError().Code == "NoSuchUpload"
}

func isSlowDown(err error) bool {
	var s3e s3err.S3Error
	return errors.As(err, &s3e) && s3e.BaseError().Code == "SlowDown"
}
