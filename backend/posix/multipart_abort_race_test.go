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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type triggerOnRead struct {
	r       io.Reader
	once    sync.Once
	trigger func()
}

func (tr *triggerOnRead) Read(p []byte) (int, error) {
	tr.once.Do(tr.trigger)
	return tr.r.Read(p)
}

type hookMetadataStorer struct {
	meta.MetadataStorer
	renameObject   func(bucket, oldObject, newObject string) error
	storeAttribute func(f *os.File, bucket, object, attribute string, value []byte) error
}

func (h *hookMetadataStorer) RenameObject(bucket, oldObject, newObject string) error {
	if h.renameObject != nil {
		return h.renameObject(bucket, oldObject, newObject)
	}
	return h.MetadataStorer.RenameObject(bucket, oldObject, newObject)
}

func (h *hookMetadataStorer) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	if h.storeAttribute != nil {
		return h.storeAttribute(f, bucket, object, attribute, value)
	}
	return h.MetadataStorer.StoreAttribute(f, bucket, object, attribute, value)
}

func abortTmpLeftovers(t *testing.T, p *Posix, bucket, sidecarDir string) []string {
	t.Helper()
	roots := []string{p.ObjectPath(bucket, MetaTmpDir)}
	if sidecarDir != "" {
		roots = append(roots, filepath.Join(sidecarDir, bucket, MetaTmpDir))
	}
	var leftovers []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".abort-") {
				leftovers = append(leftovers, filepath.Join(root, e.Name()))
			}
		}
	}
	return leftovers
}

func isNoSuchUploadErr(err error) bool {
	var nsuErr s3err.NoSuchUploadError
	if errors.As(err, &nsuErr) {
		return true
	}
	var apiErr s3err.APIError
	return errors.As(err, &apiErr) && apiErr.Code == "NoSuchUpload"
}

func TestUploadPartRacingAbortMultipartUpload(t *testing.T) {
	ctx := context.Background()

	t.Run("deterministic_resurrection_after_abort", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket"
		createTestBucket(t, p, bucket)

		key := "mpu/resurrected"
		initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket: &bucket,
			Key:    &key,
		})
		require.NoError(t, err)
		uploadID := initRes.UploadId
		payload := []byte("part-uploaded-while-abort-runs")

		var abortErr error
		body := &triggerOnRead{
			r: bytes.NewReader(payload),
			trigger: func() {
				abortErr = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &key,
					UploadId: &uploadID,
				})
			},
		}

		partNum := int32(1)
		cl := int64(len(payload))
		upOut, upErr := p.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &key,
			UploadId:      &uploadID,
			PartNumber:    &partNum,
			ContentLength: &cl,
			Body:          body,
		})
		require.NoError(t, abortErr)
		assert.Equal(t, s3err.GetNoSuchUploadErr(uploadID), upErr)

		listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		require.NoError(t, err)
		for _, u := range listRes.Uploads {
			assert.NotEqual(t, uploadID, u.UploadID, "aborted upload was resurrected")
		}

		etag := "\"00000000000000000000000000000000\""
		if upOut != nil && upOut.ETag != nil {
			etag = *upOut.ETag
		}
		_, _, compErr := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{{PartNumber: &partNum, ETag: &etag}},
			},
		})
		assert.True(t, isNoSuchUploadErr(compErr), "expected NoSuchUpload, got %v", compErr)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("deterministic_abort_before_link", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-prelink"
		createTestBucket(t, p, bucket)

		key := "mpu/prelink"
		initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket: &bucket,
			Key:    &key,
		})
		require.NoError(t, err)
		uploadID := initRes.UploadId
		payload := []byte("part-aborted-right-before-link")
		partNum := int32(1)
		cl := int64(len(payload))

		var abortErr error
		_, upErr := p.UploadPartWithPostFunc(ctx, &s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &key,
			UploadId:      &uploadID,
			PartNumber:    &partNum,
			ContentLength: &cl,
			Body:          bytes.NewReader(payload),
		}, func(*os.File) error {
			abortErr = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: &uploadID,
			})
			return nil
		})
		require.NoError(t, abortErr)
		assert.Equal(t, s3err.GetNoSuchUploadErr(uploadID), upErr)

		listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		require.NoError(t, err)
		for _, u := range listRes.Uploads {
			assert.NotEqual(t, uploadID, u.UploadID, "aborted upload was resurrected")
		}

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("upload_part_copy_after_abort", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		p.copyObjectThreshold = 5 * 1024 * 1024
		defer p.Shutdown()

		bucket := "mpubucket-copy"
		createTestBucket(t, p, bucket)

		srcKey := "src/object"
		srcBody := bytes.Repeat([]byte("S"), 512)
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           &srcKey,
			ContentLength: aws.Int64(int64(len(srcBody))),
			Body:          bytes.NewReader(srcBody),
		})
		require.NoError(t, err)

		dstKey := "mpu/copy-aborted"
		initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket: &bucket,
			Key:    &dstKey,
		})
		require.NoError(t, err)
		uploadID := initRes.UploadId

		require.NoError(t, p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &dstKey,
			UploadId: &uploadID,
		}))

		copySource := url.PathEscape(bucket + "/" + srcKey)
		_, copyErr := p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			Key:             &dstKey,
			UploadId:        &uploadID,
			PartNumber:      aws.Int32(1),
			CopySource:      &copySource,
			CopySourceRange: aws.String(""),
		})
		assert.Equal(t, s3err.GetNoSuchUploadErr(uploadID), copyErr)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	for _, tc := range []struct {
		name       string
		useSidecar bool
	}{
		{name: "concurrent_upload_part_copy_vs_abort_sidecar", useSidecar: true},
		{name: "concurrent_upload_part_copy_vs_abort_xattr", useSidecar: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				p       *Posix
				sidecar string
				err     error
			)
			if tc.useSidecar {
				p, sidecar = newSidecarTestPosix(t)
			} else {
				p, err = New(t.TempDir(), meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755})
				require.NoError(t, err)
			}
			p.copyObjectThreshold = 5 * 1024 * 1024
			defer p.Shutdown()

			bucket := "mpubucket-copy-race"
			createTestBucket(t, p, bucket)

			srcKey := "src/object"
			srcBody := bytes.Repeat([]byte("C"), 4096)
			_, err = p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &srcKey,
				ContentLength: aws.Int64(int64(len(srcBody))),
				Body:          bytes.NewReader(srcBody),
			})
			require.NoError(t, err)
			copySource := url.PathEscape(bucket + "/" + srcKey)

			const rounds = 40
			for round := 0; round < rounds; round++ {
				dstKey := fmt.Sprintf("mpu/copy-race-%03d", round)
				initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
					Bucket:      &bucket,
					Key:         &dstKey,
					ContentType: aws.String("application/octet-stream"),
				})
				require.NoError(t, err)
				uploadID := initRes.UploadId

				start := make(chan struct{})
				var wg sync.WaitGroup
				var copyErr, abortErr error
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					_, copyErr = p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:          &bucket,
						Key:             &dstKey,
						UploadId:        &uploadID,
						PartNumber:      aws.Int32(1),
						CopySource:      &copySource,
						CopySourceRange: aws.String(""),
					})
				}()
				go func() {
					defer wg.Done()
					<-start
					abortErr = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &dstKey,
						UploadId: &uploadID,
					})
				}()
				close(start)
				wg.Wait()

				if copyErr != nil && !isNoSuchUploadErr(copyErr) {
					t.Fatalf("round %d: unexpected UploadPartCopy error: %v", round, copyErr)
				}
				if abortErr != nil && !isNoSuchUploadErr(abortErr) {
					t.Fatalf("round %d: unexpected AbortMultipartUpload error: %v", round, abortErr)
				}
			}

			listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket:     &bucket,
				MaxUploads: aws.Int32(1000),
			})
			require.NoError(t, err)
			assert.Empty(t, listRes.Uploads)
			assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
			if sidecar != "" {
				assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
			}
			assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
		})
	}

	for _, tc := range []struct {
		name           string
		useSidecar     bool
		forceNoTmpFile bool
	}{
		{name: "concurrent_internal_500_sidecar", useSidecar: true, forceNoTmpFile: false},
		{name: "concurrent_internal_500_sidecar_no_otmpfile", useSidecar: true, forceNoTmpFile: true},
		{name: "concurrent_internal_500_xattr", useSidecar: false, forceNoTmpFile: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			var (
				p          *Posix
				sidecarDir string
				err        error
			)
			if tc.useSidecar {
				sidecarDir = t.TempDir()
				sc, scErr := meta.NewSideCar(sidecarDir)
				require.NoError(t, scErr)
				p, err = New(rootDir, sc, PosixOpts{
					NewDirPerm:     0755,
					SideCarDir:     sidecarDir,
					ForceNoTmpFile: tc.forceNoTmpFile,
				})
			} else {
				p, err = New(rootDir, meta.XattrMeta{}, PosixOpts{
					NewDirPerm:     0755,
					ForceNoTmpFile: tc.forceNoTmpFile,
				})
			}
			require.NoError(t, err)
			defer p.Shutdown()

			bucket := "mpubucket500"
			createTestBucket(t, p, bucket)

			const rounds = 80
			payload := bytes.Repeat([]byte("A"), 256)

			for round := 0; round < rounds; round++ {
				key := fmt.Sprintf("mpu/r500-%03d", round)
				initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
					Bucket:      &bucket,
					Key:         &key,
					ContentType: aws.String("application/octet-stream"),
				})
				require.NoError(t, err)
				uploadID := initRes.UploadId

				var wg sync.WaitGroup
				var abortErr error
				body := &triggerOnRead{
					r: bytes.NewReader(payload),
					trigger: func() {
						wg.Add(1)
						go func() {
							defer wg.Done()
							abortErr = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
								Bucket:   &bucket,
								Key:      &key,
								UploadId: &uploadID,
							})
						}()
					},
				}

				partNum := int32(1)
				cl := int64(len(payload))
				_, upErr := p.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        &bucket,
					Key:           &key,
					UploadId:      &uploadID,
					PartNumber:    &partNum,
					ContentLength: &cl,
					Body:          body,
				})
				wg.Wait()

				if upErr != nil && !isNoSuchUploadErr(upErr) {
					t.Fatalf("round %d: unexpected UploadPart error: %v", round, upErr)
				}
				if abortErr != nil && !isNoSuchUploadErr(abortErr) {
					t.Fatalf("round %d: unexpected AbortMultipartUpload error: %v", round, abortErr)
				}
			}

			listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket:     &bucket,
				MaxUploads: aws.Int32(1000),
			})
			require.NoError(t, err)
			assert.Empty(t, listRes.Uploads)
			assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
			if sidecarDir != "" {
				assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecarDir, bucket)))
			}
			assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecarDir))
		})
	}

	t.Run("concurrent_upload_part_vs_complete", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-complete-race"
		createTestBucket(t, p, bucket)

		const rounds = 20
		part1Body := bytes.Repeat([]byte("1"), 64)
		part2Body := bytes.Repeat([]byte("2"), 64)

		for round := 0; round < rounds; round++ {
			key := fmt.Sprintf("mpu/complete-race-%03d", round)
			initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    &key,
			})
			require.NoError(t, err)
			uploadID := initRes.UploadId

			p1Out, err := p.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:        &bucket,
				Key:           &key,
				UploadId:      &uploadID,
				PartNumber:    aws.Int32(1),
				ContentLength: aws.Int64(int64(len(part1Body))),
				Body:          bytes.NewReader(part1Body),
			})
			require.NoError(t, err)

			var wg sync.WaitGroup
			var compErr error
			body := &triggerOnRead{
				r: bytes.NewReader(part2Body),
				trigger: func() {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, _, compErr = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
							Bucket:   &bucket,
							Key:      &key,
							UploadId: &uploadID,
							MultipartUpload: &types.CompletedMultipartUpload{
								Parts: []types.CompletedPart{{
									PartNumber: aws.Int32(1),
									ETag:       p1Out.ETag,
								}},
							},
						})
					}()
				},
			}

			_, upErr := p.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:        &bucket,
				Key:           &key,
				UploadId:      &uploadID,
				PartNumber:    aws.Int32(2),
				ContentLength: aws.Int64(int64(len(part2Body))),
				Body:          body,
			})
			wg.Wait()

			require.NoError(t, compErr)
			if upErr != nil && !isNoSuchUploadErr(upErr) {
				t.Fatalf("round %d: unexpected UploadPart error during CompleteMultipartUpload: %v", round, upErr)
			}
		}

		listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		require.NoError(t, err)
		assert.Empty(t, listRes.Uploads)
		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("early_abort_xattr_race", func(t *testing.T) {
		rootDir := t.TempDir()
		p, err := New(rootDir, meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755})
		require.NoError(t, err)
		defer p.Shutdown()

		bucket := "mpubucket-early-xattr"
		createTestBucket(t, p, bucket)

		const rounds = 80
		payload := bytes.Repeat([]byte("X"), 64)
		for round := 0; round < rounds; round++ {
			key := fmt.Sprintf("mpu/early-xattr-%03d", round)
			initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
				Bucket:      &bucket,
				Key:         &key,
				ContentType: aws.String("application/octet-stream"),
			})
			require.NoError(t, err)
			uploadID := initRes.UploadId

			start := make(chan struct{})
			var wg sync.WaitGroup
			var upErr, abortErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, upErr = p.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        &bucket,
					Key:           &key,
					UploadId:      &uploadID,
					PartNumber:    aws.Int32(1),
					ContentLength: aws.Int64(int64(len(payload))),
					Body:          bytes.NewReader(payload),
				})
			}()
			go func() {
				defer wg.Done()
				<-start
				abortErr = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &key,
					UploadId: &uploadID,
				})
			}()
			close(start)
			wg.Wait()

			if upErr != nil && !isNoSuchUploadErr(upErr) {
				t.Fatalf("round %d: unexpected UploadPart error: %v", round, upErr)
			}
			if abortErr != nil && !isNoSuchUploadErr(abortErr) {
				t.Fatalf("round %d: unexpected AbortMultipartUpload error: %v", round, abortErr)
			}
		}

		listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		require.NoError(t, err)
		assert.Empty(t, listRes.Uploads)
		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, ""))
	})

	t.Run("failed_complete_rollback_preserves_part_meta", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-rollback"
		createTestBucket(t, p, bucket)

		key := "mpu/rollback-part-meta"
		initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket:      &bucket,
			Key:         &key,
			ContentType: aws.String("application/octet-stream"),
		})
		require.NoError(t, err)
		uploadID := initRes.UploadId

		part1Body := bytes.Repeat([]byte("P"), 128)
		p1Out, err := p.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &key,
			UploadId:      &uploadID,
			PartNumber:    aws.Int32(1),
			ContentLength: aws.Int64(int64(len(part1Body))),
			Body:          bytes.NewReader(part1Body),
		})
		require.NoError(t, err)
		require.NotNil(t, p1Out.ETag)

		// Simulate an overlapping UploadPart for part 1 hitting f.link() while
		// CompleteMultipartUpload holds the .inprogress claim directory.
		objdir := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
		uploadDir := p.ObjectPath(bucket, filepath.Join(objdir, uploadID))
		claimName := uploadID + ".testclaim" + inProgressSuffix
		claimDir := p.ObjectPath(bucket, filepath.Join(objdir, claimName))
		oldMetaObj := filepath.Join(objdir, uploadID)
		newMetaObj := filepath.Join(objdir, claimName)

		_, upErr := p.UploadPartWithPostFunc(ctx, &s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &key,
			UploadId:      &uploadID,
			PartNumber:    aws.Int32(1),
			ContentLength: aws.Int64(int64(len(part1Body))),
			Body:          bytes.NewReader(part1Body),
		}, func(*os.File) error {
			require.NoError(t, os.Rename(uploadDir, claimDir))
			require.NoError(t, p.meta.RenameObject(bucket, oldMetaObj, newMetaObj))
			return nil
		})
		assert.Equal(t, s3err.GetNoSuchUploadErr(uploadID), upErr)
		// UploadPart must not recreate the unclaimed sidecar directory while Complete holds .inprogress.
		_, sidecarErr := os.Stat(filepath.Join(sidecar, bucket, oldMetaObj))
		assert.True(t, errors.Is(sidecarErr, os.ErrNotExist), "UploadPart recreated sidecar upload dir: %v", sidecarErr)

		// Roll back the claim just as CompleteMultipartUpload does on retryable error.
		require.NoError(t, p.meta.RenameObject(bucket, newMetaObj, oldMetaObj))
		require.NoError(t, os.Rename(claimDir, uploadDir))
		_, claimDataErr := os.Stat(claimDir)
		assert.True(t, errors.Is(claimDataErr, os.ErrNotExist))
		_, claimMetaErr := os.Stat(filepath.Join(sidecar, bucket, newMetaObj))
		assert.True(t, errors.Is(claimMetaErr, os.ErrNotExist))

		// Also exercise a real retryable failed CompleteMultipartUpload (missing part 2).
		_, _, badCompErr := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{PartNumber: aws.Int32(1), ETag: p1Out.ETag},
					{PartNumber: aws.Int32(2), ETag: aws.String("\"deadbeef\"")},
				},
			},
		})
		require.Error(t, badCompErr)

		// Part 1's ETag metadata must still be intact for ListParts and valid CompleteMultipartUpload.
		partsRes, err := p.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MaxParts: aws.Int32(1000),
		})
		require.NoError(t, err)
		require.Len(t, partsRes.Parts, 1)
		assert.Equal(t, *p1Out.ETag, partsRes.Parts[0].ETag)

		_, _, compErr := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{PartNumber: aws.Int32(1), ETag: p1Out.ETag},
				},
			},
		})
		require.NoError(t, compErr)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("concurrent_upload_part_vs_failed_complete_rollback", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-rollback-race"
		createTestBucket(t, p, bucket)

		const rounds = 40
		initialBody := bytes.Repeat([]byte("A"), 256)
		replacementBody := bytes.Repeat([]byte("B"), 256)

		for round := 0; round < rounds; round++ {
			key := fmt.Sprintf("mpu/rollback-race-%03d", round)
			initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
				Bucket:      &bucket,
				Key:         &key,
				ContentType: aws.String("application/octet-stream"),
			})
			require.NoError(t, err)
			uploadID := initRes.UploadId

			p1Out, err := p.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:        &bucket,
				Key:           &key,
				UploadId:      &uploadID,
				PartNumber:    aws.Int32(1),
				ContentLength: aws.Int64(int64(len(initialBody))),
				Body:          bytes.NewReader(initialBody),
			})
			require.NoError(t, err)
			require.NotNil(t, p1Out.ETag)

			start := make(chan struct{})
			var wg sync.WaitGroup
			var upOut *s3.UploadPartOutput
			var upErr, compErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, _, compErr = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &key,
					UploadId: &uploadID,
					MultipartUpload: &types.CompletedMultipartUpload{
						Parts: []types.CompletedPart{{
							PartNumber: aws.Int32(1),
							ETag:       aws.String("\"00000000000000000000000000000000\""),
						}},
					},
				})
			}()
			go func() {
				defer wg.Done()
				<-start
				upOut, upErr = p.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        &bucket,
					Key:           &key,
					UploadId:      &uploadID,
					PartNumber:    aws.Int32(1),
					ContentLength: aws.Int64(int64(len(replacementBody))),
					Body:          bytes.NewReader(replacementBody),
				})
			}()
			close(start)
			wg.Wait()

			require.Error(t, compErr)
			assert.Contains(t, compErr.Error(), "<Code>InvalidPart</Code>", "round %d: expected InvalidPart, got %v", round, compErr)

			if upErr != nil && !isNoSuchUploadErr(upErr) {
				t.Fatalf("round %d: unexpected UploadPart error: %v", round, upErr)
			}

			objdir := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
			for _, root := range []string{p.ObjectPath(bucket, objdir), filepath.Join(sidecar, bucket, objdir)} {
				entries, readErr := os.ReadDir(root)
				require.NoError(t, readErr)
				for _, e := range entries {
					assert.False(t, strings.HasSuffix(e.Name(), inProgressSuffix), "round %d: leftover in-progress entry %s in %s", round, e.Name(), root)
				}
			}

			partsRes, err := p.ListParts(ctx, &s3.ListPartsInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: &uploadID,
				MaxParts: aws.Int32(1000),
			})
			require.NoError(t, err)
			require.Len(t, partsRes.Parts, 1)

			expectedBody := initialBody
			expectedETag := *p1Out.ETag
			if upErr == nil {
				require.NotNil(t, upOut)
				require.NotNil(t, upOut.ETag)
				expectedBody = replacementBody
				expectedETag = *upOut.ETag
			}
			assert.Equal(t, expectedETag, partsRes.Parts[0].ETag)

			_, _, finalErr := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: &uploadID,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: []types.CompletedPart{{
						PartNumber: aws.Int32(1),
						ETag:       aws.String(partsRes.Parts[0].ETag),
					}},
				},
			})
			require.NoError(t, finalErr)

			getOut, err := p.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			require.NoError(t, err)
			gotBody, err := io.ReadAll(getOut.Body)
			require.NoError(t, getOut.Body.Close())
			require.NoError(t, err)
			assert.Equal(t, expectedBody, gotBody)
		}

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("abort_rollback_after_parent_cleanup", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-abort-rollback"
		createTestBucket(t, p, bucket)

		key := "mpu/abort-rollback"
		initA, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket:      &bucket,
			Key:         &key,
			ContentType: aws.String("application/octet-stream"),
		})
		require.NoError(t, err)
		uploadIDA := initA.UploadId

		payload := bytes.Repeat([]byte("R"), 128)
		p1Out, err := p.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &key,
			UploadId:      &uploadIDA,
			PartNumber:    aws.Int32(1),
			ContentLength: aws.Int64(int64(len(payload))),
			Body:          bytes.NewReader(payload),
		})
		require.NoError(t, err)
		require.NotNil(t, p1Out.ETag)

		initB, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket: &bucket,
			Key:    &key,
		})
		require.NoError(t, err)
		uploadIDB := initB.UploadId

		objdirRel := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
		upiddirRelA := filepath.Join(objdirRel, uploadIDA)
		upiddirPathA := p.ObjectPath(bucket, upiddirRelA)
		targetPath := filepath.Join(p.ObjectPath(bucket, MetaTmpDir), ".abort-rollback-test")
		metaTarget := filepath.Join(MetaTmpDir, ".abort-meta-rollback-test")

		require.NoError(t, os.Rename(upiddirPathA, targetPath))
		require.NoError(t, p.meta.RenameObject(bucket, upiddirRelA, metaTarget))

		require.NoError(t, p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadIDB,
		}))

		_, statErr := os.Stat(p.ObjectPath(bucket, objdirRel))
		require.True(t, os.IsNotExist(statErr), "expected objdir to be removed after aborting B, got %v", statErr)

		require.NoError(t, p.restoreRetiredUpload(bucket, key, objdirRel, upiddirRelA, upiddirPathA, targetPath, metaTarget))

		listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		require.NoError(t, err)
		require.Len(t, listRes.Uploads, 1)
		assert.Equal(t, uploadIDA, listRes.Uploads[0].UploadID)
		assert.Equal(t, key, listRes.Uploads[0].Key)

		partsRes, err := p.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadIDA,
			MaxParts: aws.Int32(1000),
		})
		require.NoError(t, err)
		require.Len(t, partsRes.Parts, 1)
		assert.Equal(t, *p1Out.ETag, partsRes.Parts[0].ETag)

		_, _, compErr := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadIDA,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{{
					PartNumber: aws.Int32(1),
					ETag:       p1Out.ETag,
				}},
			},
		})
		require.NoError(t, compErr)

		getOut, err := p.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		require.NoError(t, err)
		gotBody, err := io.ReadAll(getOut.Body)
		require.NoError(t, getOut.Body.Close())
		require.NoError(t, err)
		assert.Equal(t, payload, gotBody)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("abort_metadata_rename_failure_rollback_after_parent_cleanup", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-abort-meta-rb"
		createTestBucket(t, p, bucket)

		key := "mpu/abort-meta-rollback"
		initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket: &bucket,
			Key:    &key,
		})
		require.NoError(t, err)
		uploadID := initRes.UploadId

		payload := bytes.Repeat([]byte("m"), 4096)
		p1Out, err := p.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &key,
			UploadId:      &uploadID,
			PartNumber:    aws.Int32(1),
			ContentLength: aws.Int64(int64(len(payload))),
			Body:          bytes.NewReader(payload),
		})
		require.NoError(t, err)

		sum := sha256.Sum256([]byte(key))
		objdirRel := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", sum))

		origMeta := p.meta
		injectedErr := errors.New("injected metadata rename failure")
		p.meta = &hookMetadataStorer{
			MetadataStorer: origMeta,
			renameObject: func(b, oldObj, newObj string) error {
				if strings.Contains(newObj, ".abort-meta-") {
					p.cleanupEmptyMultipartObjDir(b, key, objdirRel)
					return injectedErr
				}
				return origMeta.RenameObject(b, oldObj, newObj)
			},
		}

		abortErr := p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
		})
		require.ErrorIs(t, abortErr, injectedErr)
		p.meta = origMeta

		listRes, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		require.NoError(t, err)
		require.Len(t, listRes.Uploads, 1)
		assert.Equal(t, uploadID, listRes.Uploads[0].UploadID)
		assert.Equal(t, key, listRes.Uploads[0].Key)

		partsRes, err := p.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MaxParts: aws.Int32(1000),
		})
		require.NoError(t, err)
		require.Len(t, partsRes.Parts, 1)
		assert.Equal(t, *p1Out.ETag, partsRes.Parts[0].ETag)

		_, _, compErr := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{{
					PartNumber: aws.Int32(1),
					ETag:       p1Out.ETag,
				}},
			},
		})
		require.NoError(t, compErr)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("restore_retired_upload_reports_meta_errors_and_detects_sidecar_leftovers", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-restore-errs"
		createTestBucket(t, p, bucket)

		sidecarTmp := filepath.Join(sidecar, bucket, MetaTmpDir)
		require.NoError(t, os.MkdirAll(sidecarTmp, 0o755))
		leftoverPath := filepath.Join(sidecarTmp, ".abort-meta-probe")
		require.NoError(t, os.WriteFile(leftoverPath, []byte("x"), 0o600))
		assert.Equal(t, []string{leftoverPath}, abortTmpLeftovers(t, p, bucket, sidecar))
		require.NoError(t, os.Remove(leftoverPath))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))

		key := "mpu/restore-errors"
		initRes, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket:      &bucket,
			Key:         &key,
			ContentType: aws.String("application/octet-stream"),
		})
		require.NoError(t, err)
		uploadID := initRes.UploadId

		sum := sha256.Sum256([]byte(key))
		objdirRel := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", sum))
		upiddir := filepath.Join(objdirRel, uploadID)
		upiddirPath := p.ObjectPath(bucket, upiddir)
		targetPath := filepath.Join(p.ObjectPath(bucket, MetaTmpDir), ".abort-test-1")
		metaTarget := filepath.Join(MetaTmpDir, ".abort-meta-test-1")

		require.NoError(t, os.Rename(upiddirPath, targetPath))
		require.NoError(t, p.meta.RenameObject(bucket, upiddir, metaTarget))

		origMeta := p.meta
		storeErr := errors.New("injected store attr failure")
		renameErr := errors.New("injected restore meta rename failure")
		p.meta = &hookMetadataStorer{
			MetadataStorer: origMeta,
			storeAttribute: func(f *os.File, b, obj, attr string, val []byte) error {
				if attr == onameAttr {
					return storeErr
				}
				return origMeta.StoreAttribute(f, b, obj, attr, val)
			},
			renameObject: func(b, oldObj, newObj string) error {
				if oldObj == metaTarget && newObj == upiddir {
					return renameErr
				}
				return origMeta.RenameObject(b, oldObj, newObj)
			},
		}

		restoreErr := p.restoreRetiredUpload(bucket, key, objdirRel, upiddir, upiddirPath, targetPath, metaTarget)
		require.ErrorIs(t, restoreErr, storeErr)
		require.ErrorIs(t, restoreErr, renameErr)
		p.meta = origMeta

		// Clean up the left-behind sidecar metaTarget so the leftover check passes.
		assert.Equal(t, []string{filepath.Join(sidecar, bucket, metaTarget)}, abortTmpLeftovers(t, p, bucket, sidecar))
		p.removeUploadMetaRetry(bucket, metaTarget)
		require.NoError(t, p.meta.StoreAttribute(nil, bucket, objdirRel, onameAttr, []byte(key)))
		require.NoError(t, p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
		}))

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})

	t.Run("failed_create_cleans_up_without_abort_leftovers", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		defer p.Shutdown()

		bucket := "mpubucket-failed-create"
		createTestBucket(t, p, bucket)

		key := "mpu/failed-create"
		_, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &key,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		require.Error(t, err)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
		assert.Empty(t, abortTmpLeftovers(t, p, bucket, sidecar))
	})
}
