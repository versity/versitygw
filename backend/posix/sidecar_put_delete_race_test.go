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
	"maps"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestSidecarPutObjectRacingDeleteObjects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		useBatch bool
	}{
		{name: "DeleteObjects", useBatch: true},
		{name: "DeleteObject", useBatch: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p := newTestPosix(t, metaModes(t)["sidecar"])
			defer p.Shutdown()

			bucket := "racebucket"
			createTestBucket(t, p, bucket)

			const (
				rounds     = 40
				keysPerRnd = 4
			)

			type expectedObj struct {
				body        []byte
				etag        string
				contentType string
				metadata    map[string]string
			}

			for round := 0; round < rounds; round++ {
				keys := make([]string, keysPerRnd)
				delObjs := make([]types.ObjectIdentifier, keysPerRnd)
				updatedByKey := make(map[string]expectedObj, keysPerRnd)

				for i := 0; i < keysPerRnd; i++ {
					k := fmt.Sprintf("prefix/round-%02d-k%d", round, i)
					keys[i] = k
					delObjs[i] = types.ObjectIdentifier{Key: aws.String(k)}

					initBody := fmt.Appendf(nil, "initial-%02d-%d", round, i)
					initMeta := map[string]string{
						"phase": "initial",
						"round": fmt.Sprintf("%d", round),
					}
					initCT := "text/plain"
					cl := int64(len(initBody))
					if _, err := p.PutObject(ctx, s3response.PutObjectInput{
						Bucket:        &bucket,
						Key:           &k,
						ContentLength: &cl,
						ContentType:   &initCT,
						Metadata:      initMeta,
						Body:          bytes.NewReader(initBody),
					}); err != nil {
						t.Fatalf("seed PutObject(%s): %v", k, err)
					}
				}

				start := make(chan struct{})
				var wg sync.WaitGroup
				var mu sync.Mutex
				var errs []error

				for i, key := range keys {
					k := key
					idx := i
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						updBody := fmt.Appendf(nil, "updated-concurrent-%02d-%d", round, idx)
						updMeta := map[string]string{
							"phase": "updated",
							"round": fmt.Sprintf("%d", round),
						}
						updCT := "application/octet-stream"
						cl := int64(len(updBody))
						out, putErr := p.PutObject(ctx, s3response.PutObjectInput{
							Bucket:        &bucket,
							Key:           &k,
							ContentLength: &cl,
							ContentType:   &updCT,
							Metadata:      updMeta,
							Body:          bytes.NewReader(updBody),
						})
						mu.Lock()
						defer mu.Unlock()
						if putErr != nil {
							errs = append(errs, fmt.Errorf("PutObject(%s): %w", k, putErr))
							return
						}
						updatedByKey[k] = expectedObj{
							body:        updBody,
							etag:        out.ETag,
							contentType: updCT,
							metadata:    updMeta,
						}
					}()
				}

				if tc.useBatch {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						res, delErr := p.DeleteObjects(ctx, &s3.DeleteObjectsInput{
							Bucket: &bucket,
							Delete: &types.Delete{Objects: delObjs},
						})
						mu.Lock()
						defer mu.Unlock()
						if delErr != nil {
							errs = append(errs, fmt.Errorf("DeleteObjects: %w", delErr))
							return
						}
						for _, e := range res.Error {
							errs = append(errs, fmt.Errorf("DeleteObjects entry %s: %s (%s)",
								aws.ToString(e.Key), aws.ToString(e.Code), aws.ToString(e.Message)))
						}
					}()
				} else {
					for _, key := range keys {
						k := key
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							if _, delErr := p.DeleteObject(ctx, &s3.DeleteObjectInput{
								Bucket: &bucket,
								Key:    &k,
							}); delErr != nil {
								mu.Lock()
								errs = append(errs, fmt.Errorf("DeleteObject(%s): %w", k, delErr))
								mu.Unlock()
							}
						}()
					}
				}

				close(start)
				wg.Wait()

				if len(errs) > 0 {
					t.Fatalf("round %d: got %d errors, first: %v", round, len(errs), errs[0])
				}

				for _, k := range keys {
					head, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &k})
					if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
						continue
					}
					if err != nil {
						t.Fatalf("round %d: HeadObject(%s): %v", round, k, err)
					}

					get, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &k})
					if err != nil {
						t.Fatalf("round %d: GetObject(%s): %v", round, k, err)
					}
					gotBody, err := io.ReadAll(get.Body)
					_ = get.Body.Close()
					if err != nil {
						t.Fatalf("round %d: read body(%s): %v", round, k, err)
					}

					want := updatedByKey[k]
					if !bytes.Equal(gotBody, want.body) {
						t.Fatalf("round %d: body for %s = %q, want %q", round, k, gotBody, want.body)
					}

					if got := aws.ToString(head.ETag); got != want.etag {
						t.Fatalf("round %d: HeadObject(%s) ETag = %q, want %q", round, k, got, want.etag)
					}
					if got := aws.ToString(head.ContentType); got != want.contentType {
						t.Fatalf("round %d: HeadObject(%s) ContentType = %q, want %q", round, k, got, want.contentType)
					}
					if !maps.Equal(head.Metadata, want.metadata) {
						t.Fatalf("round %d: HeadObject(%s) Metadata = %v, want %v", round, k, head.Metadata, want.metadata)
					}
					if got := aws.ToString(get.ETag); got != want.etag {
						t.Fatalf("round %d: GetObject(%s) ETag = %q, want %q", round, k, got, want.etag)
					}
					if got := aws.ToString(get.ContentType); got != want.contentType {
						t.Fatalf("round %d: GetObject(%s) ContentType = %q, want %q", round, k, got, want.contentType)
					}
					if !maps.Equal(get.Metadata, want.metadata) {
						t.Fatalf("round %d: GetObject(%s) Metadata = %v, want %v", round, k, get.Metadata, want.metadata)
					}
				}
			}
		})
	}
}

func TestVersionedConcurrentPutAndDeletePreservesVersions(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			p := newVersionedTestPosix(t, mkMeta)
			defer p.Shutdown()

			bucket := "versioned-race"
			key := "shared-key"
			createTestBucket(t, p, bucket)
			if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("PutBucketVersioning: %v", err)
			}

			type ackVersion struct {
				versionID string
				body      []byte
			}

			var acknowledged []ackVersion
			var mu sync.Mutex

			const (
				rounds   = 25
				writers  = 2
				deleters = 2
			)

			for round := 0; round < rounds; round++ {
				start := make(chan struct{})
				var wg sync.WaitGroup
				var errs []error

				for w := 0; w < writers; w++ {
					writerID := w
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						body := fmt.Appendf(nil, "round-%02d-writer-%d", round, writerID)
						cl := int64(len(body))
						out, err := p.PutObject(ctx, s3response.PutObjectInput{
							Bucket:        &bucket,
							Key:           &key,
							ContentLength: &cl,
							Body:          bytes.NewReader(body),
						})
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							errs = append(errs, fmt.Errorf("PutObject(r=%d,w=%d): %w", round, writerID, err))
							return
						}
						if out.VersionID == "" {
							errs = append(errs, fmt.Errorf("PutObject(r=%d,w=%d): empty VersionID", round, writerID))
							return
						}
						acknowledged = append(acknowledged, ackVersion{
							versionID: out.VersionID,
							body:      body,
						})
					}()
				}

				for d := 0; d < deleters; d++ {
					deleterID := d
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{
							Bucket: &bucket,
							Key:    &key,
						})
						if err != nil {
							mu.Lock()
							errs = append(errs, fmt.Errorf("DeleteObject(r=%d,d=%d): %w", round, deleterID, err))
							mu.Unlock()
						}
					}()
				}

				close(start)
				wg.Wait()

				if len(errs) > 0 {
					t.Fatalf("round %d: got %d errors, first: %v", round, len(errs), errs[0])
				}
			}

			for i, v := range acknowledged {
				vid := v.versionID
				out, err := p.GetObject(ctx, &s3.GetObjectInput{
					Bucket:    &bucket,
					Key:       &key,
					VersionId: &vid,
				})
				if err != nil {
					t.Fatalf("acknowledged version %d (%s) lost: %v", i, vid, err)
				}
				got, err := io.ReadAll(out.Body)
				_ = out.Body.Close()
				if err != nil {
					t.Fatalf("read version %s: %v", vid, err)
				}
				if !bytes.Equal(got, v.body) {
					t.Fatalf("version %s body = %q, want %q", vid, got, v.body)
				}
			}
		})
	}
}

func TestConcurrentConditionalDeleteObjectAtomicity(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			p := newVersionedTestPosix(t, mkMeta)
			defer p.Shutdown()

			unversioned := "cond-unversioned"
			versioned := "cond-versioned"
			suspended := "cond-suspended"
			for _, b := range []string{unversioned, versioned, suspended} {
				createTestBucket(t, p, b)
			}
			if err := p.PutBucketVersioning(ctx, versioned, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("enable versioning: %v", err)
			}
			if err := p.PutBucketVersioning(ctx, suspended, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("enable versioning before suspend: %v", err)
			}
			if err := p.PutBucketVersioning(ctx, suspended, types.BucketVersioningStatusSuspended); err != nil {
				t.Fatalf("suspend versioning: %v", err)
			}

			const rounds = 20

			for _, tc := range []struct {
				name     string
				bucket   string
				useBatch bool
			}{
				{name: "unversioned", bucket: unversioned},
				{name: "versioned", bucket: versioned},
				{name: "suspended", bucket: suspended},
				{name: "DeleteObjects", bucket: unversioned, useBatch: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for round := 0; round < rounds; round++ {
						key := fmt.Sprintf("key-%s-%02d", tc.name, round)
						res, err := testPut(p, tc.bucket, key, []byte("payload"), nil, nil)
						if err != nil {
							t.Fatalf("round %d: put: %v", round, err)
						}
						etag := res.ETag

						start := make(chan struct{})
						var wg sync.WaitGroup
						results := make([]error, 2)

						for i := 0; i < 2; i++ {
							idx := i
							wg.Add(1)
							go func() {
								defer wg.Done()
								<-start
								if tc.useBatch {
									out, delErr := p.DeleteObjects(ctx, &s3.DeleteObjectsInput{
										Bucket: &tc.bucket,
										Delete: &types.Delete{
											Objects: []types.ObjectIdentifier{{
												Key:  aws.String(key),
												ETag: aws.String(etag),
											}},
										},
									})
									if delErr != nil {
										results[idx] = delErr
										return
									}
									if len(out.Deleted) == 1 && len(out.Error) == 0 {
										results[idx] = nil
										return
									}
									if len(out.Error) == 1 && aws.ToString(out.Error[0].Code) == "NoSuchKey" {
										results[idx] = s3err.GetAPIError(s3err.ErrNoSuchKey)
										return
									}
									results[idx] = fmt.Errorf("unexpected batch result: deleted=%d errors=%+v", len(out.Deleted), out.Error)
									return
								}
								_, delErr := p.DeleteObject(ctx, &s3.DeleteObjectInput{
									Bucket:  &tc.bucket,
									Key:     &key,
									IfMatch: aws.String(etag),
								})
								results[idx] = delErr
							}()
						}

						close(start)
						wg.Wait()

						var succeeded, notFound int
						for _, r := range results {
							switch {
							case r == nil:
								succeeded++
							case errors.Is(r, s3err.GetAPIError(s3err.ErrNoSuchKey)):
								notFound++
							default:
								t.Fatalf("round %d: unexpected error: %v", round, r)
							}
						}
						if succeeded != 1 || notFound != 1 {
							t.Fatalf("round %d: got succeeded=%d noSuchKey=%d (results=%v), want 1 and 1",
								round, succeeded, notFound, results)
						}
					}
				})
			}
		})
	}
}

type lockSlotVerifyMeta struct {
	meta.MetadataStorer
	t           *testing.T
	slot        chan struct{}
	deleteObj   string
	putObj      string
	sawDelete   bool
	sawPutStore bool
}

func (m *lockSlotVerifyMeta) assertSlotHeld(op string) {
	select {
	case <-m.slot:
		m.slot <- struct{}{}
		m.t.Fatalf("%s: expected publish lock slot to be held, but it was free", op)
	default:
	}
}

func (m *lockSlotVerifyMeta) DeleteAttributes(bucket, object string) error {
	if object == m.deleteObj {
		m.sawDelete = true
		m.assertSlotHeld("DeleteAttributes(" + object + ")")
	}
	return m.MetadataStorer.DeleteAttributes(bucket, object)
}

func (m *lockSlotVerifyMeta) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	if object == m.putObj {
		m.sawPutStore = true
		m.assertSlotHeld("StoreAttribute(" + object + ")")
	}
	return m.MetadataStorer.StoreAttribute(f, bucket, object, attribute, value)
}

func TestSidecarDeleteDirObjectRacingPutFileObjectPreservesMetadata(t *testing.T) {
	for _, key := range []string{"foo", "dir/foo", "a/b/c"} {
		want := objLockShard(key)
		if got := objLockShard(key + "/"); got != want {
			t.Fatalf("objLockShard(%q) = %d, objLockShard(%q) = %d; want equal", key+"/", got, key, want)
		}
		if got := objLockShard(key + "//"); got != want {
			t.Fatalf("objLockShard(%q) = %d, objLockShard(%q) = %d; want equal", key+"//", got, key, want)
		}
	}

	ctx := context.Background()
	bucket := "alias-race"

	for _, suffix := range []string{"/", "//"} {
		t.Run("deterministic publish lock slot/"+suffix, func(t *testing.T) {
			p := newTestPosix(t, metaModes(t)["sidecar"])
			defer p.Shutdown()
			createTestBucket(t, p, bucket)

			fileKey := "foo"
			dirKey := fileKey + suffix
			slotIdx := objLockSlot(sha256.Sum256([]byte(bucket)), objLockShard(fileKey))
			slot := p.objLockSlots[slotIdx]

			zero := int64(0)
			if _, err := p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &dirKey,
				ContentLength: &zero,
				Body:          bytes.NewReader(nil),
			}); err != nil {
				t.Fatalf("seed dir object %q: %v", dirKey, err)
			}

			hook := &lockSlotVerifyMeta{
				MetadataStorer: p.meta,
				t:              t,
				slot:           slot,
				deleteObj:      dirKey,
				putObj:         fileKey,
			}
			p.meta = hook

			if _, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &dirKey,
			}); err != nil {
				t.Fatalf("DeleteObject(%s): %v", dirKey, err)
			}
			if !hook.sawDelete {
				t.Fatalf("DeleteObject(%s) did not call DeleteAttributes", dirKey)
			}
			select {
			case <-slot:
				slot <- struct{}{}
			default:
				t.Fatalf("publish lock slot leaked after DeleteObject(%s)", dirKey)
			}

			wantBody := []byte("file-payload")
			wantCT := "text/plain"
			wantMeta := map[string]string{"owner": "file", "suffix": suffix}
			cl := int64(len(wantBody))
			res, err := p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &fileKey,
				ContentLength: &cl,
				ContentType:   &wantCT,
				Metadata:      wantMeta,
				Body:          bytes.NewReader(wantBody),
			})
			if err != nil {
				t.Fatalf("PutObject(%s): %v", fileKey, err)
			}
			if !hook.sawPutStore {
				t.Fatalf("PutObject(%s) did not call StoreAttribute", fileKey)
			}
			select {
			case <-slot:
				slot <- struct{}{}
			default:
				t.Fatalf("publish lock slot leaked after PutObject(%s)", fileKey)
			}

			head, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &fileKey})
			if err != nil {
				t.Fatalf("HeadObject(%s): %v", fileKey, err)
			}
			if got := aws.ToString(head.ETag); got != res.ETag {
				t.Fatalf("HeadObject ETag = %q, want %q", got, res.ETag)
			}
			if got := aws.ToString(head.ContentType); got != wantCT {
				t.Fatalf("HeadObject ContentType = %q, want %q", got, wantCT)
			}
			if !maps.Equal(head.Metadata, wantMeta) {
				t.Fatalf("HeadObject Metadata = %v, want %v", head.Metadata, wantMeta)
			}
		})
	}

	for _, suffix := range []string{"/", "//"} {
		t.Run("concurrent barrier rounds/"+suffix, func(t *testing.T) {
			p := newTestPosix(t, metaModes(t)["sidecar"])
			defer p.Shutdown()
			createTestBucket(t, p, bucket)

			const rounds = 25
			for round := 0; round < rounds; round++ {
				fileKey := fmt.Sprintf("alias-%02d", round)
				dirKey := fileKey + suffix
				zero := int64(0)
				if _, err := p.PutObject(ctx, s3response.PutObjectInput{
					Bucket:        &bucket,
					Key:           &dirKey,
					ContentLength: &zero,
					Body:          bytes.NewReader(nil),
				}); err != nil {
					t.Fatalf("round %d: seed %s: %v", round, dirKey, err)
				}

				wantBody := fmt.Appendf(nil, "file-round-%02d", round)
				wantCT := "application/octet-stream"
				wantMeta := map[string]string{"owner": "file", "round": fmt.Sprintf("%d", round)}
				cl := int64(len(wantBody))

				start := make(chan struct{})
				var wg sync.WaitGroup
				var delErr, putErr error
				var putOut s3response.PutObjectOutput

				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					_, delErr = p.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    &dirKey,
					})
				}()
				go func() {
					defer wg.Done()
					<-start
					putOut, putErr = p.PutObject(ctx, s3response.PutObjectInput{
						Bucket:        &bucket,
						Key:           &fileKey,
						ContentLength: &cl,
						ContentType:   &wantCT,
						Metadata:      wantMeta,
						Body:          bytes.NewReader(wantBody),
					})
				}()

				close(start)
				wg.Wait()

				if delErr != nil {
					t.Fatalf("round %d: DeleteObject(%s): %v", round, dirKey, delErr)
				}
				// If PutObject won the lock before DeleteObject removed the
				// directory, PutObject legitimately fails with ErrExistingObjectIsDirectory.
				if errors.Is(putErr, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)) {
					continue
				}
				if putErr != nil {
					t.Fatalf("round %d: PutObject(%s): %v", round, fileKey, putErr)
				}

				head, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &fileKey})
				if err != nil {
					t.Fatalf("round %d: HeadObject(%s): %v", round, fileKey, err)
				}
				if got := aws.ToString(head.ETag); got != putOut.ETag {
					t.Fatalf("round %d: HeadObject ETag = %q, want %q", round, got, putOut.ETag)
				}
				if got := aws.ToString(head.ContentType); got != wantCT {
					t.Fatalf("round %d: HeadObject ContentType = %q, want %q", round, got, wantCT)
				}
				if !maps.Equal(head.Metadata, wantMeta) {
					t.Fatalf("round %d: HeadObject Metadata = %v, want %v", round, head.Metadata, wantMeta)
				}
			}
		})
	}
}

func TestObjLockKeyNormalization(t *testing.T) {
	wantKey := "dir/foo"
	wantShard := objLockShard(wantKey)
	for _, alias := range []string{
		"dir/foo/",
		"dir/foo//",
		"dir//foo",
		"dir///foo//",
		"/dir/foo",
		"//dir/foo",
		"./dir/foo",
		"dir/./foo",
		"dir/a/../foo",
	} {
		if got := normalizeObjLockKey(alias); got != wantKey {
			t.Fatalf("normalizeObjLockKey(%q) = %q, want %q", alias, got, wantKey)
		}
		if got := objLockShard(alias); got != wantShard {
			t.Fatalf("objLockShard(%q) = %d, objLockShard(%q) = %d; want equal", alias, got, wantKey, wantShard)
		}
	}

	rootShard := objLockShard("")
	for _, rootAlias := range []string{"", ".", "/", "///", "a/.."} {
		if got := normalizeObjLockKey(rootAlias); got != "" {
			t.Fatalf("normalizeObjLockKey(%q) = %q, want %q", rootAlias, got, "")
		}
		if got := objLockShard(rootAlias); got != rootShard {
			t.Fatalf("objLockShard(%q) = %d, want %d", rootAlias, got, rootShard)
		}
	}

	if normalizeObjLockKey(`a\b`) == normalizeObjLockKey("a/b") {
		t.Fatalf("normalizeObjLockKey(%q) unexpectedly matched normalizeObjLockKey(%q)", `a\b`, "a/b")
	}
}

type etagSyncMeta struct {
	meta.MetadataStorer
	t       *testing.T
	seedKey string
	slot    chan struct{}
	once    sync.Once
	release func()
	putDone <-chan struct{}
}

func (m *etagSyncMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	val, err := m.MetadataStorer.RetrieveAttribute(f, bucket, object, attribute)
	if attribute == etagkey && err == nil {
		m.once.Do(func() {
			select {
			case <-m.slot:
				m.slot <- struct{}{}
				m.t.Errorf("RetrieveAttribute(%q, etag): expected publish lock slot for %q to be held, but it was free", object, m.seedKey)
			default:
			}
			m.release()
			select {
			case <-m.putDone:
			case <-time.After(25 * time.Millisecond):
			}
		})
	}
	return val, err
}

func TestConditionalDeleteVsOverwriteAtomicityDeterministic(t *testing.T) {
	ctx := context.Background()
	const (
		bucket  = "cond-det-bucket"
		seedKey = "dir/foo"
	)

	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			for _, delKey := range []string{"dir/foo", "dir//foo", "/dir/foo"} {
				t.Run("delKey="+delKey, func(t *testing.T) {
					p := newTestPosix(t, mkMeta)
					defer p.Shutdown()
					createTestBucket(t, p, bucket)

					seedRes, err := testPut(p, bucket, seedKey, []byte("old"), nil, nil)
					if err != nil {
						t.Fatalf("seed PutObject: %v", err)
					}
					oldETag := seedRes.ETag

					slotIdx := objLockSlot(sha256.Sum256([]byte(bucket)), objLockShard(seedKey))
					slot := p.objLockSlots[slotIdx]

					putReady := make(chan struct{})
					releasePut := make(chan struct{})
					putDone := make(chan struct{})
					var releaseOnce sync.Once
					release := func() {
						releaseOnce.Do(func() { close(releasePut) })
					}

					p.meta = &etagSyncMeta{
						MetadataStorer: p.meta,
						t:              t,
						seedKey:        seedKey,
						slot:           slot,
						release:        release,
						putDone:        putDone,
					}

					var putOut s3response.PutObjectOutput
					var putErr error
					go func() {
						defer close(putDone)
						newBody := []byte("new")
						cl := int64(len(newBody))
						putOut, putErr = p.PutObjectWithPostFunc(ctx, s3response.PutObjectInput{
							Bucket:        aws.String(bucket),
							Key:           aws.String(seedKey),
							ContentLength: &cl,
							Body:          bytes.NewReader(newBody),
						}, func(*os.File) error {
							close(putReady)
							<-releasePut
							return nil
						})
					}()
					defer func() {
						release()
						<-putDone
					}()

					select {
					case <-putReady:
					case <-putDone:
						t.Fatalf("PutObject exited before postprocess: %v", putErr)
					}

					_, delErr := p.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket:  aws.String(bucket),
						Key:     aws.String(delKey),
						IfMatch: aws.String(oldETag),
					})

					release()
					<-putDone

					if putErr != nil {
						t.Fatalf("PutObject failed: %v", putErr)
					}
					if delErr != nil {
						t.Fatalf("DeleteObject(%q) failed: %v", delKey, delErr)
					}

					head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket: aws.String(bucket),
						Key:    aws.String(seedKey),
					})
					if err != nil {
						t.Fatalf("HeadObject(%q) failed: %v", seedKey, err)
					}
					if got := aws.ToString(head.ETag); got != putOut.ETag {
						t.Fatalf("HeadObject ETag = %q, want %q", got, putOut.ETag)
					}

					get, err := p.GetObject(ctx, &s3.GetObjectInput{
						Bucket: aws.String(bucket),
						Key:    aws.String(seedKey),
					})
					if err != nil {
						t.Fatalf("GetObject(%q) failed: %v", seedKey, err)
					}
					gotBody, err := io.ReadAll(get.Body)
					_ = get.Body.Close()
					if err != nil {
						t.Fatalf("read GetObject body: %v", err)
					}
					if !bytes.Equal(gotBody, []byte("new")) {
						t.Fatalf("GetObject body = %q, want %q", gotBody, "new")
					}
					if got := aws.ToString(get.ETag); got != putOut.ETag {
						t.Fatalf("GetObject ETag = %q, want %q", got, putOut.ETag)
					}
				})
			}
		})
	}
}

func TestConditionalDeleteVsOverwriteRace(t *testing.T) {
	ctx := context.Background()
	const rounds = 20

	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newVersionedTestPosix(t, mkMeta)
			defer p.Shutdown()

			unversioned := "cond-ovw-unversioned"
			versioned := "cond-ovw-versioned"
			suspended := "cond-ovw-suspended"
			for _, b := range []string{unversioned, versioned, suspended} {
				createTestBucket(t, p, b)
			}
			if err := p.PutBucketVersioning(ctx, versioned, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("enable versioning: %v", err)
			}
			if err := p.PutBucketVersioning(ctx, suspended, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("enable versioning before suspend: %v", err)
			}
			if err := p.PutBucketVersioning(ctx, suspended, types.BucketVersioningStatusSuspended); err != nil {
				t.Fatalf("suspend versioning: %v", err)
			}

			for _, tc := range []struct {
				name     string
				bucket   string
				useBatch bool
			}{
				{name: "unversioned", bucket: unversioned},
				{name: "versioned", bucket: versioned},
				{name: "suspended", bucket: suspended},
				{name: "DeleteObjects", bucket: unversioned, useBatch: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for round := 0; round < rounds; round++ {
						key := fmt.Sprintf("key-%s-%02d", tc.name, round)
						seedRes, err := testPut(p, tc.bucket, key, []byte("old"), nil, nil)
						if err != nil {
							t.Fatalf("round %d: seed put: %v", round, err)
						}
						oldETag := seedRes.ETag

						start := make(chan struct{})
						var wg sync.WaitGroup
						var putOut s3response.PutObjectOutput
						var putErr error
						var delErr error
						var batchOut s3response.DeleteResult

						wg.Add(2)
						go func() {
							defer wg.Done()
							<-start
							putOut, putErr = testPut(p, tc.bucket, key, []byte("new"), nil, nil)
						}()
						go func() {
							defer wg.Done()
							<-start
							if tc.useBatch {
								batchOut, delErr = p.DeleteObjects(ctx, &s3.DeleteObjectsInput{
									Bucket: aws.String(tc.bucket),
									Delete: &types.Delete{
										Objects: []types.ObjectIdentifier{{
											Key:  aws.String(key),
											ETag: aws.String(oldETag),
										}},
									},
								})
								return
							}
							_, delErr = p.DeleteObject(ctx, &s3.DeleteObjectInput{
								Bucket:  aws.String(tc.bucket),
								Key:     aws.String(key),
								IfMatch: aws.String(oldETag),
							})
						}()

						close(start)
						wg.Wait()

						if putErr != nil {
							t.Fatalf("round %d: PutObject failed: %v", round, putErr)
						}
						if tc.useBatch {
							if delErr != nil {
								t.Fatalf("round %d: DeleteObjects failed: %v", round, delErr)
							}
							okDeleted := len(batchOut.Deleted) == 1 && len(batchOut.Error) == 0
							okPrecond := len(batchOut.Deleted) == 0 && len(batchOut.Error) == 1 &&
								aws.ToString(batchOut.Error[0].Code) == "PreconditionFailed"
							if !okDeleted && !okPrecond {
								t.Fatalf("round %d: unexpected DeleteObjects result: deleted=%d errors=%+v",
									round, len(batchOut.Deleted), batchOut.Error)
							}
						} else if delErr != nil && !isPreconditionFailed(delErr) {
							t.Fatalf("round %d: DeleteObject unexpected error: %v", round, delErr)
						}

						head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
							Bucket: aws.String(tc.bucket),
							Key:    aws.String(key),
						})
						if err != nil {
							t.Fatalf("round %d: HeadObject(%q) failed: %v", round, key, err)
						}
						if got := aws.ToString(head.ETag); got != putOut.ETag {
							t.Fatalf("round %d: HeadObject ETag = %q, want %q", round, got, putOut.ETag)
						}

						get, err := p.GetObject(ctx, &s3.GetObjectInput{
							Bucket: aws.String(tc.bucket),
							Key:    aws.String(key),
						})
						if err != nil {
							t.Fatalf("round %d: GetObject(%q) failed: %v", round, key, err)
						}
						gotBody, err := io.ReadAll(get.Body)
						_ = get.Body.Close()
						if err != nil {
							t.Fatalf("round %d: read GetObject body: %v", round, err)
						}
						if !bytes.Equal(gotBody, []byte("new")) {
							t.Fatalf("round %d: GetObject body = %q, want %q", round, gotBody, "new")
						}
						if got := aws.ToString(get.ETag); got != putOut.ETag {
							t.Fatalf("round %d: GetObject ETag = %q, want %q", round, got, putOut.ETag)
						}
					}
				})
			}
		})
	}
}
