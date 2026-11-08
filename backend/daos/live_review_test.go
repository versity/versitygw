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

//go:build linux && cgo && daos

package daos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func openLive(t *testing.T) (string, *Daos) {
	t.Helper()
	pool := os.Getenv("DAOS_POOL")
	cont := os.Getenv("DAOS_CONT")
	if pool == "" || cont == "" {
		t.Skip("DAOS_POOL and DAOS_CONT are required")
	}
	sys := os.Getenv("DAOS_SYS")
	bucket := "vgw-live-" + uuid.NewString()
	fs, err := openContainer(pool, sys, cont)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir(bucket); err != nil {
		fs.Close()
		t.Fatal(err)
	}
	fs.Close()
	be, err := New(pool, cont, sys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		be.Shutdown()
		fs, err := openContainer(pool, sys, cont)
		if err != nil {
			t.Errorf("cleanup open: %v", err)
			return
		}
		defer fs.Close()
		if err := fs.Remove(bucket, true); err != nil && !errors.Is(err, errNotExist) {
			t.Errorf("cleanup bucket: %v", err)
		}
	})
	return bucket, be
}

func TestLivePutFileOverDirectoryIsConflict(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	if _, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("dir/"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("dir/keep"),
		Body:   bytes.NewReader([]byte("keep")),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("dir"),
		Body:   bytes.NewReader([]byte("file")),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)) {
		t.Fatalf("file over directory = %v", err)
	}
	got, err := be.GetObject(ctx, &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("dir/keep"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	if err != nil || string(body) != "keep" {
		t.Fatalf("kept child %q %v", body, err)
	}
}

func TestLivePutLongComponentIsKeyTooLong(t *testing.T) {
	bucket, be := openLive(t)
	key := strings.Repeat("a", maxComponent+1)
	_, err := be.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString(key),
		Body:   bytes.NewReader([]byte("x")),
	})
	var long s3err.KeyTooLongError
	if !errors.As(err, &long) || long.Size != int64(maxComponent+1) || long.MaxSizeAllowed != int64(maxComponent) {
		t.Fatalf("long component = %v", err)
	}
	_, err = be.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString(key + "/child"),
		Body:   bytes.NewReader([]byte("x")),
	})
	long = s3err.KeyTooLongError{}
	if !errors.As(err, &long) || long.Size != int64(maxComponent+1) {
		t.Fatalf("long parent = %v", err)
	}
}

func TestLiveDeleteBucketKeepsAnUpload(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	created, err := be.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.DeleteBucket(ctx, bucket); !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, bucket)) {
		t.Fatalf("delete = %v", err)
	}
	part := int32(1)
	if _, err := be.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString(bucket),
		Key:           backend.GetPtrFromString("obj"),
		UploadId:      &created.UploadId,
		PartNumber:    &part,
		ContentLength: int64ptr(4),
		Body:          bytes.NewReader([]byte("part")),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLiveDeleteKeepsImplicitParents(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	if _, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("a/b/c"),
		Body:   bytes.NewReader([]byte("c")),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := be.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("a/b/c"),
	}); err != nil {
		t.Fatal(err)
	}
	pool := os.Getenv("DAOS_POOL")
	fs, err := openContainer(pool, os.Getenv("DAOS_SYS"), os.Getenv("DAOS_CONT"))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	for _, p := range []string{bucket + "/a", bucket + "/a/b"} {
		info, err := fs.Stat(p)
		if err != nil || !info.IsDir {
			t.Fatalf("%s = %+v %v", p, info, err)
		}
	}
}

func TestLiveGetReadsTheWrittenObject(t *testing.T) {
	bucket, be := openLive(t)
	want := bytes.Repeat([]byte("z"), 1<<20)
	ctx := context.Background()
	if _, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("big"),
		Body:   bytes.NewReader(want),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := be.GetObject(ctx, &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("big"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("got %d bytes, want %d", len(body), len(want))
	}
}

func TestLiveMultipartCompletes(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	key := "photos/a.jpg"
	ctype := "image/jpeg"
	created, err := be.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket:      backend.GetPtrFromString(bucket),
		Key:         backend.GetPtrFromString(key),
		ContentType: &ctype,
		Metadata:    map[string]string{"origin": "lab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p1 := int32(1)
	p2 := int32(2)
	e1 := uploadLivePart(t, be, bucket, key, created.UploadId, p1, "hello")
	e2 := uploadLivePart(t, be, bucket, key, created.UploadId, p2, "world")
	listed, err := be.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   backend.GetPtrFromString(bucket),
		Key:      backend.GetPtrFromString(key),
		UploadId: &created.UploadId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Parts) != 2 || listed.Parts[0].ETag != e1 || listed.Parts[1].ETag != e2 {
		t.Fatalf("parts = %+v", listed.Parts)
	}
	completed := []types.CompletedPart{
		{PartNumber: &p1, ETag: &e1},
		{PartNumber: &p2, ETag: &e2},
	}
	wantETag, err := backend.ComputeMultipartETagFromPartETags(created.UploadId, completed)
	if err != nil {
		t.Fatal(err)
	}
	done, version, err := be.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          backend.GetPtrFromString(bucket),
		Key:             backend.GetPtrFromString(key),
		UploadId:        &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		t.Fatal(err)
	}
	if version != "" || awsString(done.ETag) != wantETag {
		t.Fatalf("complete version %q etag %q want %q", version, awsString(done.ETag), wantETag)
	}
	got, err := be.GetObject(ctx, &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString(key),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "helloworld" || awsString(got.ContentType) != ctype || got.Metadata["origin"] != "lab" {
		t.Fatalf("object %q type %q meta %v", body, awsString(got.ContentType), got.Metadata)
	}
	if _, err := be.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   backend.GetPtrFromString(bucket),
		Key:      backend.GetPtrFromString(key),
		UploadId: &created.UploadId,
	}); err == nil {
		t.Fatal("parts survived the completion")
	}
}

func TestLiveAbortLetsBucketDelete(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	created, err := be.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	p1 := int32(1)
	if _, err := be.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString(bucket),
		Key:           backend.GetPtrFromString("obj"),
		UploadId:      &created.UploadId,
		PartNumber:    &p1,
		ContentLength: int64ptr(4),
		Body:          bytes.NewReader([]byte("part")),
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   backend.GetPtrFromString(bucket),
		Key:      backend.GetPtrFromString("obj"),
		UploadId: &created.UploadId,
	}); err != nil {
		t.Fatal(err)
	}
	if err := be.DeleteBucket(ctx, bucket); err != nil {
		t.Fatalf("delete after abort = %v", err)
	}
}

func TestLiveRangeGetSlicesTheObject(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	want := "0123456789"
	if _, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("ranged"),
		Body:   bytes.NewReader([]byte(want)),
	}); err != nil {
		t.Fatal(err)
	}
	rng := "bytes=2-5"
	got, err := be.GetObject(ctx, &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("ranged"),
		Range:  &rng,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "2345" {
		t.Fatalf("range = %q", body)
	}
}

func TestLiveCopyObjectPreservesMetadata(t *testing.T) {
	bucket, be := openLive(t)
	ctx := context.Background()
	ctype := "text/plain"
	if _, err := be.PutObject(ctx, s3response.PutObjectInput{
		Bucket:      backend.GetPtrFromString(bucket),
		Key:         backend.GetPtrFromString("src"),
		Body:        bytes.NewReader([]byte("copy me")),
		ContentType: &ctype,
		Metadata:    map[string]string{"origin": "lab"},
	}); err != nil {
		t.Fatal(err)
	}
	out, err := be.CopyObject(ctx, s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString(bucket),
		Key:        backend.GetPtrFromString("dst/copied"),
		CopySource: backend.GetPtrFromString(bucket + "/src"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := be.GetObject(ctx, &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("dst/copied"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "copy me" || awsString(got.ContentType) != ctype || got.Metadata["origin"] != "lab" {
		t.Fatalf("copy %q type %q meta %v", body, awsString(got.ContentType), got.Metadata)
	}
	if awsString(got.ETag) != awsString(out.CopyObjectResult.ETag) {
		t.Fatalf("etag %q want %q", awsString(got.ETag), awsString(out.CopyObjectResult.ETag))
	}
}

func uploadLivePart(t *testing.T, be *Daos, bucket, key, uploadID string, n int32, body string) string {
	t.Helper()
	out, err := be.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString(bucket),
		Key:           backend.GetPtrFromString(key),
		UploadId:      &uploadID,
		PartNumber:    &n,
		ContentLength: int64ptr(int64(len(body))),
		Body:          bytes.NewReader([]byte(body)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return awsString(out.ETag)
}

func TestLiveRepeatedConnectionsOpenAndClose(t *testing.T) {
	pool := os.Getenv("DAOS_POOL")
	cont := os.Getenv("DAOS_CONT")
	if pool == "" || cont == "" {
		t.Skip("DAOS_POOL and DAOS_CONT are required")
	}
	sys := os.Getenv("DAOS_SYS")
	for i := 0; i < 8; i++ {
		handles := make([]*dfsFS, 4)
		for j := range handles {
			fs, err := openContainer(pool, sys, cont)
			if err != nil {
				t.Fatalf("round %d open %d: %v", i, j, err)
			}
			if _, err := fs.Stat(""); err == nil {
				t.Fatalf("round %d stat of empty path succeeded", i)
			}
			handles[j] = fs
		}
		for _, fs := range handles {
			if err := fs.Close(); err != nil {
				t.Fatalf("round %d close: %v", i, err)
			}
		}
	}
}
