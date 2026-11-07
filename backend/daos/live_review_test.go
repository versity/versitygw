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
		if err := fs.Remove(bucket, true); err != nil {
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
