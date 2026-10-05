// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

package daos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestMultipartCopiesPartBytes(t *testing.T) {
	d, fs := newTest(t)
	ctype := "text/plain"
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:      backend.GetPtrFromString("bucket"),
		Key:         backend.GetPtrFromString("photos/a.jpg"),
		ContentType: &ctype,
		Metadata:    map[string]string{"origin": "lab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e1 := uploadPart(t, d, "photos/a.jpg", created.UploadId, 1, "hello")
	e2 := uploadPart(t, d, "photos/a.jpg", created.UploadId, 2, "world")
	listed, err := d.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket: backend.GetPtrFromString("bucket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Uploads) != 1 || listed.Uploads[0].Key != "photos/a.jpg" || listed.Uploads[0].UploadID != created.UploadId {
		t.Fatalf("uploads = %+v", listed.Uploads)
	}
	parts, err := d.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("photos/a.jpg"),
		UploadId: &created.UploadId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(parts.Parts) != 2 || parts.Parts[0].ETag != e1 || parts.Parts[1].Size != 5 {
		t.Fatalf("parts = %+v", parts.Parts)
	}
	completed := []types.CompletedPart{
		{PartNumber: int32ptr(1), ETag: &e1},
		{PartNumber: int32ptr(2), ETag: &e2},
	}
	wantETag, err := backend.ComputeMultipartETagFromPartETags(completed)
	if err != nil {
		t.Fatal(err)
	}
	readBefore := fs.BytesRead()
	wroteBefore := fs.BytesWritten()
	done, version, err := d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:          backend.GetPtrFromString("bucket"),
		Key:             backend.GetPtrFromString("photos/a.jpg"),
		UploadId:        &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		t.Fatal(err)
	}
	if version != "" || awsString(done.ETag) != wantETag {
		t.Fatalf("complete version %q etag %q want %q", version, awsString(done.ETag), wantETag)
	}
	if fs.BytesRead()-readBefore != 10 || fs.BytesWritten()-wroteBefore != 10 {
		t.Fatalf("copied read %d write %d", fs.BytesRead()-readBefore, fs.BytesWritten()-wroteBefore)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("photos/a.jpg"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "helloworld" || awsString(got.ContentType) != ctype || got.Metadata["origin"] != "lab" {
		t.Fatalf("object %q type %q meta %v", body, awsString(got.ContentType), got.Metadata)
	}
	objects, err := d.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket:  backend.GetPtrFromString("bucket"),
		MaxKeys: int32ptr(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(objects.Contents) != 1 || awsString(objects.Contents[0].Key) != "photos/a.jpg" {
		t.Fatalf("list = %+v", objects.Contents)
	}
}

func TestCompleteRetriesClaimedUpload(t *testing.T) {
	d, fs := newTest(t)
	created := startUpload(t, d, "a.bin")
	e1 := uploadPart(t, d, "a.bin", created.UploadId, 1, "abcd")
	completed := []types.CompletedPart{{PartNumber: int32ptr(1), ETag: &e1}}
	fs.FailMoveOn(2)
	_, _, err := d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:          backend.GetPtrFromString("bucket"),
		Key:             backend.GetPtrFromString("a.bin"),
		UploadId:        &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err == nil {
		t.Fatal("expected publish failure")
	}
	still, err := d.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("a.bin"),
		UploadId: &created.UploadId,
	})
	if err != nil || len(still.Parts) != 1 {
		t.Fatalf("claimed list = %+v err %v", still.Parts, err)
	}
	readBefore := fs.BytesRead()
	_, _, err = d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:          backend.GetPtrFromString("bucket"),
		Key:             backend.GetPtrFromString("a.bin"),
		UploadId:        &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fs.BytesRead()-readBefore != 4 {
		t.Fatalf("retry read %d", fs.BytesRead()-readBefore)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a.bin"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "abcd" {
		t.Fatalf("body %q", body)
	}
}

func TestAbortRemovesUpload(t *testing.T) {
	d, _ := newTest(t)
	created := startUpload(t, d, "gone")
	uploadPart(t, d, "gone", created.UploadId, 1, "x")
	if err := d.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("gone"),
		UploadId: &created.UploadId,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("gone"),
		UploadId:   &created.UploadId,
		PartNumber: int32ptr(2),
		Body:       bytes.NewReader([]byte("y")),
	})
	if !errors.Is(err, s3err.GetNoSuchUploadErr(created.UploadId)) {
		t.Fatalf("upload after abort = %v", err)
	}
}

func TestMultipartRejectsUnsupported(t *testing.T) {
	d, _ := newTest(t)
	_, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("dir/"),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)) {
		t.Fatalf("directory = %v", err)
	}
	_, err = d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("locked"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotImplemented)) {
		t.Fatalf("checksum = %v", err)
	}
}

func startUpload(t *testing.T, d *Daos, key string) s3response.InitiateMultipartUploadResult {
	t.Helper()
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString(key),
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func uploadPart(t *testing.T, d *Daos, key, uploadID string, n int32, body string) string {
	t.Helper()
	out, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
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

func int64ptr(v int64) *int64 { return &v }
