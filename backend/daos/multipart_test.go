// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
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
	"slices"
	"testing"
	"time"

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
	var zero time.Time
	_, err = d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:                    backend.GetPtrFromString("bucket"),
		Key:                       backend.GetPtrFromString("plain"),
		ObjectLockRetainUntilDate: &zero,
	})
	if err != nil {
		t.Fatalf("unset lock date = %v", err)
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

func TestListMultipartUploadsResumes(t *testing.T) {
	d, _ := newTest(t)
	first := startUpload(t, d, "photos/a.jpg")
	second := startUpload(t, d, "photos/a.jpg")
	max := int32(1)
	page, err := d.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		MaxUploads: &max,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !page.IsTruncated || len(page.Uploads) != 1 {
		t.Fatalf("first page = %+v truncated %v", page.Uploads, page.IsTruncated)
	}
	next, err := d.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket:         backend.GetPtrFromString("bucket"),
		KeyMarker:      &page.NextKeyMarker,
		UploadIdMarker: &page.NextUploadIDMarker,
		MaxUploads:     &max,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Uploads) != 1 || next.IsTruncated {
		t.Fatalf("second page = %+v truncated %v", next.Uploads, next.IsTruncated)
	}
	got := map[string]bool{page.Uploads[0].UploadID: true, next.Uploads[0].UploadID: true}
	if !got[first.UploadId] || !got[second.UploadId] || page.Uploads[0].UploadID == next.Uploads[0].UploadID {
		t.Fatalf("pages %s then %s, want %s and %s", page.Uploads[0].UploadID, next.Uploads[0].UploadID, first.UploadId, second.UploadId)
	}
}

func TestListMultipartUploadsDelimiterPages(t *testing.T) {
	d, _ := newTest(t)
	startUpload(t, d, "a/x")
	startUpload(t, d, "a/y")
	startUpload(t, d, "b")
	max := int32(1)
	delim := "/"
	var keyMarker, uploadMarker string
	var prefixes, keys []string
	for pageN := 0; pageN < 5; pageN++ {
		page, err := d.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
			Bucket:         backend.GetPtrFromString("bucket"),
			Delimiter:      &delim,
			KeyMarker:      &keyMarker,
			UploadIdMarker: &uploadMarker,
			MaxUploads:     &max,
		})
		if err != nil {
			t.Fatalf("page %d: %v", pageN, err)
		}
		for _, prefix := range page.CommonPrefixes {
			prefixes = append(prefixes, prefix.Prefix)
		}
		for _, upload := range page.Uploads {
			keys = append(keys, upload.Key)
		}
		if !page.IsTruncated {
			break
		}
		keyMarker = page.NextKeyMarker
		uploadMarker = page.NextUploadIDMarker
	}
	if !slices.Equal(prefixes, []string{"a/"}) || !slices.Equal(keys, []string{"b"}) {
		t.Fatalf("prefixes %v keys %v", prefixes, keys)
	}
}

func TestListMultipartUploadsHonorsZero(t *testing.T) {
	d, _ := newTest(t)
	startUpload(t, d, "obj")
	zero := int32(0)
	page, err := d.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		MaxUploads: &zero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Uploads) != 0 || len(page.CommonPrefixes) != 0 || !page.IsTruncated || page.MaxUploads != 0 {
		t.Fatalf("uploads %d prefixes %d truncated %v max %d", len(page.Uploads), len(page.CommonPrefixes), page.IsTruncated, page.MaxUploads)
	}
}

func TestListPartsReturnsChecksumAndHonorsZero(t *testing.T) {
	d, _ := newTest(t)
	sum, err := hashBytes(types.ChecksumAlgorithmCrc32, []byte("part"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("listed"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumType:      types.ChecksumTypeFullObject,
	})
	if err != nil {
		t.Fatal(err)
	}
	n := int32(1)
	_, err = d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("listed"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		Body:          bytes.NewReader([]byte("part")),
		ChecksumCRC32: &sum,
	})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := d.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("listed"),
		UploadId: &created.UploadId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if listed.ChecksumAlgorithm != types.ChecksumAlgorithmCrc32 || len(listed.Parts) != 1 || awsString(listed.Parts[0].ChecksumCRC32) != sum {
		t.Fatalf("listed = %+v", listed)
	}
	zero := int32(0)
	empty, err := d.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("listed"),
		UploadId: &created.UploadId,
		MaxParts: &zero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Parts) != 0 || !empty.IsTruncated {
		t.Fatalf("zero page parts %d truncated %v", len(empty.Parts), empty.IsTruncated)
	}
}
