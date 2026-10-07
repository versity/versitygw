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

package daos

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestCopyRecomputesETagAndKeepsMetadata(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "src", "copied-bytes", "text/plain", map[string]string{"color": "blue"})
	obj, err := fs.Open(objectPath("bucket", "src"), openRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SetXattr(obj, attrETag, []byte(`"planted"`)); err != nil {
		t.Fatal(err)
	}
	fs.Release(obj)

	out, err := d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("dst"),
		CopySource: backend.GetPtrFromString("bucket/src"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.CopyObjectResult == nil || awsString(out.CopyObjectResult.ETag) == `"planted"` {
		t.Fatalf("etag = %v", out.CopyObjectResult)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("dst"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "copied-bytes" || awsString(got.ETag) != awsString(out.CopyObjectResult.ETag) {
		t.Fatalf("body %q etag %q", body, awsString(got.ETag))
	}
	if awsString(got.ContentType) != "text/plain" || got.Metadata["color"] != "blue" {
		t.Fatalf("type %q meta %v", awsString(got.ContentType), got.Metadata)
	}
}

func TestCopyReplaceUsesRequestHeaders(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "src", "same", "text/plain", map[string]string{"color": "blue"})
	ctype := "application/octet-stream"
	_, err := d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("dst"),
		CopySource:        backend.GetPtrFromString("bucket/src"),
		MetadataDirective: types.MetadataDirectiveReplace,
		ContentType:       &ctype,
		Metadata:          map[string]string{"color": "red"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("dst"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(got.ContentType) != ctype || got.Metadata["color"] != "red" {
		t.Fatalf("type %q meta %v", awsString(got.ContentType), got.Metadata)
	}
}

func TestCopyRejectsVersionAndSelfCopy(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "src", "same", "", nil)
	_, err := d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("dst"),
		CopySource: backend.GetPtrFromString("bucket/src?versionId=1"),
	})
	if !errors.Is(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "1")) {
		t.Fatalf("version = %v", err)
	}
	algo := "AES256"
	_, err = d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:               backend.GetPtrFromString("bucket"),
		Key:                  backend.GetPtrFromString("dst"),
		CopySource:           backend.GetPtrFromString("bucket/src"),
		SSECustomerAlgorithm: &algo,
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotImplemented)) {
		t.Fatalf("sse = %v", err)
	}
	_, err = d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("src"),
		CopySource: backend.GetPtrFromString("bucket/src"),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidCopyDest)) {
		t.Fatalf("self = %v", err)
	}
}

func TestUploadPartCopyWritesTheRequestedRange(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "src", "abcdefghij", "", nil)
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("joined"),
	})
	if err != nil {
		t.Fatal(err)
	}
	rng := "bytes=3-6"
	part, err := d.UploadPartCopy(context.Background(), &s3.UploadPartCopyInput{
		Bucket:          backend.GetPtrFromString("bucket"),
		Key:             backend.GetPtrFromString("joined"),
		UploadId:        &created.UploadId,
		PartNumber:      int32ptr(1),
		CopySource:      backend.GetPtrFromString("bucket/src"),
		CopySourceRange: &rng,
	})
	if err != nil {
		t.Fatal(err)
	}
	ver := "9"
	_, err = d.UploadPartCopy(context.Background(), &s3.UploadPartCopyInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("joined"),
		UploadId:   &created.UploadId,
		PartNumber: int32ptr(2),
		CopySource: backend.GetPtrFromString("bucket/src?versionId=" + ver),
	})
	if !errors.Is(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, ver)) {
		t.Fatalf("version = %v", err)
	}
	_, _, err = d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("joined"),
		UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
			{PartNumber: int32ptr(1), ETag: part.ETag},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("joined"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "defg" {
		t.Fatalf("body = %q", body)
	}
}

func TestUploadPartCopyKeepsCompositeChecksum(t *testing.T) {
	d, _ := newTest(t)
	body := "hello"
	put(t, d, "src", body, "", nil)
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("copied"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumType:      types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatal(err)
	}
	part, err := d.UploadPartCopy(context.Background(), &s3.UploadPartCopyInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("copied"),
		UploadId:   &created.UploadId,
		PartNumber: int32ptr(1),
		CopySource: backend.GetPtrFromString("bucket/src"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := hashBytes(types.ChecksumAlgorithmCrc32, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if awsString(part.ChecksumCRC32) != sum {
		t.Fatalf("copied checksum %q", awsString(part.ChecksumCRC32))
	}
	reader, err := utils.NewCompositeChecksumReader(utils.HashTypeCRC32)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Process(sum); err != nil {
		t.Fatal(err)
	}
	bare := reader.Sum()
	done, _, err := d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("copied"),
		UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
			{PartNumber: int32ptr(1), ETag: part.ETag, ChecksumCRC32: part.ChecksumCRC32},
		}},
		ChecksumCRC32: &bare,
		ChecksumType:  types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(done.ChecksumCRC32) != bare+"-1" {
		t.Fatalf("complete checksum %q", awsString(done.ChecksumCRC32))
	}
}
