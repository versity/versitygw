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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestPutChecksumRoundTrip(t *testing.T) {
	d, fs := newTest(t)
	want, err := hashBytes(types.ChecksumAlgorithmCrc32, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("obj"),
		Body:              bytes.NewReader([]byte("hello")),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumCRC32:     &want,
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(out.ChecksumCRC32) != want || out.ChecksumType != types.ChecksumTypeFullObject {
		t.Fatalf("put checksum %q type %q", awsString(out.ChecksumCRC32), out.ChecksumType)
	}
	obj, err := fs.Open("bucket/obj", openRead)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Release(obj)
	raw, err := fs.GetXattr(obj, attrChecksums)
	if err != nil {
		t.Fatal(err)
	}
	var stored s3response.Checksum
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Algorithm != types.ChecksumAlgorithmCrc32 || awsString(stored.CRC32) != want {
		t.Fatalf("stored = %+v", stored)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(got.ChecksumCRC32) != want || got.ChecksumType != types.ChecksumTypeFullObject {
		t.Fatalf("get checksum %q type %q", awsString(got.ChecksumCRC32), got.ChecksumType)
	}
	head, err := d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(head.ChecksumCRC32) != want {
		t.Fatalf("head checksum %q", awsString(head.ChecksumCRC32))
	}
}

func TestPutRejectsBadChecksum(t *testing.T) {
	d, _ := newTest(t)
	bad := "00000000"
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("obj"),
		Body:              bytes.NewReader([]byte("hello")),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumCRC32:     &bad,
	})
	if !errors.Is(err, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc32)) {
		t.Fatalf("err = %v", err)
	}
}

func TestDirectoryPutBadChecksumLeavesObject(t *testing.T) {
	d, fs := newTest(t)
	bad := "00000000"
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("folder/"),
		Body:              bytes.NewReader(nil),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumCRC32:     &bad,
	})
	if !errors.Is(err, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc32)) {
		t.Fatalf("err = %v", err)
	}
	if _, err := fs.Stat("bucket/folder"); !errors.Is(err, errNotExist) {
		t.Fatalf("stat = %v", err)
	}
}

func TestMultipartChecksumComposite(t *testing.T) {
	d, _ := newTest(t)
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("mp"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumType:      types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := "hello"
	sum, err := hashBytes(types.ChecksumAlgorithmCrc32, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	n := int32(1)
	part, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("mp"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: int64ptr(int64(len(body))),
		Body:          bytes.NewReader([]byte(body)),
		ChecksumCRC32: &sum,
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(part.ChecksumCRC32) != sum {
		t.Fatalf("part checksum %q", awsString(part.ChecksumCRC32))
	}
	reader, err := utils.NewCompositeChecksumReader(utils.HashTypeCRC32)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Process(sum); err != nil {
		t.Fatal(err)
	}
	bare := reader.Sum()
	want := fmt.Sprintf("%s-1", bare)
	completed := []types.CompletedPart{{
		PartNumber:    &n,
		ETag:          part.ETag,
		ChecksumCRC32: part.ChecksumCRC32,
	}}
	done, _, err := d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:          backend.GetPtrFromString("bucket"),
		Key:             backend.GetPtrFromString("mp"),
		UploadId:        &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
		ChecksumCRC32:   &bare,
		ChecksumType:    types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatal(err)
	}
	if done.ChecksumType == nil || *done.ChecksumType != types.ChecksumTypeComposite || awsString(done.ChecksumCRC32) != want {
		t.Fatalf("complete %q want %q type %v", awsString(done.ChecksumCRC32), want, done.ChecksumType)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("mp"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(got.ChecksumCRC32) != awsString(done.ChecksumCRC32) || got.ChecksumType != types.ChecksumTypeComposite {
		t.Fatalf("get %q type %q", awsString(got.ChecksumCRC32), got.ChecksumType)
	}
}

type shortHashReader struct {
	body []byte
	alg  string
	sum  string
}

func (r *shortHashReader) Read(p []byte) (int, error) {
	if len(r.body) == 0 {
		return 0, nil
	}
	n := copy(p, r.body)
	r.body = r.body[n:]
	return n, nil
}

func (r *shortHashReader) Algorithm() string { return r.alg }

func (r *shortHashReader) Checksum() string { return r.sum }

func crc32Chunk(body, trailer string) string {
	return fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n", len(body), body, trailer)
}

func TestUploadPartReadsPastContentLength(t *testing.T) {
	d, _ := newTest(t)
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("mp"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumType:      types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := "hello"
	h := crc32.NewIEEE()
	_, _ = h.Write([]byte(body))
	sum := base64.StdEncoding.EncodeToString(h.Sum(nil))
	wrong := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0})
	n := int32(1)
	length := int64(len(body))
	chunk, err := utils.NewUnsignedChunkReader(strings.NewReader(crc32Chunk(body, wrong)), "x-amz-checksum-crc32", length)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("mp"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: &length,
		Body:          chunk,
	})
	if !errors.Is(err, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc32)) {
		t.Fatalf("trailing checksum err = %v", err)
	}
	_, err = d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("mp"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: &length,
		Body:          bytes.NewReader([]byte(body)),
		ChecksumCRC32: backend.GetPtrFromString("00000000"),
	})
	if !errors.Is(err, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc32)) {
		t.Fatalf("header checksum err = %v", err)
	}
	good, err := utils.NewUnsignedChunkReader(strings.NewReader(crc32Chunk(body, sum)), "x-amz-checksum-crc32", length)
	if err != nil {
		t.Fatal(err)
	}
	part, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("mp"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: &length,
		Body:          good,
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(part.ChecksumCRC32) != sum {
		t.Fatalf("part checksum %q", awsString(part.ChecksumCRC32))
	}
}

type emptyThenEOF struct {
	n int
}

func (r *emptyThenEOF) Read([]byte) (int, error) {
	if r.n == 0 {
		r.n++
		return 0, nil
	}
	return 0, io.EOF
}

func TestUploadPartAllowsOneEmptyRead(t *testing.T) {
	d, _ := newTest(t)
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("empty-read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	n := int32(1)
	length := int64(0)
	part, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("empty-read"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: &length,
		Body:          &emptyThenEOF{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if part.ETag == nil || *part.ETag == "" {
		t.Fatal("missing etag")
	}
}

func TestRejectedCompleteLeavesUploadActive(t *testing.T) {
	d, _ := newTest(t)
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:            backend.GetPtrFromString("bucket"),
		Key:               backend.GetPtrFromString("mp"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumType:      types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := "part"
	sum, err := hashBytes(types.ChecksumAlgorithmCrc32, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	n := int32(1)
	part, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("mp"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: int64ptr(int64(len(body))),
		Body:          bytes.NewReader([]byte(body)),
		ChecksumCRC32: &sum,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("mp"),
		UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{
			PartNumber: &n,
			ETag:       part.ETag,
		}}},
	})
	var api s3err.APIError
	if !errors.As(err, &api) || api.Code != "InvalidRequest" {
		t.Fatalf("complete = %v", err)
	}
	if _, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:        backend.GetPtrFromString("bucket"),
		Key:           backend.GetPtrFromString("mp"),
		UploadId:      &created.UploadId,
		PartNumber:    &n,
		ContentLength: int64ptr(int64(len(body))),
		Body:          bytes.NewReader([]byte(body)),
		ChecksumCRC32: &sum,
	}); err != nil {
		t.Fatalf("replacement part = %v", err)
	}
	listed, err := d.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{
		Bucket: backend.GetPtrFromString("bucket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Uploads) != 1 || listed.Uploads[0].Key != "mp" || listed.Uploads[0].UploadID != created.UploadId {
		t.Fatalf("uploads = %+v", listed.Uploads)
	}
}
