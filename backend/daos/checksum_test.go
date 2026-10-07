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
	"encoding/json"
	"errors"
	"fmt"
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
