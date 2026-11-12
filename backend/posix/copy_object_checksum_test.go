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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

// TestCopyObjectSelfChecksumAlgorithm checks that a metadata-only copy of an
// object onto itself with a new checksum algorithm stores and returns the
// FULL_OBJECT checksum of the object's content in that algorithm, for an
// object larger than the copy buffer, a directory object and a multipart
// object with a COMPOSITE checksum.
func TestCopyObjectSelfChecksumAlgorithm(t *testing.T) {
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("random data: %v", err)
	}

	sources := []struct {
		name string
		key  string
		body []byte
		put  func(t *testing.T, p *Posix, bucket, key string, body []byte)
	}{
		{name: "object", key: "object", body: data, put: putSelfCopySource},
		{name: "directory", key: "dir/", body: nil, put: putSelfCopySource},
		{name: "composite multipart", key: "mp", body: data, put: putCompositeSelfCopySource},
	}

	for mode, mkMeta := range metaModes(t) {
		for _, src := range sources {
			t.Run(mode+"/"+src.name, func(t *testing.T) {
				ctx := context.Background()
				p := newTestPosix(t, mkMeta)
				p.copyObjectThreshold = 4 << 20
				bucket, key := "bucket", src.key
				createTestBucket(t, p, bucket)
				src.put(t, p, bucket, key, src.body)

				shaSum := sha256.Sum256(src.body)
				crcSum := binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(src.body))
				for _, tc := range []struct {
					algo types.ChecksumAlgorithm
					want types.ChecksumAlgorithm
					sum  string
					got  func(*s3response.CopyObjectResult) *string
					head func(*s3.HeadObjectOutput) *string
				}{
					{
						algo: types.ChecksumAlgorithmSha256,
						want: types.ChecksumAlgorithmSha256,
						sum:  base64.StdEncoding.EncodeToString(shaSum[:]),
						got:  func(r *s3response.CopyObjectResult) *string { return r.ChecksumSHA256 },
						head: func(h *s3.HeadObjectOutput) *string { return h.ChecksumSHA256 },
					},
					{
						// the algorithm is accepted in any case
						algo: "crc32",
						want: types.ChecksumAlgorithmCrc32,
						sum:  base64.StdEncoding.EncodeToString(crcSum),
						got:  func(r *s3response.CopyObjectResult) *string { return r.ChecksumCRC32 },
						head: func(h *s3.HeadObjectOutput) *string { return h.ChecksumCRC32 },
					},
				} {
					res, err := p.CopyObject(ctx, s3response.CopyObjectInput{
						Bucket:              &bucket,
						Key:                 &key,
						CopySource:          aws.String(bucket + "/" + key),
						ExpectedBucketOwner: aws.String(""),
						MetadataDirective:   types.MetadataDirectiveReplace,
						ChecksumAlgorithm:   tc.algo,
					})
					if err != nil {
						t.Fatalf("copy object with %v: %v", tc.algo, err)
					}
					if got := aws.ToString(tc.got(res.CopyObjectResult)); got != tc.sum {
						t.Errorf("copy %v checksum = %q, want %q", tc.algo, got, tc.sum)
					}

					head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:       &bucket,
						Key:          &key,
						ChecksumMode: types.ChecksumModeEnabled,
					})
					if err != nil {
						t.Fatalf("head object: %v", err)
					}
					if got := aws.ToString(tc.head(head)); got != tc.sum {
						t.Errorf("head %v checksum = %q, want %q", tc.algo, got, tc.sum)
					}
					if head.ChecksumType != types.ChecksumTypeFullObject {
						t.Errorf("head checksum type = %q, want %q", head.ChecksumType, types.ChecksumTypeFullObject)
					}

					stored, err := p.retrieveChecksums(nil, bucket, key)
					if err != nil {
						t.Fatalf("retrieve checksums: %v", err)
					}
					if stored.Algorithm != tc.want || stored.Type != types.ChecksumTypeFullObject {
						t.Errorf("stored checksum is %v %v, want %v %v",
							stored.Algorithm, stored.Type, tc.want, types.ChecksumTypeFullObject)
					}

					if strings.HasSuffix(key, "/") {
						// directory objects are listed without
						// their checksum algorithm
						continue
					}
					list, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket, Prefix: &key, StartAfter: aws.String(""), MaxKeys: aws.Int32(10),
					})
					if err != nil {
						t.Fatalf("list objects: %v", err)
					}
					for _, o := range list.Contents {
						if aws.ToString(o.Key) == key && (len(o.ChecksumAlgorithm) != 1 || o.ChecksumAlgorithm[0] != tc.want) {
							t.Errorf("listed checksum algorithm = %v, want [%v]", o.ChecksumAlgorithm, tc.want)
						}
					}
				}
			})
		}
	}
}

func putSelfCopySource(t *testing.T, p *Posix, bucket, key string, body []byte) {
	t.Helper()
	if _, err := testPut(p, bucket, key, body, nil, nil); err != nil {
		t.Fatalf("put object: %v", err)
	}
}

// putCompositeSelfCopySource writes body as a one part multipart upload with
// a COMPOSITE CRC32 checksum.
func putCompositeSelfCopySource(t *testing.T, p *Posix, bucket, key string, body []byte) {
	t.Helper()
	ctx := context.Background()
	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket:            &bucket,
		Key:               &key,
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		ChecksumType:      types.ChecksumTypeComposite,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}
	partCRC := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(body)))
	part, err := p.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &mp.UploadId,
		PartNumber:    aws.Int32(1),
		ContentLength: aws.Int64(int64(len(body))),
		Body:          bytes.NewReader(body),
		ChecksumCRC32: &partCRC,
	})
	if err != nil {
		t.Fatalf("upload part: %v", err)
	}
	_, _, err = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &mp.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1), ChecksumCRC32: &partCRC}},
		},
	})
	if err != nil {
		t.Fatalf("complete multipart upload: %v", err)
	}
	stored, err := p.retrieveChecksums(nil, bucket, key)
	if err != nil {
		t.Fatalf("retrieve checksums: %v", err)
	}
	if stored.Type != types.ChecksumTypeComposite {
		t.Fatalf("multipart checksum type = %q, want %q", stored.Type, types.ChecksumTypeComposite)
	}
}

// TestSameObjectData checks that a checksum read from an object before the
// publish lock is taken is not used once the object was replaced or changed.
func TestSameObjectData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obj")
	if err := os.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, read, err := hashObjectPath(path, types.ChecksumAlgorithmCrc32)
	if err != nil {
		t.Fatalf("hash object: %v", err)
	}
	same := func() bool {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return sameObjectData(read, fi)
	}
	if !same() {
		t.Fatal("unchanged object is reported changed")
	}

	// changed in place, with a new modification time
	if err := os.WriteFile(path, []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Now(), read.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if same() {
		t.Error("object changed in place is reported unchanged")
	}

	// replaced by another file with the size and modification time read
	tmp := filepath.Join(dir, "tmp")
	if err := os.WriteFile(tmp, []byte("third"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, time.Now(), read.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if same() {
		t.Error("replaced object is reported unchanged")
	}

	// a directory object is the same as long as it is the same directory
	objDir := filepath.Join(dir, "dir")
	if err := os.Mkdir(objDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, read, err = hashObjectPath(objDir+"/", types.ChecksumAlgorithmCrc32)
	if err != nil {
		t.Fatalf("hash directory object: %v", err)
	}
	if err := os.WriteFile(filepath.Join(objDir, "child"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(objDir)
	if err != nil {
		t.Fatal(err)
	}
	if !sameObjectData(read, fi) {
		t.Error("directory object with a new child is reported changed")
	}
}
