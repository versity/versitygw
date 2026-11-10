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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

// TestCopyObjectSelfChecksumAlgorithm checks that a metadata-only copy of an
// object onto itself with a new checksum algorithm stores and returns the
// FULL_OBJECT checksum of the object's content in that algorithm.
func TestCopyObjectSelfChecksumAlgorithm(t *testing.T) {
	body := []byte("hello checksum world\n")
	shaSum := sha256.Sum256(body)
	crcSum := binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(body))

	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			p := newTestPosix(t, mkMeta)
			p.copyObjectThreshold = 1 << 20
			bucket, key := "bucket", "object"
			createTestBucket(t, p, bucket)
			if _, err := testPut(p, bucket, key, body, nil, nil); err != nil {
				t.Fatalf("put object: %v", err)
			}

			for _, tc := range []struct {
				algo types.ChecksumAlgorithm
				want string
				got  func(*s3response.CopyObjectResult) *string
				head func(*s3.HeadObjectOutput) *string
			}{
				{
					algo: types.ChecksumAlgorithmSha256,
					want: base64.StdEncoding.EncodeToString(shaSum[:]),
					got:  func(r *s3response.CopyObjectResult) *string { return r.ChecksumSHA256 },
					head: func(h *s3.HeadObjectOutput) *string { return h.ChecksumSHA256 },
				},
				{
					algo: types.ChecksumAlgorithmCrc32,
					want: base64.StdEncoding.EncodeToString(crcSum),
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
				if got := aws.ToString(tc.got(res.CopyObjectResult)); got != tc.want {
					t.Errorf("copy %v checksum = %q, want %q", tc.algo, got, tc.want)
				}

				head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket:       &bucket,
					Key:          &key,
					ChecksumMode: types.ChecksumModeEnabled,
				})
				if err != nil {
					t.Fatalf("head object: %v", err)
				}
				if got := aws.ToString(tc.head(head)); got != tc.want {
					t.Errorf("head %v checksum = %q, want %q", tc.algo, got, tc.want)
				}
				if head.ChecksumType != types.ChecksumTypeFullObject {
					t.Errorf("head checksum type = %q, want %q", head.ChecksumType, types.ChecksumTypeFullObject)
				}

				stored, err := p.retrieveChecksums(nil, bucket, key)
				if err != nil {
					t.Fatalf("retrieve checksums: %v", err)
				}
				if stored.Algorithm != tc.algo || stored.Type != types.ChecksumTypeFullObject {
					t.Errorf("stored checksum is %v %v, want %v %v",
						stored.Algorithm, stored.Type, tc.algo, types.ChecksumTypeFullObject)
				}
			}
		})
	}
}
