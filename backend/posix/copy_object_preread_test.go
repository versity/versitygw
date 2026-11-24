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
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestCopyObjectPreRead checks that a preRead rejection of the source comes
// after the copy source preconditions and before any data is read or
// written, for a copy to another key and for a self copy that computes a
// new checksum, and that directory objects and a self copy that changes
// nothing, which is rejected first, skip it.
func TestCopyObjectPreRead(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	p.copyObjectThreshold = 4 << 20
	bucket, key, body := "testbucket", "obj", "hello world"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	for _, k := range []string{key, "dir/"} {
		b := body
		if k == "dir/" {
			b = ""
		}
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           aws.String(k),
			Body:          strings.NewReader(b),
			ContentLength: aws.Int64(int64(len(b))),
		})
		if err != nil {
			t.Fatalf("put object %q: %v", k, err)
		}
	}
	head, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("head object: %v", err)
	}

	errArchived := s3err.GetAPIError(s3err.ErrInvalidObjectState)
	tests := []struct {
		name        string
		src, dst    string
		ifMatch     *string
		algo        types.ChecksumAlgorithm
		directive   types.MetadataDirective
		want        error
		wantPreRead bool
	}{
		{name: "copy to another key", src: key, dst: "copy", want: errArchived, wantPreRead: true},
		{name: "self copy with a new checksum", src: key, dst: key, algo: types.ChecksumAlgorithmSha256, want: errArchived, wantPreRead: true},
		{name: "self copy of the metadata", src: key, dst: key, want: errArchived, wantPreRead: true},
		{name: "self copy that changes nothing", src: key, dst: key, directive: types.MetadataDirectiveCopy,
			want: s3err.GetAPIError(s3err.ErrInvalidCopyDest)},
		{name: "copy source if-match differs", src: key, dst: "copy", ifMatch: aws.String("other"),
			want: s3err.GetPreconditionFailedErr(s3err.ConditionCopySourceIfMatch)},
		{name: "directory object", src: "dir/", dst: "dir-copy/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			directive := tt.directive
			if directive == "" {
				directive = types.MetadataDirectiveReplace
			}
			var preReadFile *os.File
			_, err := p.CopyObjectWithPreReadFunc(ctx, s3response.CopyObjectInput{
				Bucket:              &bucket,
				Key:                 aws.String(tt.dst),
				CopySource:          aws.String(bucket + "/" + tt.src),
				CopySourceIfMatch:   tt.ifMatch,
				ExpectedBucketOwner: aws.String(""),
				MetadataDirective:   directive,
				ChecksumAlgorithm:   tt.algo,
			}, func(f *os.File) error {
				preReadFile = f
				// nothing of the source is read before
				if off, err := f.Seek(0, 1); err != nil || off != 0 {
					t.Errorf("source read before preRead: offset %v, %v", off, err)
				}
				return errArchived
			})
			if tt.want == nil && err != nil {
				t.Fatalf("copy object: %v", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
			if got := preReadFile != nil; got != tt.wantPreRead {
				t.Fatalf("expected preRead called %v, got %v", tt.wantPreRead, got)
			}
			if tt.dst == "copy" {
				if _, err := os.Stat(p.ObjectPath(bucket, "copy")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("expected no copy, got %v", err)
				}
			}
			if tt.dst == key {
				res, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled})
				if err != nil {
					t.Fatalf("head object: %v", err)
				}
				if aws.ToString(res.ETag) != aws.ToString(head.ETag) || res.ChecksumSHA256 != nil {
					t.Errorf("the rejected self copy changed the object: etag %v, sha256 %v",
						aws.ToString(res.ETag), aws.ToString(res.ChecksumSHA256))
				}
			}
		})
	}

	// a nil preRead copies the object
	_, err = p.CopyObjectWithPreReadFunc(ctx, s3response.CopyObjectInput{
		Bucket:              &bucket,
		Key:                 aws.String("copy"),
		CopySource:          aws.String(bucket + "/" + key),
		ExpectedBucketOwner: aws.String(""),
	}, nil)
	if err != nil {
		t.Fatalf("copy object with nil preRead: %v", err)
	}
}
