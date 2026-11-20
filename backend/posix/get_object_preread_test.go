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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestGetObjectPreReadOrder checks that a preRead rejection comes after the
// preconditions, the range and the part number, the order S3 uses for an
// archived (GLACIER) object: a 304, 412 or 416 wins over InvalidObjectState.
func TestGetObjectPreReadOrder(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	bucket, key, body := "testbucket", "obj", "hello world"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	_, err := p.PutObject(ctx, s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          strings.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
	head, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("head object: %v", err)
	}
	etag := strings.Trim(aws.ToString(head.ETag), `"`)
	lastModified := aws.ToTime(head.LastModified)
	before := lastModified.Add(-time.Hour)

	errArchived := s3err.GetAPIError(s3err.ErrInvalidObjectState)
	errNotModified := s3err.GetAPIError(s3err.ErrNotModified)
	errIfMatch := s3err.GetPreconditionFailedErr(s3err.ConditionIfMatch)
	errIfUnmodSince := s3err.GetPreconditionFailedErr(s3err.ConditionIfUnmodifiedSince)

	tests := []struct {
		name          string
		ifMatch       *string
		ifNoneMatch   *string
		ifModSince    *time.Time
		ifUnmodSince  *time.Time
		rangeHdr      string
		partNumber    *int32
		want          error
		wantPreReader bool
	}{
		{name: "no conditions", want: errArchived, wantPreReader: true},
		{name: "if-none-match matches", ifNoneMatch: &etag, want: errNotModified},
		{name: "if-none-match any", ifNoneMatch: aws.String("*"), want: errNotModified},
		{name: "if-none-match differs", ifNoneMatch: aws.String("other"), want: errArchived, wantPreReader: true},
		{name: "if-match matches", ifMatch: &etag, want: errArchived, wantPreReader: true},
		{name: "if-match differs", ifMatch: aws.String("other"), want: errIfMatch},
		{name: "if-modified-since last modified", ifModSince: &lastModified, want: errNotModified},
		{name: "if-modified-since earlier", ifModSince: &before, want: errArchived, wantPreReader: true},
		{name: "if-unmodified-since earlier", ifUnmodSince: &before, want: errIfUnmodSince},
		{name: "if-unmodified-since last modified", ifUnmodSince: &lastModified, want: errArchived, wantPreReader: true},
		{name: "if-match and if-modified-since fails", ifMatch: &etag, ifModSince: &lastModified, want: errNotModified},
		{name: "if-match and if-unmodified-since fails", ifMatch: &etag, ifUnmodSince: &before, want: errArchived, wantPreReader: true},
		{name: "if-none-match matches and if-unmodified-since fails", ifNoneMatch: &etag, ifUnmodSince: &before, want: errIfUnmodSince},
		{name: "valid range", rangeHdr: "bytes=0-1", want: errArchived, wantPreReader: true},
		{name: "unsatisfiable range", rangeHdr: "bytes=100-200", want: s3err.GetInvalidRangeErr("bytes=100-200", int64(len(body)))},
		{name: "unsatisfiable range and if-none-match matches", rangeHdr: "bytes=100-200", ifNoneMatch: &etag, want: errNotModified},
		{name: "part number 1", partNumber: aws.Int32(1), want: errArchived, wantPreReader: true},
		{name: "part number out of range", partNumber: aws.Int32(2), want: s3err.GetInvalidPartNumberRangeErr(1, 2)},
		{name: "part number out of range and if-none-match matches", partNumber: aws.Int32(2), ifNoneMatch: &etag, want: errNotModified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var preReadFile *os.File
			res, err := p.GetObjectWithPreReadFunc(ctx, &s3.GetObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				IfMatch:           tt.ifMatch,
				IfNoneMatch:       tt.ifNoneMatch,
				IfModifiedSince:   tt.ifModSince,
				IfUnmodifiedSince: tt.ifUnmodSince,
				Range:             &tt.rangeHdr,
				PartNumber:        tt.partNumber,
			}, func(f *os.File) error {
				preReadFile = f
				return errArchived
			})
			if res != nil && res.Body != nil {
				res.Body.Close()
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected error %v, got %v", tt.want, err)
			}
			if got := preReadFile != nil; got != tt.wantPreReader {
				t.Fatalf("expected preRead called %v, got %v", tt.wantPreReader, got)
			}
			if preReadFile != nil {
				// the object file is closed when preRead rejects the read
				if _, err := preReadFile.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Errorf("expected the object file closed, got stat error %v", err)
				}
			}
		})
	}

	// a nil preRead serves the object
	res, err := p.GetObjectWithPreReadFunc(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Range:  aws.String(""),
	}, nil)
	if err != nil {
		t.Fatalf("get object with nil preRead: %v", err)
	}
	res.Body.Close()
}

// TestGetObjectPreReadVersion checks that preRead gets the file of the
// requested version, because S3 decides per version whether an object is
// archived.
func TestGetObjectPreReadVersion(t *testing.T) {
	p := newVersionedTestPosix(t, metaModes(t)["xattr"])
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
	if err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}

	bodies := []string{"version-one", "version-two!"}
	versionIds := make([]string, len(bodies))
	for i, body := range bodies {
		res, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           &key,
			Body:          strings.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		})
		if err != nil {
			t.Fatalf("put object version %d: %v", i+1, err)
		}
		versionIds[i] = res.VersionID
	}

	tests := []struct {
		name      string
		versionId string
		want      string
	}{
		{name: "older version", versionId: versionIds[0], want: bodies[0]},
		{name: "latest version", versionId: versionIds[1], want: bodies[1]},
		{name: "no version", want: bodies[1]},
	}

	errStop := errors.New("stop")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			_, err := p.GetObjectWithPreReadFunc(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &key,
				VersionId: &tt.versionId,
				Range:     aws.String(""),
			}, func(f *os.File) error {
				// ReadAt leaves the offset alone for the response body
				b := make([]byte, 64)
				n, err := f.ReadAt(b, 0)
				if err != nil && n == 0 {
					return err
				}
				got = string(b[:n])
				return errStop
			})
			if !errors.Is(err, errStop) {
				t.Fatalf("expected the preRead error, got %v", err)
			}
			if got != tt.want {
				t.Errorf("expected preRead to get %q, got %q", tt.want, got)
			}
		})
	}
}

// TestGetObjectPreReadDirObject checks that a directory object, which has
// no data, is served without calling preRead.
func TestGetObjectPreReadDirObject(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	bucket, key := "testbucket", "dir/"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	_, err := p.PutObject(ctx, s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          strings.NewReader(""),
		ContentLength: aws.Int64(0),
	})
	if err != nil {
		t.Fatalf("put directory object: %v", err)
	}

	_, err = p.GetObjectWithPreReadFunc(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Range:  aws.String(""),
	}, func(*os.File) error {
		return s3err.GetAPIError(s3err.ErrInvalidObjectState)
	})
	if err != nil {
		t.Fatalf("get directory object: %v", err)
	}
}
