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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func newTest(t *testing.T) (*Daos, *Fake) {
	t.Helper()
	fs := NewFake()
	if err := fs.Mkdir("bucket"); err != nil {
		t.Fatal(err)
	}
	return NewWithFS(fs), fs
}

func put(t *testing.T, d *Daos, key, body, ctype string, meta map[string]string) string {
	t.Helper()
	out, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:      backend.GetPtrFromString("bucket"),
		Key:         backend.GetPtrFromString(key),
		Body:        bytes.NewReader([]byte(body)),
		ContentType: backend.GetPtrFromString(ctype),
		Metadata:    meta,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.ETag
}

func TestPutGetHeadRoundTrip(t *testing.T) {
	d, _ := newTest(t)
	etag := put(t, d, "dir/obj", "hello", "text/plain", map[string]string{"color": "blue"})

	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("dir/obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" || awsString(got.ETag) != etag || awsString(got.ContentType) != "text/plain" {
		t.Fatalf("get = %q etag %q type %q", body, awsString(got.ETag), awsString(got.ContentType))
	}
	if got.Metadata["color"] != "blue" {
		t.Fatalf("metadata = %v", got.Metadata)
	}

	head, err := d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("dir/obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(head.ETag) != etag || head.ContentLength == nil || *head.ContentLength != 5 {
		t.Fatalf("head etag %q len %v", awsString(head.ETag), head.ContentLength)
	}
}

func TestReplaceDoesNotServeTheOldObject(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "obj", "one", "", nil)
	old, err := fs.Open("bucket/obj", openRead)
	if err != nil {
		t.Fatal(err)
	}
	put(t, d, "obj", "two", "", nil)

	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "two" {
		t.Fatalf("live object = %q", body)
	}
	buf := make([]byte, 3)
	if _, err := fs.Read(old, buf, 0); err != nil || string(buf) != "one" {
		t.Fatalf("old handle = %q err %v", buf, err)
	}
}

func TestMissingBucketAndKey(t *testing.T) {
	d, _ := newTest(t)
	_, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("missing"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrNoSuchBucket, "missing")) {
		t.Fatalf("bucket err = %v", err)
	}
	_, err = d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("missing"),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
		t.Fatalf("key err = %v", err)
	}
}

func TestDirectoryObject(t *testing.T) {
	d, _ := newTest(t)
	etag := put(t, d, "folder/", "", "", nil)
	if etag != emptyMD5 {
		t.Fatalf("etag = %q", etag)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("folder/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(got.ContentType) != backend.DirContentType {
		t.Fatalf("type = %q", awsString(got.ContentType))
	}
	_, err = d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("folder/"),
		Body:   bytes.NewReader([]byte("x")),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)) {
		t.Fatalf("data err = %v", err)
	}
}

func TestConditionalAndVersionRejects(t *testing.T) {
	d, _ := newTest(t)
	match := "\"abc\""
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:  backend.GetPtrFromString("bucket"),
		Key:     backend.GetPtrFromString("obj"),
		IfMatch: &match,
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotImplemented)) {
		t.Fatalf("put match = %v", err)
	}
	ver := "1"
	_, err = d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket:    backend.GetPtrFromString("bucket"),
		Key:       backend.GetPtrFromString("obj"),
		VersionId: &ver,
	})
	if err == nil || !errors.Is(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "1")) {
		t.Fatalf("version = %v", err)
	}
	algo := "AES256"
	_, err = d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:               backend.GetPtrFromString("bucket"),
		Key:                  backend.GetPtrFromString("obj"),
		SSECustomerAlgorithm: &algo,
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotImplemented)) {
		t.Fatalf("sse = %v", err)
	}
}

func TestDeleteAndDeleteObjects(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "a", "a", "", nil)
	put(t, d, "keep/", "", "", nil)
	put(t, d, "keep/child", "c", "", nil)
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a"),
	}); err != nil {
		t.Fatal(err)
	}
	ver := "1"
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket:    backend.GetPtrFromString("bucket"),
		Key:       backend.GetPtrFromString("a"),
		VersionId: &ver,
	}); !errors.Is(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "1")) {
		t.Fatalf("version = %v", err)
	}
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("missing"),
		Key:    backend.GetPtrFromString("a"),
	}); !errors.Is(err, s3err.GetBucketErr(s3err.ErrNoSuchBucket, "missing")) {
		t.Fatalf("bucket = %v", err)
	}
	_, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("keep/"),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrDirectoryNotEmpty)) {
		t.Fatalf("dir delete = %v", err)
	}
	res, err := d.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Delete: &types.Delete{Objects: []types.ObjectIdentifier{
			{Key: backend.GetPtrFromString("keep/child")},
			{Key: backend.GetPtrFromString("gone")},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) != 2 || len(res.Error) != 0 {
		t.Fatalf("result deleted %d errors %d", len(res.Deleted), len(res.Error))
	}
}

func TestReadGetters(t *testing.T) {
	d, _ := newTest(t)
	acl, err := d.GetBucketAcl(context.Background(), &s3.GetBucketAclInput{Bucket: backend.GetPtrFromString("bucket")})
	if err != nil || len(acl) != 0 {
		t.Fatalf("acl %q err %v", acl, err)
	}
	_, err = d.GetBucketPolicy(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
		t.Fatalf("policy = %v", err)
	}
	_, err = d.GetObjectLockConfiguration(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)) {
		t.Fatalf("lock = %v", err)
	}
	_, err = d.GetBucketAcl(context.Background(), &s3.GetBucketAclInput{Bucket: backend.GetPtrFromString("nope")})
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrNoSuchBucket, "nope")) {
		t.Fatalf("missing acl = %v", err)
	}
}

func TestFailedPutRemovesTemporaryName(t *testing.T) {
	d, fs := newTest(t)
	fs.FailNextMove()
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
		Body:   bytes.NewReader([]byte("hello")),
	})
	if err == nil {
		t.Fatal("put succeeded")
	}
	left, err := fs.ReadDir("bucket/.sgwtmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("temporary names left: %+v", left)
	}
	if _, err := fs.Stat("bucket/obj"); !errors.Is(err, errNotExist) {
		t.Fatalf("destination stat = %v", err)
	}
}

func TestObjectLockWriteNotImplemented(t *testing.T) {
	d, _ := newTest(t)
	mode := types.ObjectLockModeGovernance
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:         backend.GetPtrFromString("bucket"),
		Key:            backend.GetPtrFromString("obj"),
		ObjectLockMode: mode,
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotImplemented)) {
		t.Fatalf("lock write = %v", err)
	}
}

func TestXattrLimit(t *testing.T) {
	fs := NewFake()
	obj, err := fs.Open("wide", openWrite|openCreate)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SetXattr(obj, "n", bytes.Repeat([]byte("a"), maxXattrLen+1)); !errors.Is(err, errNameLong) {
		t.Fatalf("limit = %v", err)
	}
}

func TestPutHeadersRoundTrip(t *testing.T) {
	d, _ := newTest(t)
	enc := "gzip"
	lang := "en"
	disp := "attachment"
	cache := "max-age=60"
	exp := "Wed, 21 Oct 2015 07:28:00 GMT"
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:             backend.GetPtrFromString("bucket"),
		Key:                backend.GetPtrFromString("obj"),
		Body:               bytes.NewReader([]byte("hello")),
		ContentEncoding:    &enc,
		ContentLanguage:    &lang,
		ContentDisposition: &disp,
		CacheControl:       &cache,
		Expires:            &exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(got.ContentEncoding) != enc || awsString(got.ContentLanguage) != lang || awsString(got.ContentDisposition) != disp || awsString(got.CacheControl) != cache || awsString(got.ExpiresString) != exp {
		t.Fatalf("get headers enc %q lang %q disp %q cache %q exp %q", awsString(got.ContentEncoding), awsString(got.ContentLanguage), awsString(got.ContentDisposition), awsString(got.CacheControl), awsString(got.ExpiresString))
	}
	head, err := d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if awsString(head.ContentEncoding) != enc || awsString(head.ExpiresString) != exp {
		t.Fatalf("head enc %q exp %q", awsString(head.ContentEncoding), awsString(head.ExpiresString))
	}
}

func TestDirectoryPutKeepsMetadata(t *testing.T) {
	d, _ := newTest(t)
	cache := "max-age=60"
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:       backend.GetPtrFromString("bucket"),
		Key:          backend.GetPtrFromString("folder/"),
		Body:         bytes.NewReader(nil),
		Metadata:     map[string]string{"origin": "lab"},
		CacheControl: &cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	head, err := d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("folder/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if head.Metadata["origin"] != "lab" || awsString(head.ContentType) != backend.DirContentType || awsString(head.CacheControl) != "max-age=60" {
		t.Fatalf("head meta %v type %q", head.Metadata, awsString(head.ContentType))
	}
	_, err = d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("folder/"),
		Body:   bytes.NewReader(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	head, err = d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("folder/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if head.Metadata["origin"] != "" || awsString(head.CacheControl) != "" {
		t.Fatalf("cleared head meta %v cache %q", head.Metadata, awsString(head.CacheControl))
	}
}

func TestPutLongComponentIsKeyTooLong(t *testing.T) {
	d, _ := newTest(t)
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString(strings.Repeat("a", maxComponent+1)),
		Body:   bytes.NewReader([]byte("x")),
	})
	var long s3err.KeyTooLongError
	if !errors.As(err, &long) {
		t.Fatalf("put = %v", err)
	}
}

func TestDeleteSlashKeyDoesNotRemoveSibling(t *testing.T) {
	d, _ := newTest(t)
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a/b"),
		Body:   bytes.NewReader([]byte("keep")),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a/b/"),
	})
	if err != nil {
		t.Fatalf("delete = %v", err)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a/b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep" {
		t.Fatalf("body %q", body)
	}
}

func TestReservedTempKeyIsRejected(t *testing.T) {
	d, fs := newTest(t)
	for _, key := range []string{".sgwtmp/user-data", "foo/../.sgwtmp/x", ".sgwtmp", "dir/.sgwtmp/file"} {
		_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
			Bucket: backend.GetPtrFromString("bucket"),
			Key:    backend.GetPtrFromString(key),
			Body:   bytes.NewReader([]byte("hidden")),
		})
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidRequest)) {
			t.Fatalf("put %s = %v", key, err)
		}
	}
	put(t, d, ".sgwtmp/../ok", "visible", "", nil)
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("ok"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "visible" {
		t.Fatalf("body %q", body)
	}
	_, err = d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString(".sgwtmp/copied"),
		CopySource: backend.GetPtrFromString("bucket/ok"),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidRequest)) {
		t.Fatalf("copy = %v", err)
	}
	_, err = d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString(".sgwtmp/parted"),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidRequest)) {
		t.Fatalf("create = %v", err)
	}
	if _, err := fs.Stat("bucket/.sgwtmp/user-data"); !errors.Is(err, errNotExist) {
		t.Fatalf("reserved object stat = %v", err)
	}
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("ok"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(context.Background(), "bucket"); err != nil {
		t.Fatal(err)
	}
}

func TestDeletePrunesImplicitParents(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "a/b/c", "nested", "", nil)
	put(t, d, "a/keep", "stay", "", nil)
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a/b/c"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(context.Background(), "bucket"); !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("bucket with sibling = %v", err)
	}
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a/keep"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(context.Background(), "bucket"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteKeepsExplicitDirectory(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "keep/", "", "", nil)
	put(t, d, "keep/file", "child", "", nil)
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("keep/file"),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("keep/"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Body.Close()
	if err := d.DeleteBucket(context.Background(), "bucket"); !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("explicit directory bucket = %v", err)
	}
}
