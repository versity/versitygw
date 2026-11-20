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
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestListSkipsTempAndImplicitDirectories(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "sample.jpg", "s", "", nil)
	put(t, d, "photos/2006/a.jpg", "a", "", nil)
	put(t, d, "folder/", "", "", nil)
	hide(t, fs, "bucket/.sgwtmp/secret")

	got, err := d.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket:    backend.GetPtrFromString("bucket"),
		Delimiter: backend.GetPtrFromString("/"),
		MaxKeys:   int32ptr(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(objectKeys(got.Contents), []string{"sample.jpg"}) {
		t.Fatalf("contents = %v", objectKeys(got.Contents))
	}
	if !slices.Equal(prefixKeys(got.CommonPrefixes), []string{"folder/", "photos/"}) {
		t.Fatalf("prefixes = %v", prefixKeys(got.CommonPrefixes))
	}

	flat, err := d.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket:  backend.GetPtrFromString("bucket"),
		MaxKeys: int32ptr(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(objectKeys(flat.Contents), []string{"folder/", "photos/2006/a.jpg", "sample.jpg"}) {
		t.Fatalf("flat = %v", objectKeys(flat.Contents))
	}
}

func TestListObjectsV2Pages(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "a", "a", "", nil)
	put(t, d, "b", "b", "", nil)
	put(t, d, "c", "c", "", nil)
	one := int32(1)
	first, err := d.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket:  backend.GetPtrFromString("bucket"),
		MaxKeys: &one,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.IsTruncated == nil || !*first.IsTruncated || awsString(first.NextContinuationToken) == "" {
		t.Fatalf("first truncated %v token %q", first.IsTruncated, awsString(first.NextContinuationToken))
	}
	if !slices.Equal(objectKeys(first.Contents), []string{"a"}) {
		t.Fatalf("first = %v", objectKeys(first.Contents))
	}
	second, err := d.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket:            backend.GetPtrFromString("bucket"),
		MaxKeys:           &one,
		ContinuationToken: first.NextContinuationToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(objectKeys(second.Contents), []string{"b"}) {
		t.Fatalf("second = %v", objectKeys(second.Contents))
	}
}

func TestListMissingBucket(t *testing.T) {
	d, _ := newTest(t)
	_, err := d.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket: backend.GetPtrFromString("missing"),
	})
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrNoSuchBucket, "missing")) {
		t.Fatalf("list = %v", err)
	}
}

func hide(t *testing.T, fs *Fake, p string) {
	t.Helper()
	if err := fs.Mkdir("bucket/.sgwtmp"); err != nil && !errors.Is(err, errExist) {
		t.Fatal(err)
	}
	obj, err := fs.Open(p, openWrite|openCreate)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Release(obj)
	if _, err := fs.Write(obj, []byte("secret"), 0); err != nil {
		t.Fatal(err)
	}
	if err := fs.SetXattr(obj, attrETag, []byte("\"secret\"")); err != nil {
		t.Fatal(err)
	}
}

func objectKeys(objs []s3response.Object) []string {
	out := make([]string, len(objs))
	for i, obj := range objs {
		out[i] = awsString(obj.Key)
	}
	return out
}

func prefixKeys(prefixes []types.CommonPrefix) []string {
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = awsString(p.Prefix)
	}
	slices.Sort(out)
	return out
}

func int32ptr(v int32) *int32 { return &v }

func TestListTakesStatFromLookupAndSkipsFullAttrDecode(t *testing.T) {
	d, fs := newTest(t)
	for i := 0; i < 20; i++ {
		put(t, d, fmt.Sprintf("obj-%02d", i), "x", "", nil)
	}
	statsBefore := fs.StatCalls()
	res, err := d.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: backend.GetPtrFromString("bucket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 20 {
		t.Fatalf("contents = %d", len(res.Contents))
	}
	// The fake has no combined lookup, so the fallback issues one
	// StatObj per entry; a listing must not add a second stat on the
	// opened child beyond that.
	if got := fs.StatCalls() - statsBefore; got > 20 {
		t.Fatalf("StatObj calls = %d, want at most 20", got)
	}
	// Each entry reads the packed blob once and nothing else: a
	// packed-format object answers from one GetXattr.
	if got := fs.XattrGets("meta.v1"); got != 20 {
		t.Fatalf("packed reads = %d, want 20", got)
	}
	for _, name := range []string{"etag", "content-type", "metadata"} {
		if got := fs.XattrGets(name); got != 0 {
			t.Fatalf("legacy %q probes = %d, want 0", name, got)
		}
	}
}

func TestListLegacyEntryProbesOnlyETag(t *testing.T) {
	d, fs := newTest(t)
	// Write one object, then strip its packed blob and set the
	// legacy etag xattr: the pre-packed on-disk format.
	put(t, d, "legacy", "x", "", nil)
	if err := fs.SetXattrRaw("bucket/legacy", "etag", []byte(`"abc"`)); err != nil {
		t.Fatal(err)
	}
	if err := fs.RemoveXattrRaw("bucket/legacy", "meta.v1"); err != nil {
		t.Fatal(err)
	}
	res, err := d.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: backend.GetPtrFromString("bucket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 || awsString(res.Contents[0].ETag) != `"abc"` {
		t.Fatalf("contents = %+v", res.Contents)
	}
	// The packed probe misses and only the legacy etag is read: one
	// probe instead of nine.
	if got := fs.XattrGets("etag"); got != 1 {
		t.Fatalf("legacy etag probes = %d, want 1", got)
	}
	for _, name := range []string{"content-type", "metadata", "content-encoding"} {
		if got := fs.XattrGets(name); got != 0 {
			t.Fatalf("legacy %q probes = %d, want 0", name, got)
		}
	}
}
