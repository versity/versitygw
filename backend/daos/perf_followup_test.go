// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing
// permissions and limitations under the License.

package daos

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// chunkedReader yields at most max bytes per Read, independent of the
// buffer the caller passes.
type chunkedReader struct {
	data []byte
	max  int
	off  int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.max {
		n = r.max
	}
	if r.off+n > len(r.data) {
		n = len(r.data) - r.off
	}
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}

// allButLastAreChunkSized reports whether every write except a trailing
// partial one used the full chunk size.
func allButLastAreChunkSized(lens []int, chunk int) bool {
	for i, n := range lens {
		if i == len(lens)-1 {
			return n <= chunk
		}
		if n != chunk {
			return false
		}
	}
	return true
}

func TestPutStreamsInChunkSizedWrites(t *testing.T) {
	d, fs := newTest(t)
	fs.SetDefaultChunk(512 * 1024)
	body := bytes.Repeat([]byte("a"), 1200*1024)
	sum := md5.Sum(body)
	wantEtag := "\"" + hex.EncodeToString(sum[:]) + "\""

	out, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
		Body:   &chunkedReader{data: body, max: 8 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ETag != wantEtag {
		t.Fatalf("etag = %q want %q", out.ETag, wantEtag)
	}
	lens := fs.WriteLens()
	if !allButLastAreChunkSized(lens, 512*1024) {
		t.Fatalf("write lengths %v, want chunk-sized except the last", lens)
	}
	if total := func() int64 {
		var n int64
		for _, l := range lens {
			n += int64(l)
		}
		return n
	}(); total != int64(len(body)) {
		t.Fatalf("wrote %d of %d", total, len(body))
	}
}

func TestGetReleasesHandleOnClose(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "obj", "hello", "", nil)
	before := fs.Handles()
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if fs.Handles() <= before {
		t.Fatalf("handle count %d did not grow while the body was open", fs.Handles())
	}
	if err := out.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if fs.Handles() != before {
		t.Fatalf("handle count %d after close, want %d", fs.Handles(), before)
	}
}

func TestPackedAttrsReadLegacyAndUpgradeOnWrite(t *testing.T) {
	d, fs := newTest(t)
	// Write attributes the legacy way: separate xattrs, no packed blob.
	obj, err := fs.Open("bucket", openRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir("bucket/legacy"); err != nil {
		t.Fatal(err)
	}
	lobj, err := fs.Open("bucket/legacy", openRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SetXattr(lobj, attrETag, []byte("\"legacy\"")); err != nil {
		t.Fatal(err)
	}
	if err := fs.SetXattr(lobj, attrContentType, []byte("text/x-legacy")); err != nil {
		t.Fatal(err)
	}
	etag, meta, headers, err := d.attrs(lobj)
	if err != nil {
		t.Fatal(err)
	}
	if etag != "\"legacy\"" || headers.ctype != "text/x-legacy" || meta != nil {
		t.Fatalf("legacy read: etag %q ctype %q meta %v", etag, headers.ctype, meta)
	}
	// The next storeAttrs upgrades the object to the packed blob.
	if err := d.storeAttrs(lobj, "\"new\"", s3response.PutObjectInput{}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.GetXattr(lobj, attrPacked); err != nil {
		t.Fatalf("packed blob missing after write: %v", err)
	}
	etag2, _, headers2, err := d.attrs(lobj)
	if err != nil {
		t.Fatal(err)
	}
	if etag2 != "\"new\"" || headers2.ctype == "" {
		t.Fatalf("packed read: etag %q ctype %q", etag2, headers2.ctype)
	}
	fs.Release(lobj)
	fs.Release(obj)
}

func TestListResolvesEntriesWithoutFullOpens(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "a", "a", "", nil)
	put(t, d, "dir/b", "b", "", nil)
	put(t, d, "folder/", "", "", nil)
	fs.ResetCounters()
	got, err := d.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket:  backend.GetPtrFromString("bucket"),
		MaxKeys: int32ptr(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contents) != 3 {
		t.Fatalf("contents = %v", objectKeys(got.Contents))
	}
	// No listed file entry is opened by its full path; directories are
	// entered by the walk itself, which is not what this measures.
	for _, opened := range fs.OpenTrace() {
		for _, obj := range got.Contents {
			key := awsString(obj.Key)
			if strings.HasSuffix(key, "/") {
				continue
			}
			if opened == objectPath("bucket", strings.TrimSuffix(key, "/")) {
				t.Fatalf("entry %q opened by full path", key)
			}
		}
	}
}

func TestGetParentIsFileStaysParentIsFile(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "file", "x", "", nil)
	_, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("file/child"),
	})
	if !isAPIErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)) {
		t.Fatalf("got %v", err)
	}
}

func TestGetBucketIsFileIsNoSuchBucket(t *testing.T) {
	fs := NewFake()
	d := NewWithFS(fs)
	// A regular file where a bucket directory would live.
	if err := fs.PlantFile("holder"); err != nil {
		t.Fatal(err)
	}
	_, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("holder"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if !isAPIErr(err, s3err.GetBucketErr(s3err.ErrNoSuchBucket, "holder")) {
		t.Fatalf("got %v", err)
	}
}

func TestPutIntermediateParentIsFileIsRejected(t *testing.T) {
	d, _ := newTest(t)
	put(t, d, "blocker", "x", "", nil)
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("blocker/child"),
		Body:   bytes.NewReader([]byte("y")),
	})
	if !isAPIErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)) {
		t.Fatalf("got %v", err)
	}
}

func TestBucketDefaultsAppliedOnlyWhenConfigured(t *testing.T) {
	fs := NewFake()
	d := NewWithFS(fs)
	if err := d.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: backend.GetPtrFromString("plain"),
	}, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if calls := fs.OclassCalls(); len(calls) != 0 {
		t.Fatalf("default config issued oclass calls %v", calls)
	}
	if calls := fs.ChunkSizeCalls(); len(calls) != 0 {
		t.Fatalf("default config issued chunk-size calls %v", calls)
	}

	d.SetBucketDefaults("RP_2G1", 1024*1024)
	if err := d.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: backend.GetPtrFromString("tuned"),
	}, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if calls := fs.OclassCalls(); len(calls) != 1 || calls[0] != "RP_2G1" {
		t.Fatalf("oclass calls %v", calls)
	}
	if calls := fs.ChunkSizeCalls(); len(calls) != 1 || calls[0] != 1024*1024 {
		t.Fatalf("chunk-size calls %v", calls)
	}
}

// isAPIErr reports whether err is the given s3 API error.
func isAPIErr(err error, apiErr error) bool {
	return errors.Is(err, apiErr)
}
