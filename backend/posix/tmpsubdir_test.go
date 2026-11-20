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
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
)

// subdirsPosix returns a backend using named temp files in subdirs subdirectories.
func subdirsPosix(t *testing.T, subdirs int) *Posix {
	t.Helper()
	return newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{
			NewDirPerm:     0755,
			ForceNoTmpFile: true,
			TmpSubdirs:     subdirs,
		}
	})
}

// regularFiles returns the regular files below dir, relative to dir.
func regularFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %v: %v", dir, err)
	}
	return files
}

// partStageRecorder records the path of the part temp file, which only
// exists while the body is being read, at the first read.
type partStageRecorder struct {
	r    io.Reader
	root string
	once sync.Once
	path string
}

func (pr *partStageRecorder) Read(p []byte) (int, error) {
	pr.once.Do(func() {
		_ = filepath.WalkDir(pr.root, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				pr.path = path
			}
			return nil
		})
	})
	return pr.r.Read(p)
}

// stageDir returns the directory the recorded temp file sits in.
func (pr *partStageRecorder) stageDir() string {
	return filepath.Dir(pr.path)
}

func TestTmpSubdirsValidation(t *testing.T) {
	for _, subdirs := range []int{-1, MaxTmpSubdirs + 1} {
		_, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{TmpSubdirs: subdirs})
		if err == nil {
			t.Errorf("TmpSubdirs %d: expected error", subdirs)
		}
	}
	for _, subdirs := range []int{0, 1, 16, MaxTmpSubdirs} {
		if _, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{TmpSubdirs: subdirs}); err != nil {
			t.Errorf("TmpSubdirs %d: %v", subdirs, err)
		}
	}
}

func TestTmpSubdir(t *testing.T) {
	tmpDir := filepath.Join("bucket", MetaTmpDir)

	for name, p := range map[string]*Posix{"zero": {}, "one": {tmpSubdirs: 1}} {
		if got := p.tmpSubdir(tmpDir); got != tmpDir {
			t.Fatalf("%s: tmpSubdir = %q, want %q", name, got, tmpDir)
		}
	}

	const subdirs = 4
	p := &Posix{tmpSubdirs: subdirs}
	// Each subdirectory is used equally often.
	counts := map[string]int{}
	for range 4 * subdirs {
		counts[p.tmpSubdir(tmpDir)]++
	}
	if len(counts) != subdirs {
		t.Fatalf("used %d subdirs, want %d: %v", len(counts), subdirs, counts)
	}
	for i := range subdirs {
		dir := filepath.Join(tmpDir, fmt.Sprint(i))
		if counts[dir] != 4 {
			t.Fatalf("temp subdirectory %q used %d times, want 4: %v", dir, counts[dir], counts)
		}
	}
}

func TestTmpSubdirPutListDelete(t *testing.T) {
	const subdirs = 4
	p := subdirsPosix(t, subdirs)
	bucket := "subdirbucket"
	createTestBucket(t, p, bucket)

	keys := []string{"a", "b", "dir/c", "dir/sub/d", "e"}
	for _, key := range keys {
		body := []byte("data for " + key)
		if _, err := testPut(p, bucket, key, body, nil, nil); err != nil {
			t.Fatalf("put %q: %v", key, err)
		}
		if got, _ := getTestObject(t, p, bucket, key); !bytes.Equal(got, body) {
			t.Fatalf("get %q = %q, want %q", key, got, body)
		}
	}

	// All subdirectories were used and none holds a leftover file.
	tmpRoot := filepath.Join(p.BucketPath(bucket), MetaTmpDir)
	if left := regularFiles(t, tmpRoot); len(left) != 0 {
		t.Fatalf("leftover temp files: %v", left)
	}
	ents, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatalf("read %v: %v", tmpRoot, err)
	}
	if len(ents) != subdirs {
		t.Fatalf("%v holds %d entries, want %d subdirs", tmpRoot, len(ents), subdirs)
	}

	// Temp subdirectories stay hidden from listings.
	out, err := p.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket:     &bucket,
		StartAfter: aws.String(""), // the frontend always sets these
		MaxKeys:    aws.Int32(1000),
	})
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}
	if len(out.Contents) != len(keys) {
		var got []string
		for _, obj := range out.Contents {
			got = append(got, aws.ToString(obj.Key))
		}
		t.Fatalf("listed %v, want %v", got, keys)
	}

	// A bucket holding only subdirectories is empty and can be deleted.
	for _, key := range keys {
		if _, err := p.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: &bucket, Key: aws.String(key),
		}); err != nil {
			t.Fatalf("delete %q: %v", key, err)
		}
	}
	if err := p.DeleteBucket(context.Background(), bucket); err != nil {
		t.Fatalf("delete bucket with subdirs: %v", err)
	}
	if _, err := os.Stat(p.BucketPath(bucket)); !os.IsNotExist(err) {
		t.Fatalf("bucket dir still present: %v", err)
	}
}

func TestTmpSubdirMultipart(t *testing.T) {
	p := subdirsPosix(t, 2)
	bucket, key := "mpbucket", "dir/mpobject"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}

	part := bytes.Repeat([]byte("x"), 1024)
	rec := &partStageRecorder{r: bytes.NewReader(part), root: p.BucketPath(bucket)}
	up, err := p.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &mp.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          rec,
		ContentLength: aws.Int64(int64(len(part))),
	})
	if err != nil {
		t.Fatalf("upload part: %v", err)
	}
	// The part itself was staged in a temp subdirectory of .sgwtmp.
	if base := filepath.Base(rec.stageDir()); base != "0" && base != "1" {
		t.Fatalf("part staged in %q, want a temp subdirectory", rec.stageDir())
	}

	// Temp subdirectories must not show up as extra uploads.
	list, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket:     &bucket,
		MaxUploads: aws.Int32(1000), // the frontend always sets it
	})
	if err != nil {
		t.Fatalf("list multipart uploads: %v", err)
	}
	if len(list.Uploads) != 1 || list.Uploads[0].UploadID != mp.UploadId {
		t.Fatalf("uploads = %+v, want only %q", list.Uploads, mp.UploadId)
	}

	_, _, err = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &mp.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: up.ETag, PartNumber: aws.Int32(1)}},
		},
	})
	if err != nil {
		t.Fatalf("complete multipart upload: %v", err)
	}
	if got, _ := getTestObject(t, p, bucket, key); !bytes.Equal(got, part) {
		t.Fatalf("completed object has %d bytes, want %d", len(got), len(part))
	}

	// No temp file was left behind.
	tmpRoot := filepath.Join(p.BucketPath(bucket), MetaTmpDir)
	for _, f := range regularFiles(t, tmpRoot) {
		if !strings.HasPrefix(f, "multipart"+string(filepath.Separator)) {
			t.Fatalf("leftover temp file: %v", f)
		}
	}
}

// TestMultipartPartStagingDefault checks that with temp subdirectories off,
// parts keep their key's multipart directory as on main.
func TestMultipartPartStagingDefault(t *testing.T) {
	p := subdirsPosix(t, 0)
	bucket, key := "mpdefault", "dir/mpobj"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}

	part := bytes.Repeat([]byte("x"), 1024)
	rec := &partStageRecorder{r: bytes.NewReader(part), root: p.BucketPath(bucket)}
	_, err = p.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &mp.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          rec,
		ContentLength: aws.Int64(int64(len(part))),
	})
	if err != nil {
		t.Fatalf("upload part: %v", err)
	}

	want := filepath.Join(p.BucketPath(bucket),
		MetaTmpMultipartDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
	if got := rec.stageDir(); got != want {
		t.Fatalf("part staged in %q, want the key's multipart directory %q", got, want)
	}
}

// TestTmpSubdirCrashLeftovers checks that temp files left by a crash stay
// hidden, do not block uploads and are removed with the bucket.
func TestTmpSubdirCrashLeftovers(t *testing.T) {
	p := subdirsPosix(t, 4)
	bucket := "crashbucket"
	createTestBucket(t, p, bucket)
	tmpRoot := filepath.Join(p.BucketPath(bucket), MetaTmpDir)

	// Leftovers as a killed gateway would leave them.
	for _, dir := range []string{"0", "2", "."} {
		if dir != "." {
			if err := os.MkdirAll(filepath.Join(tmpRoot, dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		name := fmt.Sprintf("%x.deadbeef", sha256.Sum256([]byte(dir)))
		if err := os.WriteFile(filepath.Join(tmpRoot, dir, name), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A gateway without temp subdirectories ignores them.
	def, err := New(p.rootdir, meta.XattrMeta{}, PosixOpts{
		NewDirPerm: 0755, ForceNoTmpFile: true,
	})
	if err != nil {
		t.Fatalf("new default posix: %v", err)
	}
	createTestBucket(t, def, "defbucket")
	if _, err := testPut(def, "defbucket", "plain", []byte("x"), nil, nil); err != nil {
		t.Fatalf("put with temp subdirectories disabled: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(p.BucketPath("defbucket"), MetaTmpDir))
	if err != nil {
		t.Fatalf("read default temp dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Fatalf("disabled temp subdirectories created %q", e.Name())
		}
	}
	out, err := def.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: &bucket, StartAfter: aws.String(""), MaxKeys: aws.Int32(1000),
	})
	if err != nil {
		t.Fatalf("list with temp subdirectories disabled: %v", err)
	}
	if len(out.Contents) != 0 {
		t.Fatalf("crash leftovers exposed in listing: %d keys", len(out.Contents))
	}

	// A gateway with temp subdirectories still works next to the leftovers.
	key := "after-crash"
	if _, err := testPut(p, bucket, key, []byte("ok"), nil, nil); err != nil {
		t.Fatalf("put next to leftovers: %v", err)
	}
	if got, _ := getTestObject(t, p, bucket, key); string(got) != "ok" {
		t.Fatalf("get after crash leftovers = %q", got)
	}
	out, err = p.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: &bucket, StartAfter: aws.String(""), MaxKeys: aws.Int32(1000),
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out.Contents) != 1 || aws.ToString(out.Contents[0].Key) != key {
		t.Fatalf("listing = %+v, want only %q", out.Contents, key)
	}

	// Deleting the bucket takes the leftovers with it.
	if _, err := p.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: &bucket, Key: aws.String(key),
	}); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	if err := p.DeleteBucket(context.Background(), bucket); err != nil {
		t.Fatalf("delete bucket with crash leftovers: %v", err)
	}
	if _, err := os.Stat(p.BucketPath(bucket)); !os.IsNotExist(err) {
		t.Fatalf("bucket dir still present: %v", err)
	}
}

// TestTmpSubdirMultipartCrashAbort checks that an upload survives a restart
// and can be aborted.
func TestTmpSubdirMultipartCrashAbort(t *testing.T) {
	p := subdirsPosix(t, 4)
	bucket, key := "mpcrash", "dir/mpobj"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}
	part := bytes.Repeat([]byte("y"), 512)
	if _, err := p.UploadPart(ctx, &s3.UploadPartInput{
		Bucket: &bucket, Key: &key, UploadId: &mp.UploadId,
		PartNumber: aws.Int32(1), Body: bytes.NewReader(part),
		ContentLength: aws.Int64(int64(len(part))),
	}); err != nil {
		t.Fatalf("upload part: %v", err)
	}

	// "Restart": a fresh backend instance over the same root.
	rp, err := New(p.rootdir, meta.XattrMeta{}, PosixOpts{
		NewDirPerm: 0755, ForceNoTmpFile: true, TmpSubdirs: 4,
	})
	if err != nil {
		t.Fatalf("new restarted posix: %v", err)
	}
	list, err := rp.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &bucket, MaxUploads: aws.Int32(1000),
	})
	if err != nil {
		t.Fatalf("list uploads after restart: %v", err)
	}
	if len(list.Uploads) != 1 || list.Uploads[0].UploadID != mp.UploadId {
		t.Fatalf("uploads = %+v, want only %q", list.Uploads, mp.UploadId)
	}
	if err := rp.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: &mp.UploadId,
	}); err != nil {
		t.Fatalf("abort after restart: %v", err)
	}
	list, err = rp.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &bucket, MaxUploads: aws.Int32(1000),
	})
	if err != nil {
		t.Fatalf("list after abort: %v", err)
	}
	if len(list.Uploads) != 0 {
		t.Fatalf("uploads after abort = %+v", list.Uploads)
	}

	// The next multipart upload works next to the empty subdirs.
	mp2, err := rp.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload after abort: %v", err)
	}
	if err := rp.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: &mp2.UploadId,
	}); err != nil {
		t.Fatalf("abort second upload: %v", err)
	}
}
