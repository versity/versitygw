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
	"bytes"
	"context"
	"errors"
	"path"
	"syscall"
	"testing"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type moveErrFS struct {
	FS
	err error
}

func (m moveErrFS) Move(string, string) error { return m.err }

func TestPutFileOverDirectoryIsConflict(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "a/", "", "", nil)
	d.fs = moveErrFS{FS: fs, err: errFileOverDir}
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a"),
		Body:   bytes.NewReader([]byte("file")),
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)) {
		t.Fatalf("put = %v", err)
	}
	info, err := fs.Stat("bucket/a")
	if err != nil || !info.IsDir {
		t.Fatalf("destination = %+v err %v", info, err)
	}
}

func TestErrnoInvalidStaysDistinct(t *testing.T) {
	if !errors.Is(errnoSentinel(int(syscall.EINVAL)), errInvalid) {
		t.Fatal("EINVAL was not preserved")
	}
	if errors.Is(errnoSentinel(int(syscall.EINVAL)), errFileOverDir) {
		t.Fatal("EINVAL became a directory conflict")
	}
}

func TestDeleteBucketKeepsAnUpload(t *testing.T) {
	d, fs := newTest(t)
	created := startUpload(t, d, "obj")
	err := d.DeleteBucket(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("empty upload = %v", err)
	}
	if _, err := fs.Stat(path.Join(mpHashDir("bucket", "obj"), created.UploadId)); err != nil {
		t.Fatalf("upload = %v", err)
	}

	d, fs = newTest(t)
	created = startUpload(t, d, "obj")
	uploadPart(t, d, "obj", created.UploadId, 1, "part")
	err = d.DeleteBucket(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("parted upload = %v", err)
	}
	if _, err := fs.Stat(path.Join(mpHashDir("bucket", "obj"), created.UploadId, "1")); err != nil {
		t.Fatalf("part = %v", err)
	}

	d, fs = newTest(t)
	claim := path.Join(mpHashDir("bucket", "obj"), "claim.inprogress")
	if err := d.mkdirParents(claim); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir(claim); err != nil {
		t.Fatal(err)
	}
	err = d.DeleteBucket(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("claim = %v", err)
	}
	if _, err := fs.Stat(claim); err != nil {
		t.Fatalf("claim stat = %v", err)
	}
}

func TestDeleteBucketClearsEmptyTemporary(t *testing.T) {
	d, _ := newTest(t)
	hash := mpHashDir("bucket", "obj")
	if err := d.mkdirParents(path.Join(hash, "child")); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(context.Background(), "bucket"); err != nil {
		t.Fatalf("scaffolding = %v", err)
	}

	d, fs := newTest(t)
	putPath := "bucket/.sgwtmp/put-temp"
	if err := d.mkdirParents(putPath); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Open(putPath, openCreate|openWrite); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(context.Background(), "bucket"); err != nil {
		t.Fatalf("put temp = %v", err)
	}
}

func TestDeleteBucketRemoveDoesNotRecurse(t *testing.T) {
	d, fs := newTest(t)
	hash := mpHashDir("bucket", "obj")
	if err := d.mkdirParents(path.Join(hash, "child")); err != nil {
		t.Fatal(err)
	}
	fs.PlantBeforeRemove(path.Join(hash, "late"))
	err := d.DeleteBucket(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("planted = %v", err)
	}
	if _, err := fs.Stat(path.Join(hash, "late")); err != nil {
		t.Fatalf("late = %v", err)
	}
}
