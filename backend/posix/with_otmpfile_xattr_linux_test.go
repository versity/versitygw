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

//go:build linux

package posix

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
	"golang.org/x/sys/unix"
)

// failProbe makes the O_TMPFILE probe fail with err, counting the probes,
// which uploads racing for an unprobed bucket run concurrently
func failProbe(t *testing.T, err error) *atomic.Int32 {
	t.Helper()
	probes := new(atomic.Int32)
	t.Cleanup(func() { probeOTmpFile = origProbeOTmpFile })
	probeOTmpFile = func(xt meta.TmpFileTester, f *os.File, dir string) error {
		probes.Add(1)
		if err != nil {
			return err
		}
		return origProbeOTmpFile(xt, f, dir)
	}
	return probes
}

// TestOTmpFileProbe checks that a filesystem whose O_TMPFILE can't hold
// xattrs or be linked uses a named temporary file, that the result is
// remembered per bucket, that errors that are not about O_TMPFILE support
// don't fail the upload or get remembered, and that deleting the bucket forgets the result.
func TestOTmpFileProbe(t *testing.T) {
	for _, mode := range []string{"xattr", "sidecar"} {
		for _, tc := range []struct {
			name     string
			err      error
			wantName bool
		}{
			{name: "supported"},
			{name: "ENODATA", err: syscall.ENODATA, wantName: true},
			{name: "EOPNOTSUPP", err: syscall.EOPNOTSUPP, wantName: true},
			{name: "EXDEV", err: syscall.EXDEV, wantName: true},
			{name: "ENOSPC", err: syscall.ENOSPC},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				p := newTestPosix(t, metaModes(t)[mode])
				bucket := "bucket"
				createTestBucket(t, p, bucket)
				skipWithoutOTmpfile(t, p.BucketPath(bucket))
				tmpDir := p.ObjectPath(bucket, MetaTmpDir)
				if err := os.MkdirAll(tmpDir, 0o755); err != nil {
					t.Fatal(err)
				}
				probes := failProbe(t, tc.err)

				open := func(obj string) (*tmpfile, error) {
					return p.openObjectTmpFile(bucket, obj, 5, auth.Account{}, false, odirectNotAllowed)
				}
				f, err := open("object")
				if err != nil {
					t.Fatalf("open tmp file: %v", err)
				}
				defer f.cleanup()
				if named := filepath.Dir(f.File().Name()) == tmpDir; named != tc.wantName {
					t.Errorf("temp file %v is named: %v, want %v", f.File().Name(), named, tc.wantName)
				}

				// A second upload to the bucket must not probe again, and
				// must use the named file if the first one did.
				f2, err := open("object2")
				if err != nil {
					t.Fatalf("open second tmp file: %v", err)
				}
				defer f2.cleanup()
				if named := filepath.Dir(f2.File().Name()) == tmpDir; named != tc.wantName {
					t.Errorf("second temp file %v is named: %v, want %v", f2.File().Name(), named, tc.wantName)
				}
				// An error that is not about O_TMPFILE support leaves the
				// result unknown: the upload keeps its O_TMPFILE and the
				// next upload probes again.
				wantProbes, wantKnown := int32(1), true
				if tc.err != nil && !tc.wantName {
					wantProbes, wantKnown = 2, false
				}
				if got := probes.Load(); got != wantProbes {
					t.Errorf("probed %d times for 2 opens, want %d", got, wantProbes)
				}
				if _, known := p.otmpProbe.Load(p.BucketPath(bucket)); known != wantKnown {
					t.Errorf("probe result remembered: %v, want %v", known, wantKnown)
				}
				if tc.err == nil {
					// the real probe leaves nothing behind
					entries, _ := os.ReadDir(tmpDir)
					if len(entries) != 0 {
						t.Errorf("probe left %d files in %v", len(entries), tmpDir)
					}
				}

				// Deleting the bucket forgets the result, so that a bucket
				// made again with that name is probed again.
				if err := p.DeleteBucket(context.Background(), bucket); err != nil {
					t.Fatalf("delete bucket: %v", err)
				}
				if _, known := p.otmpProbe.Load(p.BucketPath(bucket)); known {
					t.Error("the probe result survived DeleteBucket")
				}
			})
		}
	}
}

// TestOTmpFileProbeNoOTmpfile checks that a filesystem without O_TMPFILE is
// probed once: the failing open is remembered, without a warning, and the
// uploads go straight to the named file.
func TestOTmpFileProbeNoOTmpfile(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	tmpDir := p.ObjectPath(bucket, MetaTmpDir)
	opens := 0
	openat = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		opens++
		return -1, syscall.EOPNOTSUPP
	}
	t.Cleanup(func() { openat = unix.Openat })
	var logs strings.Builder
	orig := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(orig) })

	for _, obj := range []string{"object", "object2", "object3"} {
		f, err := p.openObjectTmpFile(bucket, obj, 5, auth.Account{}, false, odirectNotAllowed)
		if err != nil {
			t.Fatalf("open tmp file %v: %v", obj, err)
		}
		defer f.cleanup()
		if filepath.Dir(f.File().Name()) != tmpDir {
			t.Errorf("temp file %v is not a named file", f.File().Name())
		}
	}
	if opens != 1 {
		t.Errorf("tried to open an O_TMPFILE %d times for 3 uploads, want 1", opens)
	}
	if v, known := p.otmpProbe.Load(p.BucketPath(bucket)); !known || v.(bool) {
		t.Errorf("probe result is %v (remembered: %v), want false", v, known)
	}
	if logs.Len() != 0 {
		t.Errorf("expected no warning, got %q", logs.String())
	}
}

// TestOTmpFileProbeNoOTmpfileInherit checks that with InheritDefaultACL a
// failing O_TMPFILE open in the bucket's temp directory is not remembered:
// the upload opens its own file in the object's directory, which can be on
// another filesystem.
func TestOTmpFileProbeNoOTmpfileInherit(t *testing.T) {
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	if err := os.MkdirAll(filepath.Join(p.BucketPath(bucket), "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	skipWithoutOTmpfile(t, p.BucketPath(bucket))
	tmpDir := p.ObjectPath(bucket, MetaTmpDir)
	openat = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		if path == tmpDir {
			return -1, syscall.EOPNOTSUPP
		}
		return unix.Openat(dirfd, path, flags, mode)
	}
	t.Cleanup(func() { openat = unix.Openat })

	f, err := p.openObjectTmpFile(bucket, "sub/obj", 5, auth.Account{}, false, odirectNotAllowed)
	if err != nil {
		t.Fatalf("open tmp file: %v", err)
	}
	defer f.cleanup()
	if !strings.HasPrefix(f.File().Name(), procfddir) {
		t.Errorf("temp file %v is not an O_TMPFILE", f.File().Name())
	}
	if _, known := p.otmpProbe.Load(p.BucketPath(bucket)); known {
		t.Error("probe result remembered, want unknown")
	}
}

// TestOTmpFileProbeDir checks that with InheritDefaultACL the probe file is
// opened in the bucket's temp directory, not in the directory of the object,
// which can be on another filesystem.
func TestOTmpFileProbeDir(t *testing.T) {
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	skipWithoutOTmpfile(t, p.BucketPath(bucket))
	if err := os.MkdirAll(filepath.Join(p.BucketPath(bucket), "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmpDir := p.ObjectPath(bucket, MetaTmpDir)

	t.Cleanup(func() { probeOTmpFile = origProbeOTmpFile })
	var probeDir string
	probeOTmpFile = func(xt meta.TmpFileTester, f *os.File, dir string) error {
		// an O_TMPFILE reads as <dir>/#<inode> (deleted)
		link, err := os.Readlink(f.Name())
		if err != nil {
			return err
		}
		probeDir = filepath.Dir(link)
		return origProbeOTmpFile(xt, f, dir)
	}
	if err := putTestObject(t, p, bucket, "sub/obj", "x"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if probeDir != tmpDir {
		t.Errorf("probe file opened in %q, want %q", probeDir, tmpDir)
	}
}

// TestOTmpFileProbeErrorDoesNotFailPut checks that a probe that can't run
// doesn't fail an upload that succeeds without it: with
// InheritDefaultACL, a bucket root that can't be written and a writable
// sub directory, the probe can't create .sgwtmp. The result stays unknown.
// Run as a user other than root, which can write anywhere.
func TestOTmpFileProbeErrorDoesNotFailPut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to any directory")
	}
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	root := p.BucketPath(bucket)
	skipWithoutOTmpfile(t, root)
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(root, 0o755) })

	if err := putTestObject(t, p, bucket, "sub/obj", "x"); err != nil {
		t.Fatalf("put with a bucket root that can't be written: %v", err)
	}
	if _, known := p.otmpProbe.Load(root); known {
		t.Error("the probe result was remembered after a probe error")
	}
}

// TestOTmpFileProbeConcurrent checks that concurrent uploads to a bucket
// whose O_TMPFILE can't be used all get a named temporary file.
func TestOTmpFileProbeConcurrent(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	skipWithoutOTmpfile(t, p.BucketPath(bucket))
	tmpDir := p.ObjectPath(bucket, MetaTmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	failProbe(t, syscall.EOPNOTSUPP)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f, err := p.openObjectTmpFile(bucket, fmt.Sprintf("object%d", i), 5, auth.Account{}, false, odirectNotAllowed)
			if err != nil {
				t.Errorf("open tmp file %d: %v", i, err)
				return
			}
			defer f.cleanup()
			if filepath.Dir(f.File().Name()) != tmpDir {
				t.Errorf("temp file %v is not a named file", f.File().Name())
			}
		}(i)
	}
	wg.Wait()
}

// TestOTmpFileUnsupportedUploads checks that PutObject, a multipart upload
// and an overwrite of a versioned object succeed, with their etags, when the
// O_TMPFILE can't hold xattrs (xattr metadata) or can't be linked (sidecar
// metadata, which then fails with EXDEV).
func TestOTmpFileUnsupportedUploads(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		mode string
		err  error
	}{
		{"xattr", syscall.ENODATA},
		{"sidecar", syscall.EXDEV},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			mk := metaModes(t)[tc.mode]
			p := newVersionedTestPosix(t, mk)
			bucket := "bucket"
			createTestBucket(t, p, bucket)
			skipWithoutOTmpfile(t, p.BucketPath(bucket))
			if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}
			failProbe(t, tc.err)

			// PutObject, twice: the second one replaces the versioned object
			var first s3response.PutObjectOutput
			for i, body := range []string{"first", "second"} {
				out, err := testPut(p, bucket, "object", []byte(body), nil, nil)
				if err != nil {
					t.Fatalf("put %d: %v", i, err)
				}
				if i == 0 {
					first = out
				}
				got, etag := getTestObject(t, p, bucket, "object")
				if string(got) != body || etag != out.ETag || etag == "" {
					t.Errorf("put %d: object is %q with etag %q, want %q with etag %q", i, got, etag, body, out.ETag)
				}
			}

			// The previous version was copied to the versioning directory
			prev, err := p.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       aws.String("object"),
				VersionId: aws.String(first.VersionID),
			})
			if err != nil {
				t.Fatalf("get previous version: %v", err)
			}
			prevBody, err := io.ReadAll(prev.Body)
			prev.Body.Close()
			if err != nil {
				t.Fatalf("read previous version: %v", err)
			}
			if string(prevBody) != "first" || aws.ToString(prev.ETag) != first.ETag || first.ETag == "" {
				t.Errorf("previous version is %q with etag %q, want %q with etag %q", prevBody, aws.ToString(prev.ETag), "first", first.ETag)
			}

			// UploadPart followed by CompleteMultipartUpload
			key := "multipart"
			uploadID, parts := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    &key,
			})
			res, _, err := p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, key, uploadID, parts))
			if err != nil {
				t.Fatalf("complete multipart upload: %v", err)
			}
			got, etag := getTestObject(t, p, bucket, key)
			if len(got) == 0 || etag == "" || !strings.HasSuffix(strings.Trim(etag, `"`), "-2") ||
				etag != aws.ToString(res.ETag) {
				t.Errorf("multipart object has %d bytes with etag %q, want the etag %v of 2 parts", len(got), etag, aws.ToString(res.ETag))
			}
		})
	}
}
