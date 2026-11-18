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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
)

// failProbe makes the O_TMPFILE probe fail with err, counting the probes
func failProbe(t *testing.T, err error) *int {
	t.Helper()
	probes := 0
	t.Cleanup(func() { probeOTmpFile = origProbeOTmpFile })
	probeOTmpFile = func(xt meta.TmpFileTester, f *os.File, dir string) error {
		probes++
		if err != nil {
			return err
		}
		return origProbeOTmpFile(xt, f, dir)
	}
	return &probes
}

// TestOTmpFileProbe checks that a filesystem whose O_TMPFILE can't hold
// xattrs or be linked uses a named temporary file, that the result is
// remembered per bucket, that errors that are not about O_TMPFILE support are
// not hidden by the fallback, and that deleting the bucket forgets the result.
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
				if tc.err != nil && !tc.wantName {
					// not about O_TMPFILE support: reported, not hidden
					if err == nil {
						f.cleanup()
						t.Fatal("open tmp file succeeded, want the probe error")
					}
					if _, known := p.otmpProbe.Load(p.BucketPath(bucket)); known {
						t.Error("an error that is not about O_TMPFILE support was remembered")
					}
					return
				}
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
				if *probes != 1 {
					t.Errorf("probed %d times for 2 opens, want 1", *probes)
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
			p := newVersionedTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				ms, opts := mk(t)
				return ms, opts
			})
			bucket := "bucket"
			createTestBucket(t, p, bucket)
			skipWithoutOTmpfile(t, p.BucketPath(bucket))
			if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}
			failProbe(t, tc.err)

			// PutObject, twice: the second one replaces the versioned object
			for i, body := range []string{"first", "second"} {
				out, err := testPut(p, bucket, "object", []byte(body), nil, nil)
				if err != nil {
					t.Fatalf("put %d: %v", i, err)
				}
				got, etag := getTestObject(t, p, bucket, "object")
				if string(got) != body || etag != aws.ToString(&out.ETag) || etag == "" {
					t.Errorf("put %d: object is %q with etag %q, want %q with etag %q", i, got, etag, body, out.ETag)
				}
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
