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
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
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
	"golang.org/x/sys/unix"
)

// fdStageRecorder records the directory of the O_TMPFILE part file, which
// shows up as a "/dir/#inode (deleted)" symlink in /proc/self/fd while the
// body is being read.
type fdStageRecorder struct {
	r    io.Reader
	root string
	once sync.Once
	dir  string
}

func (fr *fdStageRecorder) Read(p []byte) (int, error) {
	fr.once.Do(func() {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return
		}
		for _, e := range fds {
			link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
			if err != nil || !strings.HasSuffix(link, " (deleted)") {
				continue
			}
			link = strings.TrimSuffix(link, " (deleted)")
			if strings.HasPrefix(link, fr.root+string(filepath.Separator)) {
				fr.dir = filepath.Dir(link)
				break
			}
		}
	})
	return fr.r.Read(p)
}

func (fr *fdStageRecorder) stageDir() string { return fr.dir }

// TestTmpSubdirMultipartOTmp pins that with temp subdirectories on and
// O_TMPFILE available, a part keeps its key's multipart directory and the
// bucket .sgwtmp gains no temp subdirectories.
func TestTmpSubdirMultipartOTmp(t *testing.T) {
	if fd, err := unix.Open(t.TempDir(), unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600); err != nil {
		t.Skipf("O_TMPFILE unavailable: %v", err)
	} else {
		unix.Close(fd)
	}

	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{NewDirPerm: 0o755, TmpSubdirs: 2}
	})
	bucket, key := "mpotmp", "dir/mpobj"
	createTestBucket(t, p, bucket)
	ctx := context.Background()

	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}

	part := bytes.Repeat([]byte("x"), 1024)
	absRoot, err := filepath.Abs(p.BucketPath(bucket))
	if err != nil {
		t.Fatal(err)
	}
	rec := &fdStageRecorder{r: bytes.NewReader(part), root: absRoot}
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

	// The unnamed part file sits in the key's multipart directory, not in
	// the bucket's .sgwtmp.
	want := filepath.Join(absRoot, MetaTmpMultipartDir,
		fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
	if got := rec.stageDir(); got != want {
		t.Fatalf("part staged in %q, want %q", got, want)
	}

	entries, err := os.ReadDir(filepath.Join(p.BucketPath(bucket), MetaTmpDir))
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != filepath.Base(MetaTmpMultipartDir) {
			t.Fatalf("temp dir gained %q with O_TMPFILE available", e.Name())
		}
	}

	if _, _, err := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &mp.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: up.ETag, PartNumber: aws.Int32(1)}},
		},
	}); err != nil {
		t.Fatalf("complete multipart upload: %v", err)
	}
	if got, _ := getTestObject(t, p, bucket, key); !bytes.Equal(got, part) {
		t.Fatalf("completed object has %d bytes, want %d", len(got), len(part))
	}
}
