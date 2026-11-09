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

//go:build !windows

package posix

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// TestDetectStaleEtagFIFO checks that a FIFO placed in a bucket, or a symlink
// to one, doesn't block a listing or a HeadObject that checks for stale
// etags.
func TestDetectStaleEtagFIFO(t *testing.T) {
	p := newStaleEtagPosix(t, true, false)
	bucket := "testbucket"
	createTestBucket(t, p, bucket)
	require.NoError(t, syscall.Mkfifo(p.ObjectPath(bucket, "fifo"), 0o644))
	require.NoError(t, os.Symlink("fifo", p.ObjectPath(bucket, "link")))
	_, err := testPut(p, bucket, "obj", []byte("v1"), nil, nil)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx := context.Background()
		_, _ = p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket, StartAfter: aws.String(""), MaxKeys: aws.Int32(1000),
		})
		for _, key := range []string{"fifo", "link"} {
			_, _ = p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: aws.String(key)})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}
