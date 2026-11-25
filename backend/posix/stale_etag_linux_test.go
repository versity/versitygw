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
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestDetectStaleEtagLeased checks that an object under a write lease, as an
// NFS write delegation or an SMB oplock holds, whose non-blocking open fails,
// is still found stale by HeadObject and ListObjectsV2.
func TestDetectStaleEtagLeased(t *testing.T) {
	p := newStaleEtagPosix(t, true, false)
	bucket, key := "testbucket", "obj"
	createTestBucket(t, p, bucket)
	put, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
	require.NoError(t, err)
	path := p.ObjectPath(bucket, key)
	rewrite(t, path, "v2-longer", time.Now().Add(time.Minute))

	lf, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer lf.Close()
	if _, err := unix.FcntlInt(lf.Fd(), unix.F_SETLEASE, unix.F_WRLCK); err != nil {
		t.Skipf("set lease: %v", err)
	}

	h := headEtag(t, p, bucket, key)
	assert.NotEqual(t, put.ETag, aws.ToString(h.ETag))
	assert.True(t, isStaleEtag(aws.ToString(h.ETag)), "etag %v", aws.ToString(h.ETag))

	list, err := p.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: &bucket, StartAfter: aws.String(""), MaxKeys: aws.Int32(1000),
	})
	require.NoError(t, err)
	require.Len(t, list.Contents, 1)
	assert.NotEqual(t, put.ETag, aws.ToString(list.Contents[0].ETag))
	assert.True(t, isStaleEtag(aws.ToString(list.Contents[0].ETag)), "etag %v", aws.ToString(list.Contents[0].ETag))
}
