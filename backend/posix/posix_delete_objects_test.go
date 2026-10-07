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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// TestDeleteObjectsHonorsETagPrecondition checks that DeleteObjects applies
// the per-object ETag precondition the same way DeleteObject applies If-Match.
func TestDeleteObjectsHonorsETagPrecondition(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket, key := "bucket", "obj"
			createTestBucket(t, p, bucket)

			put, err := testPut(p, bucket, key, []byte("hello"), nil, nil)
			if err != nil {
				t.Fatalf("put object: %v", err)
			}

			deleteWithETag := func(etag string) (int, []types.Error) {
				t.Helper()
				res, err := p.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
					Bucket: &bucket,
					Delete: &types.Delete{
						Objects: []types.ObjectIdentifier{
							{Key: aws.String(key), ETag: aws.String(etag)},
						},
					},
				})
				if err != nil {
					t.Fatalf("delete objects: %v", err)
				}
				return len(res.Deleted), res.Error
			}

			deleted, errs := deleteWithETag("abc")
			if deleted != 0 || len(errs) != 1 || aws.ToString(errs[0].Code) != "PreconditionFailed" {
				t.Fatalf("bad ETag: want one PreconditionFailed error and no deletes, got deleted=%d errors=%v", deleted, errs)
			}
			if _, err := os.Stat(p.ObjectPath(bucket, key)); err != nil {
				t.Fatalf("object removed despite failed precondition: %v", err)
			}

			deleted, errs = deleteWithETag(`"` + strings.Trim(put.ETag, `"`) + `"`)
			if deleted != 1 || len(errs) != 0 {
				t.Fatalf("matching ETag: want one delete and no errors, got deleted=%d errors=%v", deleted, errs)
			}
			if _, err := os.Stat(p.ObjectPath(bucket, key)); !os.IsNotExist(err) {
				t.Fatalf("object still present after matching delete: %v", err)
			}
		})
	}
}
