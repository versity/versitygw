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
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3response"
)

// TestListObjectsV2ContinuationTokenEcho checks that ListObjectsV2 echoes
// the request continuation token, and only that: start-after must not be
// reported back as a continuation token.
func TestListObjectsV2ContinuationTokenEcho(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	bucket := "testbucket"
	createTestBucket(t, p, bucket)

	ctx := context.Background()
	for _, key := range []string{"a", "b", "c"} {
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           aws.String(key),
			Body:          strings.NewReader("data"),
			ContentLength: aws.Int64(4),
		})
		if err != nil {
			t.Fatalf("put object %q: %v", key, err)
		}
	}

	tests := []struct {
		name       string
		cToken     string
		startAfter string
		wantToken  *string
		wantKeys   []string
	}{
		{"no token or start-after", "", "", nil, []string{"a", "b", "c"}},
		{"start-after only", "", "a", nil, []string{"b", "c"}},
		{"continuation token only", "a", "", aws.String("a"), []string{"b", "c"}},
		{"start-after past the continuation token", "a", "b", aws.String("a"), []string{"c"}},
		{"continuation token past start-after", "b", "a", aws.String("b"), []string{"c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:            &bucket,
				ContinuationToken: &tt.cToken,
				StartAfter:        &tt.startAfter,
				MaxKeys:           aws.Int32(1000),
			})
			if err != nil {
				t.Fatalf("list objects v2: %v", err)
			}

			if !reflect.DeepEqual(out.ContinuationToken, tt.wantToken) {
				t.Fatalf("continuation token = %q, want %q",
					aws.ToString(out.ContinuationToken), aws.ToString(tt.wantToken))
			}

			var keys []string
			for _, obj := range out.Contents {
				keys = append(keys, aws.ToString(obj.Key))
			}
			if strings.Join(keys, ",") != strings.Join(tt.wantKeys, ",") {
				t.Fatalf("keys = %v, want %v", keys, tt.wantKeys)
			}
		})
	}
}
