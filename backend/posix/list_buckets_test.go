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
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func createOwnedBucket(t *testing.T, p *Posix, bucket, owner string) {
	t.Helper()
	acl := []byte(`{"Owner":"` + owner + `","Grantees":[{"Permission":"FULL_CONTROL","Access":"` + owner + `","Type":"CanonicalUser"}]}`)
	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, acl)
	if err != nil {
		t.Fatalf("create bucket %s: %v", bucket, err)
	}
}

func bucketNames(res s3response.ListAllMyBucketsResult) []string {
	names := []string{}
	for _, b := range res.Buckets.Bucket {
		names = append(names, b.Name)
	}
	return names
}

// TestListBucketsVisibility checks that ListBuckets lists the buckets
// IsVisible accepts along with the owned ones, asks only about the buckets
// it would otherwise skip, and pages over the listed buckets alone: a
// continuation token only ever leads to another listed bucket.
func TestListBucketsVisibility(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			defer p.Shutdown()

			// Buckets owned by "user", buckets IsVisible shows it and
			// buckets it doesn't, interleaved and trailing.
			owners := map[string]string{
				"a-1": "user", "a-2": "other", "a-3": "other", "a-4": "user",
				"a-5": "other", "a-6": "other", "b-1": "user", "b-2": "other",
			}
			for bucket, owner := range owners {
				createOwnedBucket(t, p, bucket, owner)
			}
			shown := map[string]bool{"a-2": true, "b-2": true}

			var asked []string
			isVisible := func(_ context.Context, bucket string, acl []byte) (bool, error) {
				asked = append(asked, bucket)
				if len(acl) == 0 {
					t.Errorf("IsVisible(%s) got no ACL", bucket)
				}
				return shown[bucket], nil
			}

			tests := []struct {
				name      string
				input     s3response.ListBucketsInput
				want      []string
				wantToken string
				wantAsked []string
			}{
				{
					name:  "owned only without IsVisible",
					input: s3response.ListBucketsInput{Owner: "user", MaxBuckets: 100},
					want:  []string{"a-1", "a-4", "b-1"},
				},
				{
					name:      "owned and visible",
					input:     s3response.ListBucketsInput{Owner: "user", MaxBuckets: 100, IsVisible: isVisible},
					want:      []string{"a-1", "a-2", "a-4", "b-1", "b-2"},
					wantAsked: []string{"a-2", "a-3", "a-5", "a-6", "b-2"},
				},
				{
					name:      "prefix limits what is asked about",
					input:     s3response.ListBucketsInput{Owner: "user", MaxBuckets: 100, Prefix: "b", IsVisible: isVisible},
					want:      []string{"b-1", "b-2"},
					wantAsked: []string{"b-2"},
				},
				{
					name:      "first page",
					input:     s3response.ListBucketsInput{Owner: "user", MaxBuckets: 1, IsVisible: isVisible},
					want:      []string{"a-1"},
					wantToken: "a-1",
					wantAsked: []string{"a-2"},
				},
				{
					name:      "page after an owned bucket",
					input:     s3response.ListBucketsInput{Owner: "user", MaxBuckets: 1, ContinuationToken: "a-1", IsVisible: isVisible},
					want:      []string{"a-2"},
					wantToken: "a-2",
					wantAsked: []string{"a-2", "a-3"},
				},
				{
					name:      "page skips hidden buckets between listed ones",
					input:     s3response.ListBucketsInput{Owner: "user", MaxBuckets: 2, ContinuationToken: "a-2", IsVisible: isVisible},
					want:      []string{"a-4", "b-1"},
					wantToken: "b-1",
					wantAsked: []string{"a-3", "a-5", "a-6", "b-2"},
				},
				{
					name:      "last page ending on the last listed bucket has no token",
					input:     s3response.ListBucketsInput{Owner: "user", MaxBuckets: 2, Prefix: "a", ContinuationToken: "a-1", IsVisible: isVisible},
					want:      []string{"a-2", "a-4"},
					wantAsked: []string{"a-2", "a-3", "a-5", "a-6"},
				},
				{
					name:  "owned only page followed by hidden buckets has no token",
					input: s3response.ListBucketsInput{Owner: "user", MaxBuckets: 2, Prefix: "a"},
					want:  []string{"a-1", "a-4"},
				},
				{
					name:  "admin lists everything without asking",
					input: s3response.ListBucketsInput{Owner: "user", IsAdmin: true, MaxBuckets: 100, IsVisible: isVisible},
					want:  []string{"a-1", "a-2", "a-3", "a-4", "a-5", "a-6", "b-1", "b-2"},
				},
				{
					name:      "admin page has a token while buckets follow",
					input:     s3response.ListBucketsInput{Owner: "user", IsAdmin: true, MaxBuckets: 7},
					want:      []string{"a-1", "a-2", "a-3", "a-4", "a-5", "a-6", "b-1"},
					wantToken: "b-1",
				},
				{
					name:  "admin exactly full last page has no token",
					input: s3response.ListBucketsInput{Owner: "user", IsAdmin: true, MaxBuckets: 8},
					want:  []string{"a-1", "a-2", "a-3", "a-4", "a-5", "a-6", "b-1", "b-2"},
				},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					asked = nil
					res, err := p.ListBuckets(context.Background(), tt.input)
					if err != nil {
						t.Fatalf("ListBuckets: %v", err)
					}
					if got := bucketNames(res); !slices.Equal(got, tt.want) {
						t.Errorf("buckets = %v, want %v", got, tt.want)
					}
					if res.ContinuationToken != tt.wantToken {
						t.Errorf("continuation token = %q, want %q", res.ContinuationToken, tt.wantToken)
					}
					if !slices.Equal(asked, tt.wantAsked) {
						t.Errorf("IsVisible asked about %v, want %v", asked, tt.wantAsked)
					}
				})
			}

			t.Run("IsVisible error fails the listing", func(t *testing.T) {
				errVisible := errors.New("visibility failed")
				_, err := p.ListBuckets(context.Background(), s3response.ListBucketsInput{
					Owner:      "user",
					MaxBuckets: 100,
					IsVisible: func(context.Context, string, []byte) (bool, error) {
						return false, errVisible
					},
				})
				if !errors.Is(err, errVisible) {
					t.Errorf("ListBuckets error = %v, want %v", err, errVisible)
				}
			})
		})
	}
}

// TestListBucketsVisibilityBackendCalls checks that IsVisible can make
// backend calls with the context it is given while the listing holds its
// action slot, even when that is the only slot.
func TestListBucketsVisibilityBackendCalls(t *testing.T) {
	root := t.TempDir()
	storer, opts := metaModes(t)["xattr"](t)
	opts.Concurrency = 1
	p, err := New(root, storer, opts)
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	defer p.Shutdown()

	createOwnedBucket(t, p, "mine", "user")
	createOwnedBucket(t, p, "shared", "other")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := p.ListBuckets(ctx, s3response.ListBucketsInput{
		Owner:      "user",
		MaxBuckets: 100,
		IsVisible: func(ctx context.Context, bucket string, _ []byte) (bool, error) {
			_, err := p.GetBucketPolicy(ctx, bucket)
			if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
				return true, nil
			}
			return false, err
		},
	})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if got, want := bucketNames(res), []string{"mine", "shared"}; !slices.Equal(got, want) {
		t.Errorf("buckets = %v, want %v", got, want)
	}
}
