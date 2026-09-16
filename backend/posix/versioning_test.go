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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// newUnversionedGateway creates a Posix backend over a temporary root
// directory with no versioning directory configured, i.e. gateway-level
// versioning disabled, matching the default gateway configuration.
func newUnversionedGateway(t *testing.T) *Posix {
	t.Helper()

	p, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{
		ValidateBucketNames: true,
	})
	if err != nil {
		t.Fatalf("init posix backend: %v", err)
	}
	return p
}

// TestVersioningUnconfigured covers the bucket versioning behavior when the
// gateway has no versioning directory configured: bucket validation still
// applies first, GetBucketVersioning returns an empty configuration, and
// PutBucketVersioning is rejected.
func TestVersioningUnconfigured(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	t.Run("get bucket versioning invalid bucket name", func(t *testing.T) {
		p := newUnversionedGateway(t)

		_, err := p.GetBucketVersioning(context.Background(), "bad/bucket")
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)) {
			t.Errorf("expected InvalidBucketName, got %v", err)
		}
	})

	t.Run("get bucket versioning no such bucket", func(t *testing.T) {
		p := newUnversionedGateway(t)

		_, err := p.GetBucketVersioning(context.Background(), "does-not-exist")
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)) {
			t.Errorf("expected NoSuchBucket, got %v", err)
		}
	})

	t.Run("get bucket versioning returns empty config", func(t *testing.T) {
		p := newUnversionedGateway(t)

		err := os.Mkdir(p.BucketPath("bucket"), 0o755)
		assert.NoError(t, err)

		res, err := p.GetBucketVersioning(context.Background(), "bucket")
		assert.NoError(t, err)
		assert.Nil(t, res.Status)
	})

	t.Run("put bucket versioning invalid bucket name", func(t *testing.T) {
		p := newUnversionedGateway(t)

		err := p.PutBucketVersioning(context.Background(), "bad/bucket", types.BucketVersioningStatusEnabled)
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)) {
			t.Errorf("expected InvalidBucketName, got %v", err)
		}
	})

	t.Run("put bucket versioning not configured", func(t *testing.T) {
		p := newUnversionedGateway(t)

		err := os.Mkdir(p.BucketPath("bucket"), 0o755)
		assert.NoError(t, err)

		err = p.PutBucketVersioning(context.Background(), "bucket", types.BucketVersioningStatusEnabled)
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)) {
			t.Errorf("expected VersioningNotConfigured, got %v", err)
		}
	})
}

func TestVersioningDeleteMarkerStaleSidecarClearedOnSameKeyReupload(t *testing.T) {
	root := t.TempDir()
	vdir := filepath.Join(t.TempDir(), "versions")
	sidecarDir := filepath.Join(t.TempDir(), "sidecar")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatalf("mkdir versioning dir: %v", err)
	}
	if err := os.MkdirAll(sidecarDir, 0o755); err != nil {
		t.Fatalf("mkdir sidecar: %v", err)
	}

	sc, err := meta.NewSideCar(sidecarDir)
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	p, err := New(root, sc, PosixOpts{
		ValidateBucketNames: true,
		VersioningDir:       vdir,
		SideCarDir:          sidecarDir,
	})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}

	ctx := context.Background()
	bucket, key := "bucket", "object"
	createTestBucket(t, p, bucket)
	if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}

	put := func(body string) {
		t.Helper()
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           &key,
			Body:          strings.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		})
		if err != nil {
			t.Fatalf("put object %q: %v", body, err)
		}
	}

	put("one")

	_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	assert.NoError(t, err)

	put("two")

	_, err = p.meta.RetrieveAttribute(nil, bucket, key, deleteMarkerKey)
	assert.ErrorIs(t, err, meta.ErrNoSuchKey)

	out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("get object after reupload: %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read object body: %v", err)
	}
	assert.Equal(t, "two", string(body))
}
