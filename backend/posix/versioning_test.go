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
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
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

		err := os.Mkdir("bucket", 0o755)
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

		err := os.Mkdir("bucket", 0o755)
		assert.NoError(t, err)

		err = p.PutBucketVersioning(context.Background(), "bucket", types.BucketVersioningStatusEnabled)
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)) {
			t.Errorf("expected VersioningNotConfigured, got %v", err)
		}
	})
}
