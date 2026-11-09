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

package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3err"
)

type backendWithBucketPolicy struct {
	backend.BackendUnsupported
	policy []byte
}

func (b backendWithBucketPolicy) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	return b.policy, nil
}

func (b backendWithBucketPolicy) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	return []byte(`{"Owner":"root"}`), nil
}

// TestAuthorizePublicBucketAccess_GetObjectAttributes checks that an
// anonymous GetObjectAttributes request needs the bucket policy to grant
// s3:GetObject along with s3:GetObjectAttributes, and s3:GetObjectVersion
// along with s3:GetObjectVersionAttributes for a request naming a version.
func TestAuthorizePublicBucketAccess_GetObjectAttributes(t *testing.T) {
	tests := []struct {
		name      string
		actions   string
		versionId string
		allowed   bool
	}{
		{name: "s3:GetObjectAttributes alone", actions: `"s3:GetObjectAttributes"`},
		{name: "s3:GetObjectAttributes and s3:GetObject", actions: `["s3:GetObjectAttributes","s3:GetObject"]`, allowed: true},
		{name: "s3:GetObjectVersionAttributes alone", actions: `"s3:GetObjectVersionAttributes"`, versionId: "version-id"},
		{name: "s3:GetObjectVersionAttributes and s3:GetObject", actions: `["s3:GetObjectVersionAttributes","s3:GetObject"]`, versionId: "version-id"},
		{name: "s3:GetObjectVersionAttributes and s3:GetObjectVersion", actions: `["s3:GetObjectVersionAttributes","s3:GetObjectVersion"]`, versionId: "version-id", allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := backendWithBucketPolicy{
				policy: fmt.Appendf(nil, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":%s,"Resource":"arn:aws:s3:::bucket/*"}]}`, tt.actions),
			}

			var authErr error
			app := fiber.New()
			app.Get("/:bucket/*", func(ctx fiber.Ctx) error {
				authErr = AuthorizePublicBucketAccess(be, metrics.ActionGetObjectAttributes, auth.GetObjectAttributesAction, auth.PermissionRead, "us-east-1", false)(ctx)
				return nil
			})

			target := "/bucket/object?attributes"
			if tt.versionId != "" {
				target += "&versionId=" + tt.versionId
			}
			_, err := app.Test(httptest.NewRequest(http.MethodGet, target, nil))
			assert.NoError(t, err)

			if tt.allowed {
				assert.NoError(t, authErr)
			} else {
				assert.Equal(t, s3err.GetAPIError(s3err.ErrAccessDenied), authErr)
			}
		})
	}
}
