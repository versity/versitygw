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
// anonymous GetObjectAttributes request is refused even when the bucket
// policy grants every action it could be authorized as, as AWS does.
func TestAuthorizePublicBucketAccess_GetObjectAttributes(t *testing.T) {
	be := backendWithBucketPolicy{
		policy: []byte(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObjectAttributes","s3:GetObject","s3:GetObjectVersionAttributes","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::bucket/*"}]}`),
	}

	tests := []struct {
		name   string
		target string
	}{
		{name: "without versionId", target: "/bucket/object?attributes"},
		{name: "with versionId", target: "/bucket/object?attributes&versionId=version-id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authErr error
			app := fiber.New()
			app.Get("/:bucket/*", func(ctx fiber.Ctx) error {
				authErr = AuthorizePublicBucketAccess(be, metrics.ActionGetObjectAttributes, auth.GetObjectAttributesAction, auth.PermissionRead, "us-east-1", false)(ctx)
				return nil
			})

			_, err := app.Test(httptest.NewRequest(http.MethodGet, tt.target, nil))
			assert.NoError(t, err)
			assert.Equal(t, s3err.GetAPIError(s3err.ErrAnonymousGetObjectAttributes), authErr)
		})
	}
}
