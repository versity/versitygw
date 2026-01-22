// Copyright 2023 Versity Software
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

package s3api

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
)

func TestS3ApiServer_Serve(t *testing.T) {
	tests := []struct {
		name    string
		sa      *S3ApiServer
		wantErr bool
	}{
		{
			name:    "Serve-invalid-address",
			wantErr: true,
			sa: &S3ApiServer{
				app:     fiber.New(),
				backend: backend.BackendUnsupported{},
				port:    "Invalid address",
				Router:  &S3ApiRouter{},
			},
		},
		{
			name:    "Serve-invalid-address-with-certificate",
			wantErr: true,
			sa: &S3ApiServer{
				app:         fiber.New(),
				backend:     backend.BackendUnsupported{},
				port:        "Invalid address",
				Router:      &S3ApiRouter{},
				CertStorage: &utils.CertStorage{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.sa.Serve(); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiServer.Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
