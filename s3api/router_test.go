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
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
)

func TestS3ApiRouter_Init(t *testing.T) {
	type args struct {
		app *fiber.App
		be  backend.Backend
		iam auth.IAMService
	}
	tests := []struct {
		name string
		sa   *S3ApiRouter
		args args
	}{
		{
			name: "Initialize S3 api router",
			sa:   &S3ApiRouter{},
			args: args{
				app: fiber.New(),
				be:  backend.BackendUnsupported{},
				iam: &auth.IAMServiceInternal{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.sa.Init(tt.args.app, tt.args.be, tt.args.iam, nil, nil, nil, nil, false, false)
		})
	}
}
