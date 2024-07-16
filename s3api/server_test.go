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
	"crypto/tls"
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/middlewares"
)

func TestNew(t *testing.T) {
	type args struct {
		app  *fiber.App
		be   backend.Backend
		port string
		root middlewares.RootUserConfig
	}

	app := fiber.New()
	be := backend.BackendUnsupported{}
	router := S3ApiRouter{}
	port := ":7070"

	tests := []struct {
		name            string
		args            args
		wantS3ApiServer *S3ApiServer
		wantErr         bool
	}{
		{
			name: "Create S3 api server",
			args: args{
				app:  app,
				be:   be,
				port: port,
				root: middlewares.RootUserConfig{},
			},
			wantS3ApiServer: &S3ApiServer{
				app:     app,
				port:    port,
				router:  &router,
				backend: be,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS3ApiServer, err := New(tt.args.app, tt.args.be, tt.args.root,
				tt.args.port, "us-east-1", &auth.IAMServiceInternal{}, nil, nil, nil, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotS3ApiServer, tt.wantS3ApiServer) {
				t.Errorf("New() = %v, want %v", gotS3ApiServer, tt.wantS3ApiServer)
			}
		})
	}
}

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
				router:  &S3ApiRouter{},
			},
		},
		{
			name:    "Serve-invalid-address-with-certificate",
			wantErr: true,
			sa: &S3ApiServer{
				app:     fiber.New(),
				backend: backend.BackendUnsupported{},
				port:    "Invalid address",
				router:  &S3ApiRouter{},
				cert:    &tls.Certificate{},
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
