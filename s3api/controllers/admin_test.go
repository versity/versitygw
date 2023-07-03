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

package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
)

func TestAdminController_CreateUser(t *testing.T) {
	type args struct {
		req *http.Request
	}

	adminController := AdminController{
		IAMService: &IAMServiceMock{
			CreateAccountFunc: func(access string, account auth.Account) error {
				return nil
			},
		},
	}

	app := fiber.New()

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "admin")
		return ctx.Next()
	})

	app.Post("/create-user", adminController.CreateUser)

	appErr := fiber.New()

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "user")
		return ctx.Next()
	})

	appErr.Post("/create-user", adminController.CreateUser)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Admin-create-user-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/create-user?access=test&secret=test&role=user", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Admin-create-user-invalid-user-role",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/create-user?access=test&secret=test&role=invalid", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Admin-create-user-invalid-requester-role",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/create-user?access=test&secret=test&role=admin", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("AdminController.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("AdminController.CreateUser() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestAdminController_DeleteUser(t *testing.T) {
	type args struct {
		req *http.Request
	}

	adminController := AdminController{
		IAMService: &IAMServiceMock{
			DeleteUserAccountFunc: func(access string) error {
				return nil
			},
		},
	}

	app := fiber.New()

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "admin")
		return ctx.Next()
	})

	app.Delete("/delete-user", adminController.DeleteUser)

	appErr := fiber.New()

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "user")
		return ctx.Next()
	})

	appErr.Delete("/delete-user", adminController.DeleteUser)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Admin-delete-user-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/delete-user?access=test", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Admin-delete-user-invalid-requester-role",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/delete-user?access=test", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("AdminController.DeleteUser() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("AdminController.DeleteUser() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}
