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
	"fmt"
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

	app.Patch("/create-user", adminController.CreateUser)

	appErr := fiber.New()

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "user")
		return ctx.Next()
	})

	appErr.Patch("/create-user", adminController.CreateUser)

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
				req: httptest.NewRequest(http.MethodPatch, "/create-user?access=test&secret=test&role=user", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Admin-create-user-invalid-user-role",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/create-user?access=test&secret=test&role=invalid", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Admin-create-user-invalid-requester-role",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/create-user?access=test&secret=test&role=admin", nil),
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

	app.Patch("/delete-user", adminController.DeleteUser)

	appErr := fiber.New()

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "user")
		return ctx.Next()
	})

	appErr.Patch("/delete-user", adminController.DeleteUser)

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
				req: httptest.NewRequest(http.MethodPatch, "/delete-user?access=test", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Admin-delete-user-invalid-requester-role",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/delete-user?access=test", nil),
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

func TestAdminController_ListUsers(t *testing.T) {
	type args struct {
		req *http.Request
	}

	adminController := AdminController{
		IAMService: &IAMServiceMock{
			ListUserAccountsFunc: func() ([]auth.Account, error) {
				return []auth.Account{}, nil
			},
		},
	}

	adminControllerErr := AdminController{
		IAMService: &IAMServiceMock{
			ListUserAccountsFunc: func() ([]auth.Account, error) {
				return []auth.Account{}, fmt.Errorf("server error")
			},
		},
	}

	appErr := fiber.New()

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "admin")
		return ctx.Next()
	})

	appErr.Patch("/list-users", adminControllerErr.ListUsers)

	appRoleErr := fiber.New()

	appRoleErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "user")
		return ctx.Next()
	})

	appRoleErr.Patch("/list-users", adminController.ListUsers)

	appSucc := fiber.New()

	appSucc.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("role", "admin")
		return ctx.Next()
	})

	appSucc.Patch("/list-users", adminController.ListUsers)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Admin-list-users-access-denied",
			app:  appRoleErr,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/list-users", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Admin-list-users-iam-error",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/list-users", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Admin-list-users-success",
			app:  appSucc,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/list-users", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("AdminController.ListUsers() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("AdminController.ListUsers() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}
