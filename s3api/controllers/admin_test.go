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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3response"
)

func TestAdminController_CreateUser(t *testing.T) {
	type args struct {
		req *http.Request
	}

	adminController := AdminController{
		iam: &IAMServiceMock{
			CreateAccountFunc: func(account auth.Account) error {
				return nil
			},
		},
	}

	app := fiber.New()

	app.Patch("/create-user", adminController.CreateUser)

	succUser := `
		<Account>
			<Access>access</Access>
			<Secret>secret</Secret>
			<Role>admin</Role>
			<UserID>0</UserID>
			<GroupID>0</GroupID>
		</Account>
	`
	invuser := `
		<Account>
			<Access>access</Access>
			<Secret>secret</Secret>
			<Role>invalid_role</Role>
			<UserID>0</UserID>
			<GroupID>0</GroupID>
		</Account>
	`

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Admin-create-user-malformed-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/create-user", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Admin-create-user-invalid-requester-role",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/create-user", strings.NewReader(invuser)),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Admin-create-user-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/create-user", strings.NewReader(succUser)),
			},
			wantErr:    false,
			statusCode: 201,
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

func TestAdminController_UpdateUser(t *testing.T) {
	type args struct {
		req *http.Request
	}

	adminController := AdminController{
		iam: &IAMServiceMock{
			UpdateUserAccountFunc: func(access string, props auth.MutableProps) error {
				return nil
			},
		},
	}

	app := fiber.New()

	app.Patch("/update-user", adminController.UpdateUser)

	adminControllerErr := AdminController{
		iam: &IAMServiceMock{
			UpdateUserAccountFunc: func(access string, props auth.MutableProps) error {
				return auth.ErrNoSuchUser
			},
		},
	}

	appNotFound := fiber.New()

	appNotFound.Patch("/update-user", adminControllerErr.UpdateUser)

	succUser := `
		<Account>
			<Secret>secret</Secret>
			<UserID>0</UserID>
			<GroupID>0</GroupID>
		</Account>
	`

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Admin-update-user-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/update-user?access=access", strings.NewReader(succUser)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Admin-update-user-missing-access",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/update-user", strings.NewReader(succUser)),
			},
			wantErr:    false,
			statusCode: 404,
		},
		{
			name: "Admin-update-user-invalid-request-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/update-user?access=access", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Admin-update-user-not-found",
			app:  appNotFound,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/update-user?access=access", strings.NewReader(succUser)),
			},
			wantErr:    false,
			statusCode: 404,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("AdminController.UpdateUser() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("AdminController.UpdateUser() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestAdminController_DeleteUser(t *testing.T) {
	type args struct {
		req *http.Request
	}

	adminController := AdminController{
		iam: &IAMServiceMock{
			DeleteUserAccountFunc: func(access string) error {
				return nil
			},
		},
	}

	app := fiber.New()

	app.Patch("/delete-user", adminController.DeleteUser)

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
		iam: &IAMServiceMock{
			ListUserAccountsFunc: func() ([]auth.Account, error) {
				return []auth.Account{}, nil
			},
		},
	}

	adminControllerErr := AdminController{
		iam: &IAMServiceMock{
			ListUserAccountsFunc: func() ([]auth.Account, error) {
				return []auth.Account{}, fmt.Errorf("server error")
			},
		},
	}

	appErr := fiber.New()
	appErr.Patch("/list-users", adminControllerErr.ListUsers)

	appSucc := fiber.New()
	appSucc.Patch("/list-users", adminController.ListUsers)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
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

func TestAdminController_ChangeBucketOwner(t *testing.T) {
	type args struct {
		req *http.Request
	}
	adminController := AdminController{
		be: &BackendMock{
			ChangeBucketOwnerFunc: func(contextMoqParam context.Context, bucket, owner string) error {
				return nil
			},
		},
		iam: &IAMServiceMock{
			GetUserAccountFunc: func(access string) (auth.Account, error) {
				return auth.Account{}, nil
			},
		},
	}

	adminControllerIamErr := AdminController{
		iam: &IAMServiceMock{
			GetUserAccountFunc: func(access string) (auth.Account, error) {
				return auth.Account{}, fmt.Errorf("unknown server error")
			},
		},
	}

	adminControllerIamAccDoesNotExist := AdminController{
		iam: &IAMServiceMock{
			GetUserAccountFunc: func(access string) (auth.Account, error) {
				return auth.Account{}, auth.ErrNoSuchUser
			},
		},
	}

	app := fiber.New()
	app.Patch("/change-bucket-owner", adminController.ChangeBucketOwner)

	appIamErr := fiber.New()
	appIamErr.Patch("/change-bucket-owner", adminControllerIamErr.ChangeBucketOwner)

	appIamNoSuchUser := fiber.New()
	appIamNoSuchUser.Patch("/change-bucket-owner", adminControllerIamAccDoesNotExist.ChangeBucketOwner)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Change-bucket-owner-check-account-server-error",
			app:  appIamErr,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/change-bucket-owner", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Change-bucket-owner-acc-does-not-exist",
			app:  appIamNoSuchUser,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/change-bucket-owner", nil),
			},
			wantErr:    false,
			statusCode: 404,
		},
		{
			name: "Change-bucket-owner-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/change-bucket-owner?bucket=bucket&owner=owner", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("AdminController.ChangeBucketOwner() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("AdminController.ChangeBucketOwner() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestAdminController_ListBuckets(t *testing.T) {
	type args struct {
		req *http.Request
	}
	adminController := AdminController{
		be: &BackendMock{
			ListBucketsAndOwnersFunc: func(contextMoqParam context.Context) ([]s3response.Bucket, error) {
				return []s3response.Bucket{}, nil
			},
		},
	}

	app := fiber.New()
	app.Patch("/list-buckets", adminController.ListBuckets)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "List-buckets-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPatch, "/list-buckets", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("AdminController.ListBuckets() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("AdminController.ListBuckets() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}
