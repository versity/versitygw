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
	"encoding/xml"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

type AdminController struct {
	iam   auth.IAMService
	be    backend.Backend
	l     s3log.AuditLogger
	s3api S3ApiController
}

func NewAdminController(iam auth.IAMService, be backend.Backend, l s3log.AuditLogger, s3api S3ApiController) AdminController {
	return AdminController{iam: iam, be: be, l: l, s3api: s3api}
}

func (c AdminController) CreateUser(ctx *fiber.Ctx) (*Response, error) {
	var usr auth.Account
	err := xml.Unmarshal(ctx.Body(), &usr)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if !usr.Role.IsValid() {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrAdminInvalidUserRole)
	}

	err = c.iam.CreateAccount(usr)
	if err != nil {
		if strings.Contains(err.Error(), "user already exists") {
			err = s3err.GetAPIError(s3err.ErrAdminUserExists)
		}

		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	return &Response{
		MetaOpts: &MetaOptions{
			Status: http.StatusCreated,
		},
	}, nil
}

func (c AdminController) UpdateUser(ctx *fiber.Ctx) (*Response, error) {
	access := ctx.Query("access")
	if access == "" {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrAdminMissingUserAcess)
	}

	var props auth.MutableProps
	if err := xml.Unmarshal(ctx.Body(), &props); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	err := props.Validate()
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrAdminInvalidUserRole)
	}

	err = c.iam.UpdateUserAccount(access, props)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			err = s3err.GetAPIError(s3err.ErrAdminUserNotFound)
		}

		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	return &Response{
		MetaOpts: &MetaOptions{},
	}, nil
}

func (c AdminController) DeleteUser(ctx *fiber.Ctx) (*Response, error) {
	access := ctx.Query("access")
	if access == "" {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrAdminMissingUserAcess)
	}

	err := c.iam.DeleteUserAccount(access)
	return &Response{
		MetaOpts: &MetaOptions{},
	}, err
}

func (c AdminController) ListUsers(ctx *fiber.Ctx) (*Response, error) {
	accs, err := c.iam.ListUserAccounts()
	return &Response{
		Data:     auth.ListUserAccountsResult{Accounts: accs},
		MetaOpts: &MetaOptions{},
	}, err
}

func (c AdminController) ChangeBucketOwner(ctx *fiber.Ctx) (*Response, error) {
	owner := ctx.Query("owner")
	bucket := ctx.Query("bucket")

	accs, err := auth.CheckIfAccountsExist([]string{owner}, c.iam)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}
	if len(accs) > 0 {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrAdminUserNotFound)
	}

	err = c.be.ChangeBucketOwner(ctx.Context(), bucket, owner)
	return &Response{
		MetaOpts: &MetaOptions{},
	}, err
}

func (c AdminController) ListBuckets(ctx *fiber.Ctx) (*Response, error) {
	buckets, err := c.be.ListBucketsAndOwners(ctx.Context())
	return &Response{
		Data: s3response.ListBucketsResult{
			Buckets: buckets,
		},
		MetaOpts: &MetaOptions{},
	}, err
}

func (c AdminController) CreateBucket(ctx *fiber.Ctx) (*Response, error) {
	owner := ctx.Get("x-vgw-owner")
	if owner == "" {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, s3err.GetAPIError(s3err.ErrAdminEmptyBucketOwnerHeader)
	}

	acc, err := c.iam.GetUserAccount(owner)
	if err != nil {
		if err == auth.ErrNoSuchUser {
			err = s3err.GetAPIError(s3err.ErrAdminUserNotFound)
		}

		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	// store the owner access key id in context
	ctx.Context().SetUserValue("bucket-owner", acc)

	_, err = c.s3api.CreateBucket(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{},
		}, err
	}

	return &Response{
		MetaOpts: &MetaOptions{
			Status: http.StatusCreated,
		},
	}, nil
}
