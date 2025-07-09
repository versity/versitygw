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
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

type AdminController struct {
	iam auth.IAMService
	be  backend.Backend
	l   s3log.AuditLogger
}

func NewAdminController(iam auth.IAMService, be backend.Backend, l s3log.AuditLogger) AdminController {
	return AdminController{iam: iam, be: be, l: l}
}

func (c AdminController) CreateUser(ctx *fiber.Ctx) error {
	var usr auth.Account
	err := xml.Unmarshal(ctx.Body(), &usr)
	if err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminCreateUser,
			})
	}

	if !usr.Role.IsValid() {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrAdminInvalidUserRole),
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminCreateUser,
			})
	}

	err = c.iam.CreateAccount(usr)
	if err != nil {
		if strings.Contains(err.Error(), "user already exists") {
			err = s3err.GetAPIError(s3err.ErrAdminUserExists)
		}

		return SendResponse(ctx, err,
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminCreateUser,
			})
	}

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger: c.l,
			Action: metrics.ActionAdminCreateUser,
			Status: http.StatusCreated,
		})
}

func (c AdminController) UpdateUser(ctx *fiber.Ctx) error {
	access := ctx.Query("access")
	if access == "" {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrAdminMissingUserAcess),
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminUpdateUser,
			})
	}

	var props auth.MutableProps
	if err := xml.Unmarshal(ctx.Body(), &props); err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminUpdateUser,
			})
	}

	err := props.Validate()
	if err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrAdminInvalidUserRole),
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminUpdateUser,
			})
	}

	err = c.iam.UpdateUserAccount(access, props)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			err = s3err.GetAPIError(s3err.ErrAdminUserNotFound)
		}

		return SendResponse(ctx, err,
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminUpdateUser,
			})
	}

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger: c.l,
			Action: metrics.ActionAdminUpdateUser,
		})
}

func (c AdminController) DeleteUser(ctx *fiber.Ctx) error {
	access := ctx.Query("access")

	err := c.iam.DeleteUserAccount(access)
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger: c.l,
			Action: metrics.ActionAdminDeleteUser,
		})
}

func (c AdminController) ListUsers(ctx *fiber.Ctx) error {
	accs, err := c.iam.ListUserAccounts()
	return SendXMLResponse(ctx,
		auth.ListUserAccountsResult{
			Accounts: accs,
		}, err,
		&MetaOpts{
			Logger: c.l,
			Action: metrics.ActionAdminListUsers,
		})
}

func (c AdminController) ChangeBucketOwner(ctx *fiber.Ctx) error {
	owner := ctx.Query("owner")
	bucket := ctx.Query("bucket")

	accs, err := auth.CheckIfAccountsExist([]string{owner}, c.iam)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminChangeBucketOwner,
			})
	}
	if len(accs) > 0 {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrAdminUserNotFound),
			&MetaOpts{
				Logger: c.l,
				Action: metrics.ActionAdminChangeBucketOwner,
			})
	}

	err = c.be.ChangeBucketOwner(ctx.Context(), bucket, owner)
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger: c.l,
			Action: metrics.ActionAdminChangeBucketOwner,
		})
}

func (c AdminController) ListBuckets(ctx *fiber.Ctx) error {
	buckets, err := c.be.ListBucketsAndOwners(ctx.Context())
	return SendXMLResponse(ctx,
		s3response.ListBucketsResult{
			Buckets: buckets,
		}, err, &MetaOpts{
			Logger: c.l,
			Action: metrics.ActionAdminListBuckets,
		})
}
