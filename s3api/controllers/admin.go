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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3log"
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
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return sendResponse(ctx, errors.New("access denied: only admin users have access to this resource"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusForbidden,
				action: "admin:CreateUser",
			})
	}
	var usr auth.Account
	err := json.Unmarshal(ctx.Body(), &usr)
	if err != nil {
		return sendResponse(ctx, fmt.Errorf("failed to parse request body: %w", err), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusBadRequest,
				action: "admin:CreateUser",
			})
	}

	if usr.Role != auth.RoleAdmin && usr.Role != auth.RoleUser && usr.Role != auth.RoleUserPlus {
		return sendResponse(ctx, errors.New("invalid parameters: user role have to be one of the following: 'user', 'admin', 'userplus'"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusBadRequest,
				action: "admin:CreateUser",
			})
	}

	err = c.iam.CreateAccount(usr)
	if err != nil {
		status := fiber.StatusInternalServerError
		err = fmt.Errorf("failed to create user: %w", err)

		if strings.Contains(err.Error(), "user already exists") {
			status = fiber.StatusConflict
		}

		return sendResponse(ctx, err, nil,
			&metaOptions{
				status: status,
				logger: c.l,
				action: "admin:CreateUser",
			})
	}

	return sendResponse(ctx, nil, "The user has been created successfully", &metaOptions{
		status: fiber.StatusCreated,
		logger: c.l,
		action: "admin:CreateUser",
	})
}

func (c AdminController) UpdateUser(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return sendResponse(ctx, errors.New("access denied: only admin users have access to this resource"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusForbidden,
				action: "admin:UpdateUser",
			})
	}

	access := ctx.Query("access")
	if access == "" {
		return sendResponse(ctx, errors.New("missing user access parameter"), nil,
			&metaOptions{
				status: fiber.StatusBadRequest,
				logger: c.l,
				action: "admin:UpdateUser",
			})
	}

	var props auth.MutableProps
	if err := json.Unmarshal(ctx.Body(), &props); err != nil {
		return sendResponse(ctx, fmt.Errorf("invalid request body %w", err), nil,
			&metaOptions{
				status: fiber.StatusBadRequest,
				logger: c.l,
				action: "admin:UpdateUser",
			})
	}

	err := c.iam.UpdateUserAccount(access, props)
	if err != nil {
		status := fiber.StatusInternalServerError
		err = fmt.Errorf("failed to update user account: %w", err)

		if strings.Contains(err.Error(), "user not found") {
			status = fiber.StatusNotFound
		}

		return sendResponse(ctx, err, nil,
			&metaOptions{
				status: status,
				logger: c.l,
				action: "admin:UpdateUser",
			})
	}

	return sendResponse(ctx, nil, "the user has been updated successfully",
		&metaOptions{
			logger: c.l,
			action: "admin:UpdateUser",
		})
}

func (c AdminController) DeleteUser(ctx *fiber.Ctx) error {
	access := ctx.Query("access")
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return sendResponse(ctx, errors.New("access denied: only admin users have access to this resource"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusForbidden,
				action: "admin:DeleteUser",
			})
	}

	err := c.iam.DeleteUserAccount(access)
	if err != nil {
		return sendResponse(ctx, err, nil,
			&metaOptions{
				logger: c.l,
				action: "admin:DeleteUser",
			})
	}

	return sendResponse(ctx, nil, "The user has been deleted successfully",
		&metaOptions{
			logger: c.l,
			action: "admin:DeleteUser",
		})
}

func (c AdminController) ListUsers(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return sendResponse(ctx, errors.New("access denied: only admin users have access to this resource"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusForbidden,
				action: "admin:ListUsers",
			})
	}
	accs, err := c.iam.ListUserAccounts()
	return sendResponse(ctx, err, accs,
		&metaOptions{
			logger: c.l,
			action: "admin:ListUsers",
		})
}

func (c AdminController) ChangeBucketOwner(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return sendResponse(ctx, errors.New("access denied: only admin users have access to this resource"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusForbidden,
				action: "admin:ChangeBucketOwner",
			})
	}
	owner := ctx.Query("owner")
	bucket := ctx.Query("bucket")

	accs, err := auth.CheckIfAccountsExist([]string{owner}, c.iam)
	if err != nil {
		return sendResponse(ctx, err, nil,
			&metaOptions{
				logger: c.l,
				action: "admin:ChangeBucketOwner",
			})
	}
	if len(accs) > 0 {
		return sendResponse(ctx, errors.New("user specified as the new bucket owner does not exist"), nil,
			&metaOptions{
				logger: c.l,
				action: "admin:ChangeBucketOwner",
				status: fiber.StatusNotFound,
			})
	}

	acl := auth.ACL{
		Owner: owner,
		Grantees: []auth.Grantee{
			{
				Permission: types.PermissionFullControl,
				Access:     owner,
			},
		},
	}

	aclParsed, err := json.Marshal(acl)
	if err != nil {
		return sendResponse(ctx, fmt.Errorf("failed to marshal the bucket acl: %w", err), nil,
			&metaOptions{
				logger: c.l,
				action: "admin:ChangeBucketOwner",
			})
	}

	err = c.be.ChangeBucketOwner(ctx.Context(), bucket, aclParsed)
	return sendResponse(ctx, err, "Bucket owner has been updated successfully",
		&metaOptions{
			logger: c.l,
			action: "admin:ChangeBucketOwner",
		})
}

func (c AdminController) ListBuckets(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return sendResponse(ctx, errors.New("access denied: only admin users have access to this resource"), nil,
			&metaOptions{
				logger: c.l,
				status: fiber.StatusForbidden,
				action: "admin:ListBuckets",
			})
	}

	buckets, err := c.be.ListBucketsAndOwners(ctx.Context())
	return sendResponse(ctx, err, buckets,
		&metaOptions{
			logger: c.l,
			action: "admin:ListBuckets",
		})
}

type metaOptions struct {
	action string
	status int
	logger s3log.AuditLogger
}

func sendResponse(ctx *fiber.Ctx, err error, data any, m *metaOptions) error {
	status := m.status
	if err != nil {
		if status == 0 {
			status = fiber.StatusInternalServerError
		}
		if m.logger != nil {
			m.logger.Log(ctx, err, []byte(err.Error()), s3log.LogMeta{
				Action:     m.action,
				HttpStatus: status,
			})
		}

		return ctx.Status(status).SendString(err.Error())
	}

	if status == 0 {
		status = fiber.StatusOK
	}

	msg, ok := data.(string)
	if ok {
		if m.logger != nil {
			m.logger.Log(ctx, nil, []byte(msg), s3log.LogMeta{
				Action:     m.action,
				HttpStatus: status,
			})
		}

		return ctx.Status(status).SendString(msg)
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if m.logger != nil {
		m.logger.Log(ctx, nil, dataJSON, s3log.LogMeta{
			HttpStatus: status,
			Action:     m.action,
		})
	}

	ctx.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	return ctx.Status(status).Send(dataJSON)
}
