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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
)

type AdminController struct {
	iam auth.IAMService
	be  backend.Backend
}

func NewAdminController(iam auth.IAMService, be backend.Backend) AdminController {
	return AdminController{iam: iam, be: be}
}

func (c AdminController) CreateUser(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return ctx.Status(fiber.StatusForbidden).SendString("access denied: only admin users have access to this resource")
	}
	var usr auth.Account
	err := json.Unmarshal(ctx.Body(), &usr)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).SendString(fmt.Errorf("failed to parse request body: %w", err).Error())
	}

	if usr.Role != auth.RoleAdmin && usr.Role != auth.RoleUser && usr.Role != auth.RoleUserPlus {
		return ctx.Status(fiber.StatusBadRequest).SendString("invalid parameters: user role have to be one of the following: 'user', 'admin', 'userplus'")
	}

	err = c.iam.CreateAccount(usr)
	if err != nil {
		status := fiber.StatusInternalServerError
		msg := fmt.Errorf("failed to create user: %w", err).Error()

		if strings.Contains(msg, "user already exists") {
			status = fiber.StatusConflict
		}

		return ctx.Status(status).SendString(msg)
	}

	return ctx.Status(fiber.StatusCreated).SendString("The user has been created successfully")
}

func (c AdminController) UpdateUser(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return ctx.Status(fiber.StatusForbidden).SendString("access denied: only admin users have access to this resource")
	}

	access := ctx.Query("access")
	if access == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("missing user access parameter")
	}

	var props auth.MutableProps
	if err := json.Unmarshal(ctx.Body(), &props); err != nil {
		return ctx.Status(fiber.StatusBadRequest).SendString(fmt.Errorf("invalid request body %w", err).Error())
	}

	err := c.iam.UpdateUserAccount(access, props)
	if err != nil {
		status := fiber.StatusInternalServerError
		msg := fmt.Errorf("failed to update user account: %w", err).Error()

		if strings.Contains(msg, "user not found") {
			status = fiber.StatusNotFound
		}

		return ctx.Status(status).SendString(msg)
	}

	return ctx.SendString("the user has been updated successfully")
}

func (c AdminController) DeleteUser(ctx *fiber.Ctx) error {
	access := ctx.Query("access")
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return ctx.Status(fiber.StatusForbidden).SendString("access denied: only admin users have access to this resource")
	}

	err := c.iam.DeleteUserAccount(access)
	if err != nil {
		return err
	}

	return ctx.SendString("The user has been deleted successfully")
}

func (c AdminController) ListUsers(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return ctx.Status(fiber.StatusForbidden).SendString("access denied: only admin users have access to this resource")
	}
	accs, err := c.iam.ListUserAccounts()
	if err != nil {
		return err
	}

	return ctx.JSON(accs)
}

func (c AdminController) ChangeBucketOwner(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return ctx.Status(fiber.StatusForbidden).SendString("access denied: only admin users have access to this resource")
	}
	owner := ctx.Query("owner")
	bucket := ctx.Query("bucket")

	accs, err := auth.CheckIfAccountsExist([]string{owner}, c.iam)
	if err != nil {
		return err
	}
	if len(accs) > 0 {
		return ctx.Status(fiber.StatusNotFound).SendString("user specified as the new bucket owner does not exist")
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
		return fmt.Errorf("failed to marshal the bucket acl: %w", err)
	}

	err = c.be.ChangeBucketOwner(ctx.Context(), bucket, aclParsed)
	if err != nil {
		return err
	}

	return ctx.SendString("Bucket owner has been updated successfully")
}

func (c AdminController) ListBuckets(ctx *fiber.Ctx) error {
	acct := ctx.Locals("account").(auth.Account)
	if acct.Role != "admin" {
		return ctx.Status(fiber.StatusForbidden).SendString("access denied: only admin users have access to this resource")
	}

	buckets, err := c.be.ListBucketsAndOwners(ctx.Context())
	if err != nil {
		return err
	}

	return ctx.JSON(buckets)
}
