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
	access, secret, role := ctx.Query("access"), ctx.Query("secret"), ctx.Query("role")
	requesterRole := ctx.Locals("role").(string)

	if requesterRole != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}
	if role != "user" && role != "admin" {
		return fmt.Errorf("invalid parameters: user role have to be one of the following: 'user', 'admin'")
	}

	user := auth.Account{Secret: secret, Role: role}

	err := c.iam.CreateAccount(access, user)
	if err != nil {
		return fmt.Errorf("failed to create a user: %w", err)
	}

	return ctx.SendString("The user has been created successfully")
}

func (c AdminController) DeleteUser(ctx *fiber.Ctx) error {
	access := ctx.Query("access")
	requesterRole := ctx.Locals("role").(string)
	if requesterRole != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}

	err := c.iam.DeleteUserAccount(access)
	if err != nil {
		return err
	}

	return ctx.SendString("The user has been deleted successfully")
}

func (c AdminController) ListUsers(ctx *fiber.Ctx) error {
	role := ctx.Locals("role").(string)
	if role != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}
	accs, err := c.iam.ListUserAccounts()
	if err != nil {
		return err
	}

	return ctx.JSON(accs)
}

func (c AdminController) ChangeBucketOwner(ctx *fiber.Ctx) error {
	role := ctx.Locals("role").(string)
	if role != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}
	owner := ctx.Query("owner")
	bucket := ctx.Query("bucket")

	accs, err := auth.CheckIfAccountsExist([]string{owner}, c.iam)
	if err != nil {
		return err
	}
	if len(accs) > 0 {
		return fmt.Errorf("user specified as the new bucket owner does not exist")
	}

	err = c.be.ChangeBucketOwner(ctx.Context(), bucket, owner)
	if err != nil {
		return err
	}

	return ctx.Status(201).SendString("Bucket owner has been updated successfully")
}

func (c AdminController) ListBuckets(ctx *fiber.Ctx) error {
	role := ctx.Locals("role").(string)
	if role != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}

	buckets, err := c.be.ListBucketsAndOwners(ctx.Context())
	if err != nil {
		return err
	}

	return ctx.JSON(buckets)
}
