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
)

type AdminController struct {
	IAMService auth.IAMService
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

	err := c.IAMService.CreateAccount(access, user)
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

	err := c.IAMService.DeleteUserAccount(access)
	if err != nil {
		return err
	}

	return ctx.SendString("The user has been deleted successfully")
}
