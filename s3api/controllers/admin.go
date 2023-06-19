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
	"github.com/versity/versitygw/backend/auth"
)

type AdminController struct {
	IAMService auth.IAMService
}

func (c AdminController) CreateUser(ctx *fiber.Ctx) error {
	access, secret, role := ctx.Query("access"), ctx.Query("secret"), ctx.Query("role")
	requesterRole := ctx.Locals("role")

	if requesterRole != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}

	user := auth.Account{Secret: secret, Role: role}

	err := c.IAMService.CreateAccount(access, user)
	if err != nil {
		return fmt.Errorf("failed to create a user: %w", err)
	}

	ctx.SendString("The user has been created successfully")
	return nil
}

func (c AdminController) DeleteUser(ctx *fiber.Ctx) error {
	access := ctx.Query("access")
	requesterRole := ctx.Locals("role")
	if requesterRole != "admin" {
		return fmt.Errorf("access denied: only admin users have access to this resource")
	}

	err := c.IAMService.DeleteUserAccount(access)
	if err != nil {
		return err
	}

	ctx.SendString("The user has been created successfully")
	return nil
}
