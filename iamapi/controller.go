// Copyright 2026 Versity Software
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

package iamapi

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/iamapi/types"
)

type IAMApiController struct {
	store storage.Storer
}

func NewController(store storage.Storer) IAMApiController {
	return IAMApiController{store: store}
}

func (c IAMApiController) CreateUser(ctx fiber.Ctx) (*Response, error) {
	userName, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok {
		debuglogger.Logf("missing required CreateUser parameter: UserName")
		return nil, iamerr.GetAPIError(iamerr.ErrMissingUserNameValue)
	}
	if err := iamutil.ValidateUserName("userName", userName, iamutil.MaxUserNameLen); err != nil {
		return nil, err
	}

	path, ok := iamutil.RequestParam(ctx, "Path")
	if !ok || path == "" {
		path = iamutil.DefaultUserPath
	}
	if err := iamutil.ValidatePath("path", path); err != nil {
		return nil, err
	}

	tags, err := iamutil.ParseTags(ctx)
	if err != nil {
		return nil, err
	}

	for range 3 {
		userID, err := iamutil.GenerateUserID()
		if err != nil {
			return nil, err
		}

		user := types.User{
			Path:       path,
			UserName:   userName,
			UserID:     userID,
			Arn:        iamutil.BuildUserArn(iamutil.DefaultAccountID, path, userName),
			CreateDate: time.Now().UTC().Truncate(time.Second),
			Tags:       tags,
		}

		stored, err := c.store.CreateUser(ctx.Context(), user)
		if errors.Is(err, storage.ErrUserIDAlreadyExists) {
			debuglogger.Logf("IAM user ID collision while creating user %q: %v", userName, err)
			continue
		}
		if err != nil {
			debuglogger.Logf("failed to create IAM user %q: %v", userName, err)
			return nil, err
		}

		return &Response{Data: &types.CreateUserResponse{
			Result: types.CreateUserResult{User: *stored},
		}}, nil
	}

	err = fmt.Errorf("generate IAM user id: exhausted collision retries")
	debuglogger.Logf("failed to create IAM user %q: %v", userName, err)
	return nil, err
}

func (c IAMApiController) DeleteUser(ctx fiber.Ctx) (*Response, error) {
	username, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok || username == "" {
		debuglogger.Logf("missing required DeleteUser parameter: UserName")
		return nil, iamerr.MissingParameter("UserName")
	}
	if err := iamutil.ValidateUserName("userName", username, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	if err := c.store.DeleteUser(ctx.Context(), username); err != nil {
		debuglogger.Logf("failed to delete IAM user %q: %v", username, err)
		return nil, err
	}

	return &Response{Data: &types.DeleteUserResponse{}}, nil
}

func (c IAMApiController) GetUser(ctx fiber.Ctx) (*Response, error) {
	username, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok {
		debuglogger.Logf("missing required GetUser parameter: UserName")
		return nil, iamerr.MissingParameter("UserName")
	}
	if username == "" {
		return &Response{Data: &types.GetUserResponse{
			Result: types.GetUserResult{User: types.User{
				UserID: iamutil.DefaultAccountID,
				Arn:    fmt.Sprintf("arn:aws:iam::%s:root", iamutil.DefaultAccountID),
			}},
		}}, nil
	}
	if err := iamutil.ValidateUserName("userName", username, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	user, err := c.store.GetUser(ctx.Context(), username)
	if err != nil {
		debuglogger.Logf("failed to get IAM user %q: %v", username, err)
		return nil, err
	}

	return &Response{Data: &types.GetUserResponse{
		Result: types.GetUserResult{User: *user},
	}}, nil
}

func (c IAMApiController) ListUsers(ctx fiber.Ctx) (*Response, error) {
	pathPrefix, ok := iamutil.RequestParam(ctx, "PathPrefix")
	if !ok || pathPrefix == "" {
		pathPrefix = iamutil.DefaultUserPath
	}
	if err := iamutil.ValidatePathPrefix(pathPrefix); err != nil {
		return nil, err
	}

	maxItems := int32(iamutil.DefaultMaxItems)
	if rawMaxItems, ok := iamutil.RequestParam(ctx, "MaxItems"); ok && rawMaxItems != "" {
		parsed, err := strconv.ParseInt(rawMaxItems, 10, 32)
		if err != nil || parsed < 1 || parsed > iamutil.MaxListItems {
			debuglogger.Logf("invalid ListUsers MaxItems value %q: parse_error=%v", rawMaxItems, err)
			return nil, iamerr.InvalidMaxItems(rawMaxItems)
		}
		maxItems = int32(parsed)
	}

	marker, _ := iamutil.RequestParam(ctx, "Marker")
	out, err := c.store.ListUsers(ctx.Context(), storage.ListUsersInput{
		PathPrefix: pathPrefix,
		Marker:     marker,
		MaxItems:   maxItems,
	})
	if err != nil {
		debuglogger.Logf("failed to list IAM users: %v", err)
		return nil, err
	}

	return &Response{Data: &types.ListUsersResponse{
		Result: types.ListUsersResult{
			Users:       types.Users{Members: out.Users},
			IsTruncated: out.IsTruncated,
			Marker:      out.Marker,
		},
	}}, nil
}

func (c IAMApiController) UpdateUser(ctx fiber.Ctx) (*Response, error) {
	username, ok := iamutil.RequestParam(ctx, "UserName")
	if !ok || username == "" {
		debuglogger.Logf("missing required UpdateUser parameter: UserName")
		return nil, iamerr.MissingParameter("UserName")
	}
	if err := iamutil.ValidateUserName("userName", username, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	newPath, _ := iamutil.RequestParam(ctx, "NewPath")
	if newPath != "" {
		if err := iamutil.ValidatePath("newPath", newPath); err != nil {
			return nil, err
		}
	}
	newUserName, _ := iamutil.RequestParam(ctx, "NewUserName")
	if newUserName != "" {
		if err := iamutil.ValidateUserName("newUserName", newUserName, iamutil.MaxUserNameLen); err != nil {
			return nil, err
		}
	}

	user, err := c.store.GetUser(ctx.Context(), username)
	if err != nil {
		debuglogger.Logf("failed to get IAM user %q for update: %v", username, err)
		return nil, err
	}

	finalPath := user.Path
	if newPath != "" {
		finalPath = newPath
	}
	finalUserName := user.UserName
	if newUserName != "" {
		finalUserName = newUserName
	}

	updated, err := c.store.UpdateUser(ctx.Context(), storage.UpdateUserInput{
		UserName:    username,
		NewPath:     newPath,
		NewUserName: newUserName,
		NewArn:      iamutil.BuildUserArn(iamutil.DefaultAccountID, finalPath, finalUserName),
	})
	if err != nil {
		debuglogger.Logf("failed to update IAM user %q: %v", finalUserName, err)
		return nil, err
	}

	return &Response{Data: &types.UpdateUserResponse{
		Result: types.UpdateUserResult{User: updated},
	}}, nil
}
