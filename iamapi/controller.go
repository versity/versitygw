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
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/policy"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/iamapi/types"
)

type IAMApiController struct {
	store storage.Storer
	// oidcThumbprintAutoFetchDisabled disables CreateOpenIDConnectProvider's
	// TLS auto-fetch fallback when ThumbprintList is omitted (operational
	// safety valve for restricted/air-gapped deployments); set via
	// iamapi.WithOIDCThumbprintAutoFetchDisabled(). Defaults to false
	// (auto-fetch enabled), matching real AWS behavior.
	oidcThumbprintAutoFetchDisabled bool
}

func NewController(store storage.Storer, oidcThumbprintAutoFetchDisabled bool) IAMApiController {
	return IAMApiController{
		store:                           store,
		oidcThumbprintAutoFetchDisabled: oidcThumbprintAutoFetchDisabled,
	}
}

func (c IAMApiController) CreateUser(ctx fiber.Ctx) (*Response, error) {
	userName, err := iamutil.GetUserName(ctx, "CreateUser", iamutil.MaxUserNameLen, iamerr.MissingValue("userName"))
	if err != nil {
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
	username, err := iamutil.GetUserName(ctx, "DeleteUser", iamutil.MaxUserLookupLen, iamerr.MissingParameter("UserName"))
	if err != nil {
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
	if err := iamutil.ValidateName("userName", username, iamutil.MaxUserLookupLen); err != nil {
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

	maxItems, err := iamutil.ParseMaxItems(ctx, "ListUsers")
	if err != nil {
		return nil, err
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
	username, err := iamutil.GetUserName(ctx, "UpdateUser", iamutil.MaxUserLookupLen, iamerr.MissingParameter("UserName"))
	if err != nil {
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
		if err := iamutil.ValidateName("newUserName", newUserName, iamutil.MaxUserNameLen); err != nil {
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

func (c IAMApiController) CreateAccessKey(ctx fiber.Ctx) (*Response, error) {
	userName, err := iamutil.GetUserName(ctx, "CreateAccessKey", iamutil.MaxUserLookupLen, iamerr.MissingParameter("UserName"))
	if err != nil {
		return nil, err
	}

	for range 3 {
		accessKeyID, err := iamutil.GenerateAccessKeyID()
		if err != nil {
			return nil, err
		}
		secretAccessKey, err := iamutil.GenerateSecretAccessKey()
		if err != nil {
			return nil, err
		}

		stored, err := c.store.CreateAccessKey(ctx.Context(), storage.CreateAccessKeyInput{
			UserName:        userName,
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			Status:          iamutil.AccessKeyStatusActive,
			CreateDate:      time.Now().UTC().Truncate(time.Second),
		})
		if errors.Is(err, storage.ErrAccessKeyIDAlreadyExists) {
			debuglogger.Logf("IAM access key id collision for user %q: %v", userName, err)
			continue
		}
		if err != nil {
			debuglogger.Logf("failed to create IAM access key for user %q: %v", userName, err)
			return nil, err
		}

		return &Response{
			Data: &types.CreateAccessKeyResponse{
				Result: types.CreateAccessKeyResult{AccessKey: *stored},
			},
		}, nil
	}

	err = fmt.Errorf("generate IAM access key id: exhausted collision retries")
	debuglogger.Logf("failed to create IAM access key for user %q: %v", userName, err)
	return nil, err
}

func (c IAMApiController) UpdateAccessKey(ctx fiber.Ctx) (*Response, error) {
	userName, err := iamutil.GetUserName(ctx, "UpdateAccessKey", iamutil.MaxUserLookupLen, iamerr.MissingParameter("UserName"))
	if err != nil {
		return nil, err
	}

	accessKeyID, ok := iamutil.RequestParam(ctx, "AccessKeyId")
	if !ok || accessKeyID == "" {
		debuglogger.Logf("missing required UpdateAccessKey parameter: AccessKeyId")
		return nil, iamerr.MissingParameter("AccessKeyId")
	}
	if err := iamutil.ValidateAccessKeyID(accessKeyID); err != nil {
		return nil, err
	}

	status, ok := iamutil.RequestParam(ctx, "Status")
	if !ok || status == "" {
		debuglogger.Logf("missing required UpdateAccessKey parameter: Status")
		return nil, iamerr.MissingParameter("Status")
	}
	if err := iamutil.ValidateAccessKeyStatus(status); err != nil {
		return nil, err
	}

	if err := c.store.UpdateAccessKey(ctx.Context(), storage.UpdateAccessKeyInput{
		UserName:    userName,
		AccessKeyID: accessKeyID,
		Status:      status,
	}); err != nil {
		debuglogger.Logf("failed to update IAM access key %q for user %q: %v", accessKeyID, userName, err)
		return nil, err
	}

	return &Response{Data: &types.UpdateAccessKeyResponse{}}, nil
}

func (c IAMApiController) DeleteAccessKey(ctx fiber.Ctx) (*Response, error) {
	userName, err := iamutil.GetUserName(ctx, "DeleteAccessKey", iamutil.MaxUserLookupLen, iamerr.MissingParameter("UserName"))
	if err != nil {
		return nil, err
	}

	accessKeyID, ok := iamutil.RequestParam(ctx, "AccessKeyId")
	if !ok || accessKeyID == "" {
		debuglogger.Logf("missing required DeleteAccessKey parameter: AccessKeyId")
		return nil, iamerr.MissingParameter("AccessKeyId")
	}
	if err := iamutil.ValidateAccessKeyID(accessKeyID); err != nil {
		return nil, err
	}

	if err := c.store.DeleteAccessKey(ctx.Context(), userName, accessKeyID); err != nil {
		debuglogger.Logf("failed to delete IAM access key %q for user %q: %v", accessKeyID, userName, err)
		return nil, err
	}

	return &Response{Data: &types.DeleteAccessKeyResponse{}}, nil
}

func (c IAMApiController) GetAccessKeyLastUsed(ctx fiber.Ctx) (*Response, error) {
	accessKeyID, ok := iamutil.RequestParam(ctx, "AccessKeyId")
	if !ok || accessKeyID == "" {
		debuglogger.Logf("missing required GetAccessKeyLastUsed parameter: AccessKeyId")
		return nil, iamerr.MissingParameter("AccessKeyId")
	}
	if err := iamutil.ValidateAccessKeyID(accessKeyID); err != nil {
		return nil, err
	}

	out, err := c.store.GetAccessKeyLastUsed(ctx.Context(), accessKeyID)
	if err != nil {
		debuglogger.Logf("failed to get IAM access key last used %q: %v", accessKeyID, err)
		return nil, err
	}

	serviceName := out.ServiceName
	if serviceName == "" {
		serviceName = "N/A"
	}
	region := out.Region
	if region == "" {
		region = "N/A"
	}

	var lastUsedDate *time.Time
	if !out.LastUsedDate.IsZero() {
		lastUsedDate = &out.LastUsedDate
	}

	return &Response{Data: &types.GetAccessKeyLastUsedResponse{
		Result: types.GetAccessKeyLastUsedResult{
			UserName: out.UserName,
			AccessKeyLastUsed: types.AccessKeyLastUsed{
				LastUsedDate: lastUsedDate,
				ServiceName:  serviceName,
				Region:       region,
			},
		},
	}}, nil
}

func (c IAMApiController) ListAccessKeys(ctx fiber.Ctx) (*Response, error) {
	userName, err := iamutil.GetUserName(ctx, "ListAccessKeys", iamutil.MaxUserLookupLen, iamerr.MissingParameter("UserName"))
	if err != nil {
		return nil, err
	}

	maxItems, err := iamutil.ParseMaxItems(ctx, "ListAccessKeys")
	if err != nil {
		return nil, err
	}

	marker, _ := iamutil.RequestParam(ctx, "Marker")
	out, err := c.store.ListAccessKeys(ctx.Context(), storage.ListAccessKeysInput{
		UserName: userName,
		Marker:   marker,
		MaxItems: maxItems,
	})
	if err != nil {
		debuglogger.Logf("failed to list IAM access keys for user %q: %v", userName, err)
		return nil, err
	}

	return &Response{Data: &types.ListAccessKeysResponse{
		Result: types.ListAccessKeysResult{
			AccessKeyMetadata: types.AccessKeyMetadataList{Members: out.AccessKeys},
			IsTruncated:       out.IsTruncated,
			Marker:            out.Marker,
		},
	}}, nil
}

func (c IAMApiController) PutUserPolicy(ctx fiber.Ctx) (*Response, error) {
	policyDocument, ok := iamutil.RequestParam(ctx, "PolicyDocument")
	if !ok {
		debuglogger.Logf("missing required PutUserPolicy parameter: PolicyDocument")
		return nil, iamerr.MissingValue("policyDocument")
	}
	if err := policy.Validate("policyDocument", policyDocument); err != nil {
		return nil, err
	}

	policyName, ok := iamutil.RequestParam(ctx, "PolicyName")
	if !ok {
		debuglogger.Logf("missing required PutUserPolicy parameter: PolicyName")
		return nil, iamerr.MissingValue("policyName")
	}
	if err := iamutil.ValidateName("policyName", policyName, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	userName, err := iamutil.GetUserName(ctx, "PutUserPolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("userName"))
	if err != nil {
		return nil, err
	}

	// Confirm the user exists before inspecting policy document content
	if _, err := c.store.GetUser(ctx.Context(), userName); err != nil {
		debuglogger.Logf("failed to get IAM user %q for PutUserPolicy: %v", userName, err)
		return nil, err
	}

	if err := policy.Parse(policyDocument); err != nil {
		return nil, err
	}

	if err := c.store.PutUserPolicy(ctx.Context(), storage.PutUserPolicyInput{
		UserName:       userName,
		PolicyName:     policyName,
		PolicyDocument: policyDocument,
	}); err != nil {
		debuglogger.Logf("failed to put IAM user policy %q for user %q: %v", policyName, userName, err)
		return nil, err
	}

	return &Response{Data: &types.PutUserPolicyResponse{}}, nil
}

func (c IAMApiController) GetUserPolicy(ctx fiber.Ctx) (*Response, error) {
	policyName, ok := iamutil.RequestParam(ctx, "PolicyName")
	if !ok {
		debuglogger.Logf("missing required GetUserPolicy parameter: PolicyName")
		return nil, iamerr.MissingValue("policyName")
	}
	if err := iamutil.ValidateName("policyName", policyName, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	userName, err := iamutil.GetUserName(ctx, "GetUserPolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("userName"))
	if err != nil {
		return nil, err
	}

	entry, err := c.store.GetUserPolicy(ctx.Context(), userName, policyName)
	if err != nil {
		debuglogger.Logf("failed to get IAM user policy %q for user %q: %v", policyName, userName, err)
		return nil, err
	}

	return &Response{Data: &types.GetUserPolicyResponse{
		Result: types.GetUserPolicyResult{
			UserName:       userName,
			PolicyName:     entry.PolicyName,
			PolicyDocument: iamutil.EncodePolicyDocument(entry.PolicyDocument),
		},
	}}, nil
}

func (c IAMApiController) DeleteUserPolicy(ctx fiber.Ctx) (*Response, error) {
	policyName, ok := iamutil.RequestParam(ctx, "PolicyName")
	if !ok {
		debuglogger.Logf("missing required DeleteUserPolicy parameter: PolicyName")
		return nil, iamerr.MissingValue("policyName")
	}
	if err := iamutil.ValidateName("policyName", policyName, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	userName, err := iamutil.GetUserName(ctx, "DeleteUserPolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("userName"))
	if err != nil {
		return nil, err
	}

	if err := c.store.DeleteUserPolicy(ctx.Context(), userName, policyName); err != nil {
		debuglogger.Logf("failed to delete IAM user policy %q for user %q: %v", policyName, userName, err)
		return nil, err
	}

	return &Response{Data: &types.DeleteUserPolicyResponse{}}, nil
}

func (c IAMApiController) ListUserPolicies(ctx fiber.Ctx) (*Response, error) {
	userName, err := iamutil.GetUserName(ctx, "ListUserPolicies", iamutil.MaxUserLookupLen, iamerr.MissingValue("userName"))
	if err != nil {
		return nil, err
	}

	maxItems, err := iamutil.ParseMaxItems(ctx, "ListUserPolicies")
	if err != nil {
		return nil, err
	}

	marker, _ := iamutil.RequestParam(ctx, "Marker")
	out, err := c.store.ListUserPolicies(ctx.Context(), storage.ListUserPoliciesInput{
		UserName: userName,
		Marker:   marker,
		MaxItems: maxItems,
	})
	if err != nil {
		debuglogger.Logf("failed to list IAM user policies for user %q: %v", userName, err)
		return nil, err
	}

	return &Response{Data: &types.ListUserPoliciesResponse{
		Result: types.ListUserPoliciesResult{
			PolicyNames: types.PolicyNameList{Members: out.PolicyNames},
			IsTruncated: out.IsTruncated,
			Marker:      out.Marker,
		},
	}}, nil
}

func (c IAMApiController) CreateRole(ctx fiber.Ctx) (*Response, error) {
	roleName, err := iamutil.GetRoleName(ctx, "CreateRole", iamutil.MaxUserNameLen, iamerr.MissingValue("roleName"))
	if err != nil {
		return nil, err
	}

	path, ok := iamutil.RequestParam(ctx, "Path")
	if !ok || path == "" {
		path = iamutil.DefaultUserPath
	}
	if err := iamutil.ValidatePath("path", path); err != nil {
		return nil, err
	}

	assumeRolePolicyDocument, ok := iamutil.RequestParam(ctx, "AssumeRolePolicyDocument")
	if !ok || assumeRolePolicyDocument == "" {
		debuglogger.Logf("missing required CreateRole parameter: AssumeRolePolicyDocument")
		return nil, iamerr.MissingValue("assumeRolePolicyDocument")
	}
	if err := policy.Validate("assumeRolePolicyDocument", assumeRolePolicyDocument); err != nil {
		return nil, err
	}
	if err := policy.ParseTrust(assumeRolePolicyDocument); err != nil {
		return nil, err
	}
	if len(assumeRolePolicyDocument) > policy.MaxTrustPolicyBytes {
		return nil, iamerr.TrustPolicySizeLimitExceeded(policy.MaxTrustPolicyBytes)
	}

	description, _ := iamutil.RequestParam(ctx, "Description")
	if err := iamutil.ValidateDescription("description", description); err != nil {
		return nil, err
	}

	maxSessionDuration, err := iamutil.ParseMaxSessionDuration(ctx)
	if err != nil {
		return nil, err
	}

	tags, err := iamutil.ParseTags(ctx)
	if err != nil {
		return nil, err
	}

	for range 3 {
		roleID, err := iamutil.GenerateRoleID()
		if err != nil {
			return nil, err
		}

		role := types.Role{
			Path:                     path,
			RoleName:                 roleName,
			RoleID:                   roleID,
			Arn:                      iamutil.BuildRoleArn(iamutil.DefaultAccountID, path, roleName),
			CreateDate:               time.Now().UTC().Truncate(time.Second),
			AssumeRolePolicyDocument: assumeRolePolicyDocument,
			Description:              description,
			MaxSessionDuration:       maxSessionDuration,
			Tags:                     tags,
		}

		stored, err := c.store.CreateRole(ctx.Context(), role)
		if errors.Is(err, storage.ErrRoleIDAlreadyExists) {
			debuglogger.Logf("IAM role ID collision while creating role %q: %v", roleName, err)
			continue
		}
		if err != nil {
			debuglogger.Logf("failed to create IAM role %q: %v", roleName, err)
			return nil, err
		}

		stored.AssumeRolePolicyDocument = iamutil.EncodePolicyDocument(stored.AssumeRolePolicyDocument)

		return &Response{Data: &types.CreateRoleResponse{
			Result: types.CreateRoleResult{Role: stored},
		}}, nil
	}

	err = fmt.Errorf("generate IAM role id: exhausted collision retries")
	debuglogger.Logf("failed to create IAM role %q: %v", roleName, err)
	return nil, err
}

func (c IAMApiController) GetRole(ctx fiber.Ctx) (*Response, error) {
	roleName, err := iamutil.GetRoleName(ctx, "GetRole", iamutil.MaxUserLookupLen, iamerr.MissingParameter("RoleName"))
	if err != nil {
		return nil, err
	}

	role, err := c.store.GetRole(ctx.Context(), roleName)
	if err != nil {
		debuglogger.Logf("failed to get IAM role %q: %v", roleName, err)
		return nil, err
	}

	role.AssumeRolePolicyDocument = iamutil.EncodePolicyDocument(role.AssumeRolePolicyDocument)

	return &Response{Data: &types.GetRoleResponse{
		Result: types.GetRoleResult{Role: role},
	}}, nil
}

func (c IAMApiController) ListRoles(ctx fiber.Ctx) (*Response, error) {
	pathPrefix, ok := iamutil.RequestParam(ctx, "PathPrefix")
	if !ok || pathPrefix == "" {
		pathPrefix = iamutil.DefaultUserPath
	}
	if err := iamutil.ValidatePathPrefix(pathPrefix); err != nil {
		return nil, err
	}

	maxItems, err := iamutil.ParseMaxItems(ctx, "ListRoles")
	if err != nil {
		return nil, err
	}

	marker, _ := iamutil.RequestParam(ctx, "Marker")
	out, err := c.store.ListRoles(ctx.Context(), storage.ListRolesInput{
		PathPrefix: pathPrefix,
		Marker:     marker,
		MaxItems:   maxItems,
	})
	if err != nil {
		debuglogger.Logf("failed to list IAM roles: %v", err)
		return nil, err
	}

	roles := make([]types.Role, len(out.Roles))
	for i, role := range out.Roles {
		role.AssumeRolePolicyDocument = iamutil.EncodePolicyDocument(role.AssumeRolePolicyDocument)
		roles[i] = role
	}

	return &Response{Data: &types.ListRolesResponse{
		Result: types.ListRolesResult{
			Roles:       types.Roles{Members: roles},
			IsTruncated: out.IsTruncated,
			Marker:      out.Marker,
		},
	}}, nil
}

func (c IAMApiController) DeleteRole(ctx fiber.Ctx) (*Response, error) {
	roleName, err := iamutil.GetRoleName(ctx, "DeleteRole", iamutil.MaxUserLookupLen, iamerr.MissingParameter("RoleName"))
	if err != nil {
		return nil, err
	}

	if err := c.store.DeleteRole(ctx.Context(), roleName); err != nil {
		debuglogger.Logf("failed to delete IAM role %q: %v", roleName, err)
		return nil, err
	}

	return &Response{Data: &types.DeleteRoleResponse{}}, nil
}

func (c IAMApiController) UpdateAssumeRolePolicy(ctx fiber.Ctx) (*Response, error) {
	policyDocument, ok := iamutil.RequestParam(ctx, "PolicyDocument")
	if !ok {
		debuglogger.Logf("missing required UpdateAssumeRolePolicy parameter: PolicyDocument")
		return nil, iamerr.MissingValue("policyDocument")
	}
	if err := policy.Validate("policyDocument", policyDocument); err != nil {
		return nil, err
	}

	roleName, err := iamutil.GetRoleName(ctx, "UpdateAssumeRolePolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("roleName"))
	if err != nil {
		return nil, err
	}

	// Confirm the role exists before inspecting policy document content
	if _, err := c.store.GetRole(ctx.Context(), roleName); err != nil {
		debuglogger.Logf("failed to get IAM role %q for UpdateAssumeRolePolicy: %v", roleName, err)
		return nil, err
	}

	if err := policy.ParseTrust(policyDocument); err != nil {
		return nil, err
	}
	if len(policyDocument) > policy.MaxTrustPolicyBytes {
		return nil, iamerr.TrustPolicySizeLimitExceeded(policy.MaxTrustPolicyBytes)
	}

	if _, err := c.store.UpdateAssumeRolePolicy(ctx.Context(), storage.UpdateAssumeRolePolicyInput{
		RoleName:       roleName,
		PolicyDocument: policyDocument,
	}); err != nil {
		debuglogger.Logf("failed to update IAM assume role policy for role %q: %v", roleName, err)
		return nil, err
	}

	return &Response{Data: &types.UpdateAssumeRolePolicyResponse{}}, nil
}

func (c IAMApiController) PutRolePolicy(ctx fiber.Ctx) (*Response, error) {
	policyDocument, ok := iamutil.RequestParam(ctx, "PolicyDocument")
	if !ok {
		debuglogger.Logf("missing required PutRolePolicy parameter: PolicyDocument")
		return nil, iamerr.MissingValue("policyDocument")
	}
	if err := policy.Validate("policyDocument", policyDocument); err != nil {
		return nil, err
	}

	policyName, ok := iamutil.RequestParam(ctx, "PolicyName")
	if !ok {
		debuglogger.Logf("missing required PutRolePolicy parameter: PolicyName")
		return nil, iamerr.MissingValue("policyName")
	}
	if err := iamutil.ValidateName("policyName", policyName, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	roleName, err := iamutil.GetRoleName(ctx, "PutRolePolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("roleName"))
	if err != nil {
		return nil, err
	}

	// Confirm the role exists before inspecting policy document content
	if _, err := c.store.GetRole(ctx.Context(), roleName); err != nil {
		debuglogger.Logf("failed to get IAM role %q for PutRolePolicy: %v", roleName, err)
		return nil, err
	}

	if err := policy.Parse(policyDocument); err != nil {
		return nil, err
	}

	if err := c.store.PutRolePolicy(ctx.Context(), storage.PutRolePolicyInput{
		RoleName:       roleName,
		PolicyName:     policyName,
		PolicyDocument: policyDocument,
	}); err != nil {
		debuglogger.Logf("failed to put IAM role policy %q for role %q: %v", policyName, roleName, err)
		return nil, err
	}

	return &Response{Data: &types.PutRolePolicyResponse{}}, nil
}

func (c IAMApiController) GetRolePolicy(ctx fiber.Ctx) (*Response, error) {
	policyName, ok := iamutil.RequestParam(ctx, "PolicyName")
	if !ok {
		debuglogger.Logf("missing required GetRolePolicy parameter: PolicyName")
		return nil, iamerr.MissingValue("policyName")
	}
	if err := iamutil.ValidateName("policyName", policyName, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	roleName, err := iamutil.GetRoleName(ctx, "GetRolePolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("roleName"))
	if err != nil {
		return nil, err
	}

	entry, err := c.store.GetRolePolicy(ctx.Context(), roleName, policyName)
	if err != nil {
		debuglogger.Logf("failed to get IAM role policy %q for role %q: %v", policyName, roleName, err)
		return nil, err
	}

	return &Response{Data: &types.GetRolePolicyResponse{
		Result: types.GetRolePolicyResult{
			RoleName:       roleName,
			PolicyName:     entry.PolicyName,
			PolicyDocument: iamutil.EncodePolicyDocument(entry.PolicyDocument),
		},
	}}, nil
}

func (c IAMApiController) DeleteRolePolicy(ctx fiber.Ctx) (*Response, error) {
	policyName, ok := iamutil.RequestParam(ctx, "PolicyName")
	if !ok {
		debuglogger.Logf("missing required DeleteRolePolicy parameter: PolicyName")
		return nil, iamerr.MissingValue("policyName")
	}
	if err := iamutil.ValidateName("policyName", policyName, iamutil.MaxUserLookupLen); err != nil {
		return nil, err
	}

	roleName, err := iamutil.GetRoleName(ctx, "DeleteRolePolicy", iamutil.MaxUserLookupLen, iamerr.MissingValue("roleName"))
	if err != nil {
		return nil, err
	}

	if err := c.store.DeleteRolePolicy(ctx.Context(), roleName, policyName); err != nil {
		debuglogger.Logf("failed to delete IAM role policy %q for role %q: %v", policyName, roleName, err)
		return nil, err
	}

	return &Response{Data: &types.DeleteRolePolicyResponse{}}, nil
}

func (c IAMApiController) ListRolePolicies(ctx fiber.Ctx) (*Response, error) {
	roleName, err := iamutil.GetRoleName(ctx, "ListRolePolicies", iamutil.MaxUserLookupLen, iamerr.MissingValue("roleName"))
	if err != nil {
		return nil, err
	}

	maxItems, err := iamutil.ParseMaxItems(ctx, "ListRolePolicies")
	if err != nil {
		return nil, err
	}

	marker, _ := iamutil.RequestParam(ctx, "Marker")
	out, err := c.store.ListRolePolicies(ctx.Context(), storage.ListRolePoliciesInput{
		RoleName: roleName,
		Marker:   marker,
		MaxItems: maxItems,
	})
	if err != nil {
		debuglogger.Logf("failed to list IAM role policies for role %q: %v", roleName, err)
		return nil, err
	}

	return &Response{Data: &types.ListRolePoliciesResponse{
		Result: types.ListRolePoliciesResult{
			PolicyNames: types.PolicyNameList{Members: out.PolicyNames},
			IsTruncated: out.IsTruncated,
			Marker:      out.Marker,
		},
	}}, nil
}

func (c IAMApiController) CreateOpenIDConnectProvider(ctx fiber.Ctx) (*Response, error) {
	rawURL, ok := iamutil.RequestParam(ctx, "Url")
	if !ok || rawURL == "" {
		debuglogger.Logf("missing required CreateOpenIDConnectProvider parameter: Url")
		return nil, iamerr.MissingValue("url")
	}
	url, err := iamutil.ValidateOIDCProviderURL(rawURL)
	if err != nil {
		return nil, err
	}

	clientIDs := iamutil.ParseStringList(ctx, "ClientIDList")
	if len(clientIDs) > storage.MaxClientIDsPerOIDCProvider {
		return nil, iamerr.ClientIdsPerOpenIdConnectProviderLimitExceeded(storage.MaxClientIDsPerOIDCProvider)
	}
	for _, id := range clientIDs {
		if len(id) > iamutil.MaxOIDCClientIDLen {
			return nil, iamerr.ValueTooLong("clientID", iamutil.MaxOIDCClientIDLen)
		}
	}

	thumbprints := iamutil.ParseStringList(ctx, "ThumbprintList")
	if len(thumbprints) == 0 {
		if c.oidcThumbprintAutoFetchDisabled {
			debuglogger.Logf("CreateOpenIDConnectProvider: ThumbprintList omitted and auto-fetch is disabled")
			return nil, iamerr.MissingValue("thumbprintList")
		}
		fetched, err := iamutil.FetchThumbprint(ctx.Context(), url)
		if err != nil {
			debuglogger.Logf("failed to auto-fetch OIDC thumbprint for url %q: %v", url, err)
			return nil, err
		}
		thumbprints = []string{fetched}
	} else {
		if err := iamutil.ValidateThumbprintList(thumbprints, false); err != nil {
			return nil, err
		}
		thumbprints = iamutil.NormalizeThumbprintList(thumbprints)
	}

	tags, err := iamutil.ParseTags(ctx)
	if err != nil {
		return nil, err
	}

	provider := types.OIDCProvider{
		Arn:            iamutil.BuildOIDCProviderArn(iamutil.DefaultAccountID, url),
		Url:            url,
		ClientIDList:   clientIDs,
		ThumbprintList: thumbprints,
		CreateDate:     time.Now().UTC().Truncate(time.Second),
		Tags:           tags,
	}

	stored, err := c.store.CreateOIDCProvider(ctx.Context(), provider)
	if err != nil {
		debuglogger.Logf("failed to create IAM OIDC provider for url %q: %v", url, err)
		return nil, err
	}

	return &Response{Data: &types.CreateOpenIDConnectProviderResponse{
		Result: types.CreateOpenIDConnectProviderResult{
			OpenIDConnectProviderArn: stored.Arn,
			Tags:                     stored.Tags,
		},
	}}, nil
}

func (c IAMApiController) GetOpenIDConnectProvider(ctx fiber.Ctx) (*Response, error) {
	arn, err := iamutil.GetOIDCProviderArn(ctx, "GetOpenIDConnectProvider")
	if err != nil {
		return nil, err
	}

	provider, err := c.store.GetOIDCProvider(ctx.Context(), arn)
	if err != nil {
		debuglogger.Logf("failed to get IAM OIDC provider %q: %v", arn, err)
		return nil, err
	}

	return &Response{Data: &types.GetOpenIDConnectProviderResponse{
		Result: types.GetOpenIDConnectProviderResult{
			Url:            provider.Url,
			ClientIDList:   provider.ClientIDList,
			ThumbprintList: provider.ThumbprintList,
			CreateDate:     provider.CreateDate,
			Tags:           provider.Tags,
		},
	}}, nil
}

func (c IAMApiController) ListOpenIDConnectProviders(ctx fiber.Ctx) (*Response, error) {
	out, err := c.store.ListOIDCProviders(ctx.Context())
	if err != nil {
		debuglogger.Logf("failed to list IAM OIDC providers: %v", err)
		return nil, err
	}

	return &Response{Data: &types.ListOpenIDConnectProvidersResponse{
		Result: types.ListOpenIDConnectProvidersResult{
			OpenIDConnectProviderList: types.OpenIDConnectProviderList{Members: out.Providers},
		},
	}}, nil
}

func (c IAMApiController) DeleteOpenIDConnectProvider(ctx fiber.Ctx) (*Response, error) {
	arn, err := iamutil.GetOIDCProviderArn(ctx, "DeleteOpenIDConnectProvider")
	if err != nil {
		return nil, err
	}

	if err := c.store.DeleteOIDCProvider(ctx.Context(), arn); err != nil {
		debuglogger.Logf("failed to delete IAM OIDC provider %q: %v", arn, err)
		return nil, err
	}

	return &Response{Data: &types.DeleteOpenIDConnectProviderResponse{}}, nil
}

func (c IAMApiController) AddClientIDToOpenIDConnectProvider(ctx fiber.Ctx) (*Response, error) {
	arn, err := iamutil.GetOIDCProviderArn(ctx, "AddClientIDToOpenIDConnectProvider")
	if err != nil {
		return nil, err
	}

	clientID, ok := iamutil.RequestParam(ctx, "ClientID")
	if !ok || clientID == "" {
		debuglogger.Logf("missing required AddClientIDToOpenIDConnectProvider parameter: ClientID")
		return nil, iamerr.MissingValue("clientID")
	}
	if len(clientID) > iamutil.MaxOIDCClientIDLen {
		return nil, iamerr.ValueTooLong("clientID", iamutil.MaxOIDCClientIDLen)
	}

	if err := c.store.AddClientIDToOIDCProvider(ctx.Context(), arn, clientID); err != nil {
		debuglogger.Logf("failed to add client id %q to IAM OIDC provider %q: %v", clientID, arn, err)
		return nil, err
	}

	return &Response{Data: &types.AddClientIDToOpenIDConnectProviderResponse{}}, nil
}

func (c IAMApiController) RemoveClientIDFromOpenIDConnectProvider(ctx fiber.Ctx) (*Response, error) {
	arn, err := iamutil.GetOIDCProviderArn(ctx, "RemoveClientIDFromOpenIDConnectProvider")
	if err != nil {
		return nil, err
	}

	clientID, ok := iamutil.RequestParam(ctx, "ClientID")
	if !ok || clientID == "" {
		debuglogger.Logf("missing required RemoveClientIDFromOpenIDConnectProvider parameter: ClientID")
		return nil, iamerr.MissingValue("clientID")
	}
	if len(clientID) > iamutil.MaxOIDCClientIDLen {
		return nil, iamerr.ValueTooLong("clientID", iamutil.MaxOIDCClientIDLen)
	}

	if err := c.store.RemoveClientIDFromOIDCProvider(ctx.Context(), arn, clientID); err != nil {
		debuglogger.Logf("failed to remove client id %q from IAM OIDC provider %q: %v", clientID, arn, err)
		return nil, err
	}

	return &Response{Data: &types.RemoveClientIDFromOpenIDConnectProviderResponse{}}, nil
}

func (c IAMApiController) UpdateOpenIDConnectProviderThumbprint(ctx fiber.Ctx) (*Response, error) {
	arn, err := iamutil.GetOIDCProviderArn(ctx, "UpdateOpenIDConnectProviderThumbprint")
	if err != nil {
		return nil, err
	}

	thumbprints := iamutil.ParseStringList(ctx, "ThumbprintList")
	if err := iamutil.ValidateThumbprintList(thumbprints, true); err != nil {
		return nil, err
	}
	thumbprints = iamutil.NormalizeThumbprintList(thumbprints)

	if err := c.store.UpdateOIDCProviderThumbprint(ctx.Context(), arn, thumbprints); err != nil {
		debuglogger.Logf("failed to update IAM OIDC provider thumbprint for %q: %v", arn, err)
		return nil, err
	}

	return &Response{Data: &types.UpdateOpenIDConnectProviderThumbprintResponse{}}, nil
}
