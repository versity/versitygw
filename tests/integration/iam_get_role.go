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

package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMGetRole_missing_role_name(s *S3Conf) error {
	testName := "IAMGetRole_missing_role_name"
	body := []byte("Action=GetRole&Version=2010-05-08")
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam",
		region:   iamAuthRegion,
		body:     body,
		date:     time.Now().UTC(),
		headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.MissingParameter("RoleName"))
	})
}

func IAMGetRole_invalid_role_name(s *S3Conf) error {
	testName := "IAMGetRole_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := getIAMRole(client, "invalid/role")
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMGetRole_long_role_name(s *S3Conf) error {
	testName := "IAMGetRole_long_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := getIAMRole(client, strings.Repeat("a", 129))
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 128))
	})
}

func IAMGetRole_non_existing_role(s *S3Conf) error {
	testName := "IAMGetRole_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		const roleName = "asdfadsf"
		_, err := getIAMRole(client, roleName)
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMGetRole_success(s *S3Conf) error {
	testName := "IAMGetRole_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			Path:                     aws.String("/engineering/"),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Description:              aws.String("a test role"),
			MaxSessionDuration:       aws.Int32(7200),
			Tags: []iamtypes.Tag{
				{Key: aws.String("env"), Value: aws.String("test")},
			},
		}); err != nil {
			return err
		}

		out, err := getIAMRole(client, roleName)
		if err != nil {
			deleteErr := deleteIAMRole(client, roleName)
			if deleteErr != nil {
				return fmt.Errorf("get role: %v; delete role: %w", err, deleteErr)
			}
			return err
		}

		checkErr := checkGetRoleOutput(out, roleName, "/engineering/", "a test role", 7200, validTrustPolicyDocument, true)
		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func getIAMRole(client *iam.Client, roleName string) (*iam.GetRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
}

// checkGetRoleOutput verifies the fields of a GetRoleOutput-shaped role.
func checkGetRoleOutput(out *iam.GetRoleOutput, roleName, path, description string, maxSessionDuration int32, wantDocument string, expectTags bool) error {
	if out == nil {
		return fmt.Errorf("expected GetRole output role")
	}
	requestID, hasRequestID := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	return checkRoleFields("GetRole", out.Role, roleName, path, description, maxSessionDuration, wantDocument, expectTags, requestID, hasRequestID)
}
