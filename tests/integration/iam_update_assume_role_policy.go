// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/policy"
)

func IAMUpdateAssumeRolePolicy_missing_role_name(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_missing_role_name"
	body := []byte(url.Values{
		"Action":         {"UpdateAssumeRolePolicy"},
		"Version":        {"2010-05-08"},
		"PolicyDocument": {validTrustPolicyDocument},
	}.Encode())
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("roleName"))
	})
}

func IAMUpdateAssumeRolePolicy_missing_policy_document(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_missing_policy_document"
	body := []byte(url.Values{
		"Action":   {"UpdateAssumeRolePolicy"},
		"Version":  {"2010-05-08"},
		"RoleName": {newIAMRoleName()},
	}.Encode())
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("policyDocument"))
	})
}

func IAMUpdateAssumeRolePolicy_invalid_role_name(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String("invalid/role"),
			PolicyDocument: aws.String(validTrustPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMUpdateAssumeRolePolicy_long_role_name(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_long_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String(strings.Repeat("a", 129)),
			PolicyDocument: aws.String(validTrustPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 128))
	})
}

func IAMUpdateAssumeRolePolicy_non_existing_role(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		const roleName = "asdfadsf"
		_, err := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String(roleName),
			PolicyDocument: aws.String(validTrustPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMUpdateAssumeRolePolicy_non_ascii_policy_document(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_non_ascii_policy_document"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String("asdfadsf"),
			PolicyDocument: aws.String("emoji\U0001F600test"),
		})
		return checkIAMApiErr(err, iamerr.InvalidCharset("policyDocument"))
	})
}

func IAMUpdateAssumeRolePolicy_trust_policy_size_limit_exceeded(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_trust_policy_size_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			oversized := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 2000) + `","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
			_, err := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
				RoleName:       &roleName,
				PolicyDocument: aws.String(oversized),
			})
			return checkIAMApiErr(err, iamerr.TrustPolicySizeLimitExceeded(policy.MaxTrustPolicyBytes))
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMUpdateAssumeRolePolicy_success(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		created, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		})
		if err != nil {
			return err
		}

		checkErr := func() error {
			const updatedDocument = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
			out, err := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
				RoleName:       &roleName,
				PolicyDocument: aws.String(updatedDocument),
			})
			if err != nil {
				return err
			}
			if out == nil {
				return fmt.Errorf("expected UpdateAssumeRolePolicy output")
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected UpdateAssumeRolePolicy response request id")
			}

			got, err := getIAMRole(client, roleName)
			if err != nil {
				return err
			}
			if got == nil || got.Role == nil || created == nil || created.Role == nil {
				return fmt.Errorf("expected created and updated roles")
			}
			gotDocument, err := url.QueryUnescape(aws.ToString(got.Role.AssumeRolePolicyDocument))
			if err != nil {
				return fmt.Errorf("failed to url-decode assume role policy document %q: %w", aws.ToString(got.Role.AssumeRolePolicyDocument), err)
			}
			if gotDocument != updatedDocument {
				return fmt.Errorf("expected updated assume role policy document %q, instead got %q", updatedDocument, gotDocument)
			}
			if aws.ToString(got.Role.RoleId) != aws.ToString(created.Role.RoleId) {
				return fmt.Errorf("expected UpdateAssumeRolePolicy to preserve role id, want %q, instead got %q", aws.ToString(created.Role.RoleId), aws.ToString(got.Role.RoleId))
			}
			if got.Role.CreateDate == nil || created.Role.CreateDate == nil || !got.Role.CreateDate.Equal(*created.Role.CreateDate) {
				return fmt.Errorf("expected UpdateAssumeRolePolicy to preserve role create date")
			}
			return nil
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func updateIAMAssumeRolePolicy(client *iam.Client, input *iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.UpdateAssumeRolePolicy(ctx, input)
}

func IAMUpdateAssumeRolePolicy_trust_policy_document_grammar(s *S3Conf) error {
	testName := "IAMUpdateAssumeRolePolicy_trust_policy_document_grammar"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, tt := range trustPolicyGrammarCases {
			if err := checkUpdateAssumeRolePolicyTrustPolicyCase(client, tt.doc, tt.wantErr); err != nil {
				return fmt.Errorf("%s: %w", tt.name, err)
			}
		}
		return nil
	})
}

// checkUpdateAssumeRolePolicyTrustPolicyCase verifies doc is accepted/rejected
// as expected when used to update an existing role's trust policy.
func checkUpdateAssumeRolePolicyTrustPolicyCase(client *iam.Client, doc string, wantErr iamerr.APIError) (err error) {
	roleName := newIAMRoleName()
	if _, err := createIAMRole(client, &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
	}); err != nil {
		return fmt.Errorf("create base role: %w", err)
	}
	defer func() {
		if deleteErr := deleteIAMRole(client, roleName); deleteErr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup: %w", deleteErr))
		}
	}()

	_, updateErr := updateIAMAssumeRolePolicy(client, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       &roleName,
		PolicyDocument: aws.String(doc),
	})
	if wantErr == nil {
		if updateErr != nil {
			return fmt.Errorf("UpdateAssumeRolePolicy: %w", updateErr)
		}
		return nil
	}
	return checkIAMApiErr(updateErr, wantErr)
}
