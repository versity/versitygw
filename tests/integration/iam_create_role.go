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
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/policy"
)

// validTrustPolicyDocument is a minimal role trust policy accepted by
// ParseTrust: any principal may assume the role via sts:AssumeRole.
const validTrustPolicyDocument = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`

var integrationIAMRoleIDPattern = regexp.MustCompile(`^AROA[A-Z2-7]{17}$`)

func IAMCreateRole_missing_role_name(s *S3Conf) error {
	testName := "IAMCreateRole_missing_role_name"
	body := []byte(url.Values{
		"Action":                   {"CreateRole"},
		"Version":                  {"2010-05-08"},
		"AssumeRolePolicyDocument": {validTrustPolicyDocument},
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

func IAMCreateRole_invalid_role_name(s *S3Conf) error {
	testName := "IAMCreateRole_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String("invalid/role"),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMCreateRole_long_role_name(s *S3Conf) error {
	testName := "IAMCreateRole_long_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(strings.Repeat("a", 65)),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 64))
	})
}

func IAMCreateRole_already_exists(s *S3Conf) error {
	testName := "IAMCreateRole_already_exists"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		})
		checkErr := checkIAMApiErr(err, iamerr.EntityAlreadyExistsRole(roleName))
		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateRole_already_exists_case_insensitive(s *S3Conf) error {
	testName := "IAMCreateRole_already_exists_case_insensitive"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		upperName := strings.ToUpper(roleName)
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &upperName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		})
		checkErr := checkIAMApiErr(err, iamerr.EntityAlreadyExistsRole(upperName))
		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateRole_invalid_path(s *S3Conf) error {
	testName := "IAMCreateRole_invalid_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Path:                     aws.String("invalid"),
		})
		return checkIAMApiErr(err, iamerr.InvalidPath("path"))
	})
}

func IAMCreateRole_long_path(s *S3Conf) error {
	testName := "IAMCreateRole_long_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Path:                     aws.String("/" + strings.Repeat("a", 511) + "/"),
		})
		return checkIAMApiErr(err, iamerr.PathTooLong("path", 512))
	})
}

func IAMCreateRole_missing_assume_role_policy_document(s *S3Conf) error {
	testName := "IAMCreateRole_missing_assume_role_policy_document"
	body := []byte(url.Values{
		"Action":   {"CreateRole"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("assumeRolePolicyDocument"))
	})
}

func IAMCreateRole_non_ascii_assume_role_policy_document(s *S3Conf) error {
	testName := "IAMCreateRole_non_ascii_assume_role_policy_document"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String("emoji\U0001F600test"),
		})
		return checkIAMApiErr(err, iamerr.InvalidCharset("assumeRolePolicyDocument"))
	})
}

func IAMCreateRole_trust_policy_size_limit_exceeded(s *S3Conf) error {
	testName := "IAMCreateRole_trust_policy_size_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		oversized := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 2000) + `","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(oversized),
		})
		return checkIAMApiErr(err, iamerr.TrustPolicySizeLimitExceeded(policy.MaxTrustPolicyBytes))
	})
}

func IAMCreateRole_description_invalid_charset(s *S3Conf) error {
	testName := "IAMCreateRole_description_invalid_charset"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Description:              aws.String("emoji\U0001F600test"),
		})
		return checkIAMApiErr(err, iamerr.InvalidDescriptionCharset("description"))
	})
}

func IAMCreateRole_description_too_long(s *S3Conf) error {
	testName := "IAMCreateRole_description_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Description:              aws.String(strings.Repeat("a", 1001)),
		})
		return checkIAMApiErr(err, iamerr.ValueTooLong("description", 1000))
	})
}

func IAMCreateRole_max_session_duration_invalid_format(s *S3Conf) error {
	testName := "IAMCreateRole_max_session_duration_invalid_format"
	body := []byte(url.Values{
		"Action":                   {"CreateRole"},
		"Version":                  {"2010-05-08"},
		"RoleName":                 {newIAMRoleName()},
		"AssumeRolePolicyDocument": {validTrustPolicyDocument},
		"MaxSessionDuration":       {"not-a-number"},
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
		return checkIAMAuthRequest(s, req, iamerr.MalformedInput())
	})
}

func IAMCreateRole_max_session_duration_too_low(s *S3Conf) error {
	testName := "IAMCreateRole_max_session_duration_too_low"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			MaxSessionDuration:       aws.Int32(3599),
		})
		return checkIAMApiErr(err, iamerr.MaxSessionDurationTooLow())
	})
}

func IAMCreateRole_max_session_duration_too_high(s *S3Conf) error {
	testName := "IAMCreateRole_max_session_duration_too_high"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			MaxSessionDuration:       aws.Int32(43201),
		})
		return checkIAMApiErr(err, iamerr.MaxSessionDurationTooHigh())
	})
}

func IAMCreateRole_duplicate_tag_keys(s *S3Conf) error {
	testName := "IAMCreateRole_duplicate_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 aws.String(newIAMRoleName()),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Tags: []iamtypes.Tag{
				{Key: aws.String("key"), Value: aws.String("one")},
				{Key: aws.String("KEY"), Value: aws.String("two")},
			},
		})
		return checkIAMApiErr(err, iamerr.InvalidInput("Duplicate tag keys found. Please note that Tag keys are case insensitive."))
	})
}

func IAMCreateRole_success(s *S3Conf) error {
	testName := "IAMCreateRole_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		out, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			Path:                     aws.String("/engineering/"),
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
			Description:              aws.String("a test role"),
			MaxSessionDuration:       aws.Int32(7200),
			Tags: []iamtypes.Tag{
				{Key: aws.String("env"), Value: aws.String("test")},
			},
		})
		if err != nil {
			return err
		}

		checkErr := checkCreateRoleOutput(out, roleName, "/engineering/", "a test role", 7200, validTrustPolicyDocument, true)
		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateRole_defaults(s *S3Conf) error {
	testName := "IAMCreateRole_defaults"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		out, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		})
		if err != nil {
			return err
		}

		checkErr := checkCreateRoleOutput(out, roleName, "/", "", 3600, validTrustPolicyDocument, false)
		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateRole_trust_policy_document_grammar(s *S3Conf) error {
	testName := "IAMCreateRole_trust_policy_document_grammar"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, tt := range trustPolicyGrammarCases {
			if err := checkCreateRoleTrustPolicyCase(client, tt.doc, tt.wantErr); err != nil {
				return fmt.Errorf("%s: %w", tt.name, err)
			}
		}
		return nil
	})
}

// checkCreateRoleTrustPolicyCase verifies doc is accepted/rejected as
// expected when used as a fresh role's AssumeRolePolicyDocument.
func checkCreateRoleTrustPolicyCase(client *iam.Client, doc string, wantErr iamerr.APIError) error {
	roleName := newIAMRoleName()
	_, err := createIAMRole(client, &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: aws.String(doc),
	})
	if wantErr == nil {
		if err != nil {
			return fmt.Errorf("CreateRole: %w", err)
		}
		return deleteIAMRole(client, roleName)
	}
	return checkIAMApiErr(err, wantErr)
}

func createIAMRole(client *iam.Client, input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.CreateRole(ctx, input)
}

func newIAMRoleName() string {
	return "create-role-" + genRandString(16)
}

// checkCreateRoleOutput verifies the fields of a CreateRoleOutput-shaped role.
func checkCreateRoleOutput(out *iam.CreateRoleOutput, roleName, path, description string, maxSessionDuration int32, wantDocument string, expectTags bool) error {
	if out == nil {
		return fmt.Errorf("expected CreateRole output role")
	}
	requestID, hasRequestID := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	return checkRoleFields("CreateRole", out.Role, roleName, path, description, maxSessionDuration, wantDocument, expectTags, requestID, hasRequestID)
}

func checkRoleFields(operation string, role *iamtypes.Role, roleName, path, description string, maxSessionDuration int32, wantDocument string, expectTags bool, requestID string, hasRequestID bool) error {
	if role == nil {
		return fmt.Errorf("expected %s output role", operation)
	}
	if aws.ToString(role.Path) != path {
		return fmt.Errorf("expected role path to be %q, instead got %q", path, aws.ToString(role.Path))
	}
	if aws.ToString(role.RoleName) != roleName {
		return fmt.Errorf("expected role name to be %q, instead got %q", roleName, aws.ToString(role.RoleName))
	}
	expectedARN := "arn:aws:iam::000000000000:role" + path + roleName
	if aws.ToString(role.Arn) != expectedARN {
		return fmt.Errorf("expected role ARN to be %q, instead got %q", expectedARN, aws.ToString(role.Arn))
	}
	if !integrationIAMRoleIDPattern.MatchString(aws.ToString(role.RoleId)) {
		return fmt.Errorf("expected AWS IAM role id, instead got %q", aws.ToString(role.RoleId))
	}
	if role.CreateDate == nil || role.CreateDate.IsZero() {
		return fmt.Errorf("expected role create date")
	}
	if aws.ToString(role.Description) != description {
		return fmt.Errorf("expected role description to be %q, instead got %q", description, aws.ToString(role.Description))
	}
	if aws.ToInt32(role.MaxSessionDuration) != maxSessionDuration {
		return fmt.Errorf("expected role max session duration to be %d, instead got %d", maxSessionDuration, aws.ToInt32(role.MaxSessionDuration))
	}
	gotDocument, err := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))
	if err != nil {
		return fmt.Errorf("failed to url-decode assume role policy document %q: %w", aws.ToString(role.AssumeRolePolicyDocument), err)
	}
	if gotDocument != wantDocument {
		return fmt.Errorf("expected assume role policy document %q, instead got %q", wantDocument, gotDocument)
	}
	if role.RoleLastUsed == nil {
		return fmt.Errorf("expected role RoleLastUsed to be non-nil (empty element)")
	}
	if expectTags {
		if len(role.Tags) != 1 || aws.ToString(role.Tags[0].Key) != "env" || aws.ToString(role.Tags[0].Value) != "test" {
			return fmt.Errorf("expected role tag env=test, instead got %#v", role.Tags)
		}
	} else if len(role.Tags) != 0 {
		return fmt.Errorf("expected no role tags, instead got %#v", role.Tags)
	}
	if !hasRequestID || requestID == "" {
		return fmt.Errorf("expected %s response request id", operation)
	}

	return nil
}
