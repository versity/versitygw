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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMListRoles_invalid_path_prefix(s *S3Conf) error {
	testName := "IAMListRoles_invalid_path_prefix"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		expected := iamerr.ValidationError("The specified value for pathPrefix is invalid. It must begin with the / character and contain only alphanumeric characters and/or / characters.")
		for _, pathPrefix := range []string{"invalid", "/invalid\n"} {
			_, err := listIAMRoles(client, &iam.ListRolesInput{PathPrefix: aws.String(pathPrefix)})
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("PathPrefix %q: %w", pathPrefix, checkErr)
			}
		}
		return nil
	})
}

func IAMListRoles_long_path_prefix(s *S3Conf) error {
	testName := "IAMListRoles_long_path_prefix"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		pathPrefix := "/" + strings.Repeat("a", 512)
		_, err := listIAMRoles(client, &iam.ListRolesInput{PathPrefix: &pathPrefix})
		return checkIAMApiErr(err, iamerr.ValidationError("The specified value for pathPrefix is invalid. It must begin with the / character and contain only alphanumeric characters and/or / characters."))
	})
}

func IAMListRoles_invalid_max_items(s *S3Conf) error {
	testName := "IAMListRoles_invalid_max_items"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, maxItems := range []int32{-1, 0, 1001} {
			_, err := listIAMRoles(client, &iam.ListRolesInput{MaxItems: aws.Int32(maxItems)})
			expected := iamerr.ValidationError(fmt.Sprintf("1 validation error detected: Value '%d' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000", maxItems))
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("MaxItems %d: %w", maxItems, checkErr)
			}
		}
		return nil
	})
}

func IAMListRoles_invalid_max_items_format(s *S3Conf) error {
	testName := "IAMListRoles_invalid_max_items_format"
	body := []byte(url.Values{
		"Action":   {"ListRoles"},
		"Version":  {"2010-05-08"},
		"MaxItems": {"not-a-number"},
	}.Encode())
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam",
		region:   iamAuthRegion,
		body:     body,
		date:     time.Now().UTC(),
		headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}, func(req *http.Request) error {
		expected := iamerr.ValidationError("1 validation error detected: Value 'not-a-number' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000")
		return checkIAMAuthRequest(s, req, expected)
	})
}

func IAMListRoles_empty_result(s *S3Conf) error {
	testName := "IAMListRoles_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		pathPrefix := "/list-roles-" + genRandString(16) + "/"
		input := &iam.ListRolesInput{PathPrefix: &pathPrefix}
		first, err := listIAMRoles(client, input)
		if err != nil {
			return err
		}
		second, err := listIAMRoles(client, input)
		if err != nil {
			return err
		}
		if err := checkIAMListRolesOutput(first); err != nil {
			return err
		}
		if err := checkIAMListRolesOutput(second); err != nil {
			return err
		}
		if len(first.Roles) != 0 || len(second.Roles) != 0 {
			return fmt.Errorf("expected consistent empty results, instead got %v and %v", iamListRoleNames(first.Roles), iamListRoleNames(second.Roles))
		}
		return nil
	})
}

func IAMListRoles_success(s *S3Conf) error {
	testName := "IAMListRoles_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		path := "/list-roles-" + genRandString(16) + "/"
		roles := map[string]string{"list-roles-" + genRandString(16): path}
		return withIAMListRoles(client, roles, func() error {
			out, err := listIAMRoles(client, &iam.ListRolesInput{PathPrefix: &path})
			if err != nil {
				return err
			}
			if err := checkIAMListRolesOutput(out); err != nil {
				return err
			}
			return checkIAMListRoles(out.Roles, roles)
		})
	})
}

func IAMListRoles_path_prefix(s *S3Conf) error {
	testName := "IAMListRoles_path_prefix"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		basePath := "/list-roles-" + genRandString(16) + "/"
		engineeringPath := basePath + "engineering/"
		namePrefix := "list-roles-" + genRandString(8)
		roles := map[string]string{
			namePrefix + "-root": basePath,
			namePrefix + "-z":    engineeringPath,
			namePrefix + "-a":    engineeringPath + "platform/",
			namePrefix + "-ops":  basePath + "operations/",
		}
		expected := map[string]string{
			namePrefix + "-a": engineeringPath + "platform/",
			namePrefix + "-z": engineeringPath,
		}
		return withIAMListRoles(client, roles, func() error {
			input := &iam.ListRolesInput{PathPrefix: &engineeringPath}
			first, err := listIAMRoles(client, input)
			if err != nil {
				return err
			}
			second, err := listIAMRoles(client, input)
			if err != nil {
				return err
			}
			if err := checkIAMListRolesOutput(first); err != nil {
				return err
			}
			if err := checkIAMListRoles(first.Roles, expected); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListRoleNames(first.Roles), iamListRoleNames(second.Roles)) {
				return fmt.Errorf("expected consistent results, instead got %v and %v", iamListRoleNames(first.Roles), iamListRoleNames(second.Roles))
			}
			return nil
		})
	})
}

func IAMListRoles_pagination(s *S3Conf) error {
	testName := "IAMListRoles_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		path := "/list-roles-" + genRandString(16) + "/"
		roles := make(map[string]string, 5)
		for range 5 {
			roles["list-roles-"+genRandString(16)] = path
		}
		return withIAMListRoles(client, roles, func() error {
			input := iam.ListRolesInput{PathPrefix: &path, MaxItems: aws.Int32(2)}
			firstPages, err := collectIAMListRolePages(client, input)
			if err != nil {
				return err
			}
			secondPages, err := collectIAMListRolePages(client, input)
			if err != nil {
				return err
			}
			if err := checkIAMListRolePages(firstPages, []int{2, 2, 1}, roles); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListRolePageValues(firstPages), iamListRolePageValues(secondPages)) {
				return fmt.Errorf("expected consistent pagination results")
			}
			return nil
		})
	})
}

func IAMListRoles_path_prefix_pagination(s *S3Conf) error {
	testName := "IAMListRoles_path_prefix_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		basePath := "/list-roles-" + genRandString(16) + "/"
		matchingPath := basePath + "engineering/"
		namePrefix := "list-roles-" + genRandString(8)
		roles := map[string]string{
			namePrefix + "-outside": basePath,
			namePrefix + "-e":       matchingPath,
			namePrefix + "-d":       matchingPath,
			namePrefix + "-c":       matchingPath + "platform/",
			namePrefix + "-b":       matchingPath + "storage/",
			namePrefix + "-a":       matchingPath + "storage/archive/",
			namePrefix + "-ops":     basePath + "operations/",
		}
		expected := map[string]string{
			namePrefix + "-a": matchingPath + "storage/archive/",
			namePrefix + "-b": matchingPath + "storage/",
			namePrefix + "-c": matchingPath + "platform/",
			namePrefix + "-d": matchingPath,
			namePrefix + "-e": matchingPath,
		}
		return withIAMListRoles(client, roles, func() error {
			input := iam.ListRolesInput{PathPrefix: &matchingPath, MaxItems: aws.Int32(2)}
			firstPages, err := collectIAMListRolePages(client, input)
			if err != nil {
				return err
			}
			secondPages, err := collectIAMListRolePages(client, input)
			if err != nil {
				return err
			}
			if err := checkIAMListRolePages(firstPages, []int{2, 2, 1}, expected); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListRolePageValues(firstPages), iamListRolePageValues(secondPages)) {
				return fmt.Errorf("expected consistent filtered pagination results")
			}
			return nil
		})
	})
}

func listIAMRoles(client *iam.Client, input *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListRoles(ctx, input)
}

func withIAMListRoles(client *iam.Client, roles map[string]string, test func() error) (err error) {
	created := make([]string, 0, len(roles))
	defer func() {
		for _, name := range created {
			if deleteErr := deleteIAMRole(client, name); deleteErr != nil {
				err = errors.Join(err, fmt.Errorf("delete IAM role %q: %w", name, deleteErr))
			}
		}
	}()

	for name, path := range roles {
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &name,
			Path:                     &path,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}
		created = append(created, name)
	}
	return test()
}

func collectIAMListRolePages(client *iam.Client, input iam.ListRolesInput) ([]*iam.ListRolesOutput, error) {
	var pages []*iam.ListRolesOutput
	for {
		out, err := listIAMRoles(client, &input)
		if err != nil {
			return nil, err
		}
		if err := checkIAMListRolesOutput(out); err != nil {
			return nil, err
		}
		pages = append(pages, out)
		if !out.IsTruncated {
			return pages, nil
		}
		input.Marker = out.Marker
	}
}

func checkIAMListRolesOutput(out *iam.ListRolesOutput) error {
	if out == nil {
		return fmt.Errorf("expected ListRoles output")
	}
	if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
		return fmt.Errorf("expected ListRoles response request id")
	}
	if out.IsTruncated != (out.Marker != nil && aws.ToString(out.Marker) != "") {
		return fmt.Errorf("expected marker only when ListRoles output is truncated")
	}
	for _, role := range out.Roles {
		if aws.ToString(role.Path) == "" || aws.ToString(role.RoleName) == "" || aws.ToString(role.RoleId) == "" || aws.ToString(role.Arn) == "" || role.CreateDate == nil || role.CreateDate.IsZero() {
			return fmt.Errorf("expected all required fields for listed role, instead got %#v", role)
		}
		if !integrationIAMRoleIDPattern.MatchString(aws.ToString(role.RoleId)) {
			return fmt.Errorf("expected AWS IAM role id, instead got %q", aws.ToString(role.RoleId))
		}
		if role.RoleLastUsed != nil {
			return fmt.Errorf("expected ListRoles RoleLastUsed to be nil (list/get asymmetry), instead got %#v", role.RoleLastUsed)
		}
	}
	return nil
}

func checkIAMListRoles(roles []iamtypes.Role, expected map[string]string) error {
	if len(roles) != len(expected) {
		return fmt.Errorf("expected %d roles, instead got %d: %v", len(expected), len(roles), iamListRoleNames(roles))
	}
	names := iamListRoleNames(roles)
	if !sort.StringsAreSorted(names) {
		return fmt.Errorf("expected roles sorted by role name, instead got %v", names)
	}
	for _, role := range roles {
		name := aws.ToString(role.RoleName)
		path, ok := expected[name]
		if !ok {
			return fmt.Errorf("unexpected listed role %q", name)
		}
		if aws.ToString(role.Path) != path {
			return fmt.Errorf("expected role %q path %q, instead got %q", name, path, aws.ToString(role.Path))
		}
		if want := "arn:aws:iam::000000000000:role" + path + name; aws.ToString(role.Arn) != want {
			return fmt.Errorf("expected role %q ARN %q, instead got %q", name, want, aws.ToString(role.Arn))
		}
	}
	return nil
}

func checkIAMListRolePages(pages []*iam.ListRolesOutput, sizes []int, expected map[string]string) error {
	if len(pages) != len(sizes) {
		return fmt.Errorf("expected %d pages, instead got %d", len(sizes), len(pages))
	}
	var roles []iamtypes.Role
	for i, page := range pages {
		if len(page.Roles) != sizes[i] {
			return fmt.Errorf("expected page %d to contain %d roles, instead got %d", i+1, sizes[i], len(page.Roles))
		}
		if page.IsTruncated != (i < len(pages)-1) {
			return fmt.Errorf("unexpected IsTruncated value on page %d", i+1)
		}
		roles = append(roles, page.Roles...)
	}
	return checkIAMListRoles(roles, expected)
}

func iamListRolePageValues(pages []*iam.ListRolesOutput) [][]string {
	values := make([][]string, len(pages))
	for i, page := range pages {
		values[i] = append([]string{fmt.Sprint(page.IsTruncated), aws.ToString(page.Marker)}, iamListRoleNames(page.Roles)...)
	}
	return values
}

func iamListRoleNames(roles []iamtypes.Role) []string {
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = aws.ToString(role.RoleName)
	}
	return names
}
