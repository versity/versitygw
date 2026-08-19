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

func IAMListUsers_invalid_path_prefix(s *S3Conf) error {
	testName := "IAMListUsers_invalid_path_prefix"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		expected := iamerr.ValidationError("The specified value for pathPrefix is invalid. It must begin with the / character and contain only alphanumeric characters and/or / characters.")
		for _, pathPrefix := range []string{"invalid", "/invalid\n"} {
			_, err := listIAMUsers(client, &iam.ListUsersInput{PathPrefix: aws.String(pathPrefix)})
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("PathPrefix %q: %w", pathPrefix, checkErr)
			}
		}
		return nil
	})
}

func IAMListUsers_long_path_prefix(s *S3Conf) error {
	testName := "IAMListUsers_long_path_prefix"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		pathPrefix := "/" + strings.Repeat("a", 512)
		_, err := listIAMUsers(client, &iam.ListUsersInput{PathPrefix: &pathPrefix})
		return checkIAMApiErr(err, iamerr.ValidationError("The specified value for pathPrefix is invalid. It must begin with the / character and contain only alphanumeric characters and/or / characters."))
	})
}

func IAMListUsers_invalid_max_items(s *S3Conf) error {
	testName := "IAMListUsers_invalid_max_items"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, maxItems := range []int32{-1, 0, 1001} {
			_, err := listIAMUsers(client, &iam.ListUsersInput{MaxItems: aws.Int32(maxItems)})
			expected := iamerr.ValidationError(fmt.Sprintf("1 validation error detected: Value '%d' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000", maxItems))
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("MaxItems %d: %w", maxItems, checkErr)
			}
		}
		return nil
	})
}

func IAMListUsers_invalid_max_items_format(s *S3Conf) error {
	testName := "IAMListUsers_invalid_max_items_format"
	body := []byte(url.Values{
		"Action":   {"ListUsers"},
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

func IAMListUsers_empty_result(s *S3Conf) error {
	testName := "IAMListUsers_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		pathPrefix := "/list-users-" + genRandString(16) + "/"
		input := &iam.ListUsersInput{PathPrefix: &pathPrefix}
		first, err := listIAMUsers(client, input)
		if err != nil {
			return err
		}
		second, err := listIAMUsers(client, input)
		if err != nil {
			return err
		}
		if err := checkIAMListUsersOutput(first); err != nil {
			return err
		}
		if err := checkIAMListUsersOutput(second); err != nil {
			return err
		}
		if len(first.Users) != 0 || len(second.Users) != 0 {
			return fmt.Errorf("expected consistent empty results, instead got %v and %v", iamListUserNames(first.Users), iamListUserNames(second.Users))
		}
		return nil
	})
}

func IAMListUsers_success(s *S3Conf) error {
	testName := "IAMListUsers_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		path := "/list-users-" + genRandString(16) + "/"
		users := map[string]string{"list-users-" + genRandString(16): path}
		return withIAMListUsers(client, users, func() error {
			out, err := listIAMUsers(client, &iam.ListUsersInput{PathPrefix: &path})
			if err != nil {
				return err
			}
			if err := checkIAMListUsersOutput(out); err != nil {
				return err
			}
			return checkIAMListUsers(out.Users, users)
		})
	})
}

func IAMListUsers_path_prefix(s *S3Conf) error {
	testName := "IAMListUsers_path_prefix"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		basePath := "/list-users-" + genRandString(16) + "/"
		engineeringPath := basePath + "engineering/"
		namePrefix := "list-users-" + genRandString(8)
		users := map[string]string{
			namePrefix + "-root": basePath,
			namePrefix + "-z":    engineeringPath,
			namePrefix + "-a":    engineeringPath + "platform/",
			namePrefix + "-ops":  basePath + "operations/",
		}
		expected := map[string]string{
			namePrefix + "-a": engineeringPath + "platform/",
			namePrefix + "-z": engineeringPath,
		}
		return withIAMListUsers(client, users, func() error {
			input := &iam.ListUsersInput{PathPrefix: &engineeringPath}
			first, err := listIAMUsers(client, input)
			if err != nil {
				return err
			}
			second, err := listIAMUsers(client, input)
			if err != nil {
				return err
			}
			if err := checkIAMListUsersOutput(first); err != nil {
				return err
			}
			if err := checkIAMListUsers(first.Users, expected); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListUserNames(first.Users), iamListUserNames(second.Users)) {
				return fmt.Errorf("expected consistent results, instead got %v and %v", iamListUserNames(first.Users), iamListUserNames(second.Users))
			}
			return nil
		})
	})
}

func IAMListUsers_pagination(s *S3Conf) error {
	testName := "IAMListUsers_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		path := "/list-users-" + genRandString(16) + "/"
		users := make(map[string]string, 5)
		for range 5 {
			users["list-users-"+genRandString(16)] = path
		}
		return withIAMListUsers(client, users, func() error {
			input := iam.ListUsersInput{PathPrefix: &path, MaxItems: aws.Int32(2)}
			firstPages, err := collectIAMListUserPages(client, input)
			if err != nil {
				return err
			}
			secondPages, err := collectIAMListUserPages(client, input)
			if err != nil {
				return err
			}
			if err := checkIAMListUserPages(firstPages, []int{2, 2, 1}, users); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListUserPageValues(firstPages), iamListUserPageValues(secondPages)) {
				return fmt.Errorf("expected consistent pagination results")
			}
			return nil
		})
	})
}

func IAMListUsers_path_prefix_pagination(s *S3Conf) error {
	testName := "IAMListUsers_path_prefix_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		basePath := "/list-users-" + genRandString(16) + "/"
		matchingPath := basePath + "engineering/"
		namePrefix := "list-users-" + genRandString(8)
		users := map[string]string{
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
		return withIAMListUsers(client, users, func() error {
			input := iam.ListUsersInput{PathPrefix: &matchingPath, MaxItems: aws.Int32(2)}
			firstPages, err := collectIAMListUserPages(client, input)
			if err != nil {
				return err
			}
			secondPages, err := collectIAMListUserPages(client, input)
			if err != nil {
				return err
			}
			if err := checkIAMListUserPages(firstPages, []int{2, 2, 1}, expected); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListUserPageValues(firstPages), iamListUserPageValues(secondPages)) {
				return fmt.Errorf("expected consistent filtered pagination results")
			}
			return nil
		})
	})
}

func listIAMUsers(client *iam.Client, input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListUsers(ctx, input)
}

func withIAMListUsers(client *iam.Client, users map[string]string, test func() error) (err error) {
	created := make([]string, 0, len(users))
	defer func() {
		for _, name := range created {
			if deleteErr := deleteIAMUser(client, name); deleteErr != nil {
				err = errors.Join(err, fmt.Errorf("delete IAM user %q: %w", name, deleteErr))
			}
		}
	}()

	for name, path := range users {
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &name, Path: &path}); err != nil {
			return err
		}
		created = append(created, name)
	}
	return test()
}

func collectIAMListUserPages(client *iam.Client, input iam.ListUsersInput) ([]*iam.ListUsersOutput, error) {
	var pages []*iam.ListUsersOutput
	for {
		out, err := listIAMUsers(client, &input)
		if err != nil {
			return nil, err
		}
		if err := checkIAMListUsersOutput(out); err != nil {
			return nil, err
		}
		pages = append(pages, out)
		if !out.IsTruncated {
			return pages, nil
		}
		input.Marker = out.Marker
	}
}

func checkIAMListUsersOutput(out *iam.ListUsersOutput) error {
	if out == nil {
		return fmt.Errorf("expected ListUsers output")
	}
	if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
		return fmt.Errorf("expected ListUsers response request id")
	}
	if out.IsTruncated != (out.Marker != nil && aws.ToString(out.Marker) != "") {
		return fmt.Errorf("expected marker only when ListUsers output is truncated")
	}
	for _, user := range out.Users {
		if aws.ToString(user.Path) == "" || aws.ToString(user.UserName) == "" || aws.ToString(user.UserId) == "" || aws.ToString(user.Arn) == "" || user.CreateDate == nil || user.CreateDate.IsZero() {
			return fmt.Errorf("expected all required fields for listed user, instead got %#v", user)
		}
		if !integrationIAMUserIDPattern.MatchString(aws.ToString(user.UserId)) {
			return fmt.Errorf("expected AWS IAM user id, instead got %q", aws.ToString(user.UserId))
		}
	}
	return nil
}

func checkIAMListUsers(users []iamtypes.User, expected map[string]string) error {
	if len(users) != len(expected) {
		return fmt.Errorf("expected %d users, instead got %d: %v", len(expected), len(users), iamListUserNames(users))
	}
	names := iamListUserNames(users)
	if !sort.StringsAreSorted(names) {
		return fmt.Errorf("expected users sorted by username, instead got %v", names)
	}
	for _, user := range users {
		name := aws.ToString(user.UserName)
		path, ok := expected[name]
		if !ok {
			return fmt.Errorf("unexpected listed user %q", name)
		}
		if aws.ToString(user.Path) != path {
			return fmt.Errorf("expected user %q path %q, instead got %q", name, path, aws.ToString(user.Path))
		}
		if want := "arn:aws:iam::000000000000:user" + path + name; aws.ToString(user.Arn) != want {
			return fmt.Errorf("expected user %q ARN %q, instead got %q", name, want, aws.ToString(user.Arn))
		}
	}
	return nil
}

func checkIAMListUserPages(pages []*iam.ListUsersOutput, sizes []int, expected map[string]string) error {
	if len(pages) != len(sizes) {
		return fmt.Errorf("expected %d pages, instead got %d", len(sizes), len(pages))
	}
	var users []iamtypes.User
	for i, page := range pages {
		if len(page.Users) != sizes[i] {
			return fmt.Errorf("expected page %d to contain %d users, instead got %d", i+1, sizes[i], len(page.Users))
		}
		if page.IsTruncated != (i < len(pages)-1) {
			return fmt.Errorf("unexpected IsTruncated value on page %d", i+1)
		}
		users = append(users, page.Users...)
	}
	return checkIAMListUsers(users, expected)
}

func iamListUserPageValues(pages []*iam.ListUsersOutput) [][]string {
	values := make([][]string, len(pages))
	for i, page := range pages {
		values[i] = append([]string{fmt.Sprint(page.IsTruncated), aws.ToString(page.Marker)}, iamListUserNames(page.Users)...)
	}
	return values
}

func iamListUserNames(users []iamtypes.User) []string {
	names := make([]string, len(users))
	for i, user := range users {
		names[i] = aws.ToString(user.UserName)
	}
	return names
}
