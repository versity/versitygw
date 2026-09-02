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

// IAMListAccessKeys_missing_user_name calls as root, which is a configured
// credential rather than a stored IAM user and so has no user name to infer
// — unlike a caller signing with an IAM user's own access key, covered by
// IAMListAccessKeys_infers_caller_user_name.
func IAMListAccessKeys_missing_user_name(s *S3Conf) error {
	testName := "IAMListAccessKeys_missing_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{})
		return checkIAMApiErr(err, iamerr.MustSpecifyUserName())
	})
}

// IAMListAccessKeys_infers_caller_user_name also covers the scoping the
// other inferred-user-name tests assert through a NoSuchEntity: a listing
// with no UserName returns the caller's own keys and only those, so a
// second user's key must not appear in it.
func IAMListAccessKeys_infers_caller_user_name(s *S3Conf) error {
	testName := "IAMListAccessKeys_infers_caller_user_name"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newAccessKeyCaller(root, s, "iam:ListAccessKeys")
		if err != nil {
			return err
		}
		defer cleanup()

		if _, err := createIAMAccessKey(root, &iam.CreateAccessKeyInput{UserName: &caller.userName}); err != nil {
			return err
		}

		otherName := newIAMUserName()
		if _, err := createIAMUser(root, &iam.CreateUserInput{UserName: &otherName}); err != nil {
			return err
		}
		defer deleteIAMUserAndAccessKeys(root, otherName)
		if _, err := createIAMAccessKey(root, &iam.CreateAccessKeyInput{UserName: &otherName}); err != nil {
			return err
		}

		callerKeys, err := listIAMAccessKeys(root, &iam.ListAccessKeysInput{UserName: &caller.userName})
		if err != nil {
			return err
		}
		if len(callerKeys.AccessKeyMetadata) != 2 {
			return fmt.Errorf("expected the caller to own 2 access keys, instead got %d", len(callerKeys.AccessKeyMetadata))
		}
		expected := make(map[string]iamtypes.StatusType, len(callerKeys.AccessKeyMetadata))
		for _, key := range callerKeys.AccessKeyMetadata {
			expected[aws.ToString(key.AccessKeyId)] = key.Status
		}

		out, err := listIAMAccessKeys(caller.client, &iam.ListAccessKeysInput{})
		if err != nil {
			return err
		}
		if out.IsTruncated {
			return fmt.Errorf("expected ListAccessKeys not to be truncated")
		}
		return checkIAMListAccessKeys(out.AccessKeyMetadata, caller.userName, expected)
	})
}

func IAMListAccessKeys_invalid_user_name(s *S3Conf) error {
	testName := "IAMListAccessKeys_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{
			UserName: aws.String("invalid/user"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMListAccessKeys_long_user_name(s *S3Conf) error {
	testName := "IAMListAccessKeys_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{
			UserName: aws.String(strings.Repeat("a", 129)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMListAccessKeys_invalid_max_items(s *S3Conf) error {
	testName := "IAMListAccessKeys_invalid_max_items"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		for maxItems, expected := range map[int32]iamerr.Error{
			-1:   iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			0:    iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			1001: iamerr.GetAPIError(iamerr.ErrMaxItemsTooHigh),
		} {
			_, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{
				UserName: &userName,
				MaxItems: aws.Int32(maxItems),
			})
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("MaxItems %d: %w", maxItems, checkErr)
			}
		}
		return nil
	})
}

func IAMListAccessKeys_invalid_max_items_format(s *S3Conf) error {
	testName := "IAMListAccessKeys_invalid_max_items_format"
	body := []byte(url.Values{
		"Action":   {"ListAccessKeys"},
		"Version":  {"2010-05-08"},
		"UserName": {"validusername"},
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
		return checkIAMAuthRequest(s, req, iamerr.MalformedInput())
	})
}

func IAMListAccessKeys_non_existing_user(s *S3Conf) error {
	testName := "IAMListAccessKeys_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{UserName: &userName})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMListAccessKeys_empty_result(s *S3Conf) error {
	testName := "IAMListAccessKeys_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			out, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{UserName: &userName})
			if err != nil {
				return err
			}
			if err := checkIAMListAccessKeysOutput(out); err != nil {
				return err
			}
			if len(out.AccessKeyMetadata) != 0 {
				return fmt.Errorf("expected no access keys, instead got %d", len(out.AccessKeyMetadata))
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
			}
			return nil
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListAccessKeys_success(s *S3Conf) error {
	testName := "IAMListAccessKeys_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			expected := map[string]iamtypes.StatusType{}
			for range 2 {
				created, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
				if err != nil {
					return err
				}
				expected[aws.ToString(created.AccessKey.AccessKeyId)] = iamtypes.StatusTypeActive
			}

			first, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{UserName: &userName})
			if err != nil {
				return err
			}
			second, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{UserName: &userName})
			if err != nil {
				return err
			}
			if err := checkIAMListAccessKeysOutput(first); err != nil {
				return err
			}
			if err := checkIAMListAccessKeys(first.AccessKeyMetadata, userName, expected); err != nil {
				return err
			}
			if !reflect.DeepEqual(iamListAccessKeyIDs(first.AccessKeyMetadata), iamListAccessKeyIDs(second.AccessKeyMetadata)) {
				return fmt.Errorf("expected consistent results across calls")
			}
			return nil
		}()

		deleteErr := deleteIAMUserAndAccessKeys(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListAccessKeys_pagination(s *S3Conf) error {
	testName := "IAMListAccessKeys_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			expected := map[string]iamtypes.StatusType{}
			for range 2 {
				created, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
				if err != nil {
					return err
				}
				expected[aws.ToString(created.AccessKey.AccessKeyId)] = iamtypes.StatusTypeActive
			}

			input := iam.ListAccessKeysInput{UserName: &userName, MaxItems: aws.Int32(1)}
			firstPages, err := collectIAMListAccessKeyPages(client, input)
			if err != nil {
				return err
			}
			secondPages, err := collectIAMListAccessKeyPages(client, input)
			if err != nil {
				return err
			}
			if len(firstPages) != 2 {
				return fmt.Errorf("expected 2 pages, instead got %d", len(firstPages))
			}
			var allKeys []iamtypes.AccessKeyMetadata
			for i, page := range firstPages {
				if len(page.AccessKeyMetadata) != 1 {
					return fmt.Errorf("expected page %d to contain 1 access key, instead got %d", i+1, len(page.AccessKeyMetadata))
				}
				if page.IsTruncated != (i < len(firstPages)-1) {
					return fmt.Errorf("unexpected IsTruncated value on page %d", i+1)
				}
				allKeys = append(allKeys, page.AccessKeyMetadata...)
			}
			if err := checkIAMListAccessKeys(allKeys, userName, expected); err != nil {
				return err
			}

			var firstIDs, secondIDs [][]string
			for _, page := range firstPages {
				firstIDs = append(firstIDs, append([]string{fmt.Sprint(page.IsTruncated), aws.ToString(page.Marker)}, iamListAccessKeyIDs(page.AccessKeyMetadata)...))
			}
			for _, page := range secondPages {
				secondIDs = append(secondIDs, append([]string{fmt.Sprint(page.IsTruncated), aws.ToString(page.Marker)}, iamListAccessKeyIDs(page.AccessKeyMetadata)...))
			}
			if !reflect.DeepEqual(firstIDs, secondIDs) {
				return fmt.Errorf("expected consistent pagination results")
			}

			return nil
		}()

		deleteErr := deleteIAMUserAndAccessKeys(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func listIAMAccessKeys(client *iam.Client, input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListAccessKeys(ctx, input)
}

func collectIAMListAccessKeyPages(client *iam.Client, input iam.ListAccessKeysInput) ([]*iam.ListAccessKeysOutput, error) {
	var pages []*iam.ListAccessKeysOutput
	for {
		out, err := listIAMAccessKeys(client, &input)
		if err != nil {
			return nil, err
		}
		if err := checkIAMListAccessKeysOutput(out); err != nil {
			return nil, err
		}
		pages = append(pages, out)
		if !out.IsTruncated {
			return pages, nil
		}
		input.Marker = out.Marker
	}
}

func checkIAMListAccessKeysOutput(out *iam.ListAccessKeysOutput) error {
	if out == nil {
		return fmt.Errorf("expected ListAccessKeys output")
	}
	if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
		return fmt.Errorf("expected ListAccessKeys response request id")
	}
	if out.IsTruncated != (out.Marker != nil && aws.ToString(out.Marker) != "") {
		return fmt.Errorf("expected marker only when ListAccessKeys output is truncated")
	}
	for _, key := range out.AccessKeyMetadata {
		if aws.ToString(key.UserName) == "" || aws.ToString(key.AccessKeyId) == "" || key.CreateDate == nil || key.CreateDate.IsZero() {
			return fmt.Errorf("expected all required fields for listed access key, instead got %#v", key)
		}
		if !integrationIAMAccessKeyIDPattern.MatchString(aws.ToString(key.AccessKeyId)) {
			return fmt.Errorf("expected AWS IAM access key id, instead got %q", aws.ToString(key.AccessKeyId))
		}
	}
	return nil
}

func checkIAMListAccessKeys(keys []iamtypes.AccessKeyMetadata, userName string, expected map[string]iamtypes.StatusType) error {
	if len(keys) != len(expected) {
		return fmt.Errorf("expected %d access keys, instead got %d: %v", len(expected), len(keys), iamListAccessKeyIDs(keys))
	}
	ids := iamListAccessKeyIDs(keys)
	if !sort.StringsAreSorted(ids) {
		return fmt.Errorf("expected access keys sorted by access key id, instead got %v", ids)
	}
	for _, key := range keys {
		id := aws.ToString(key.AccessKeyId)
		status, ok := expected[id]
		if !ok {
			return fmt.Errorf("unexpected listed access key %q", id)
		}
		if aws.ToString(key.UserName) != userName {
			return fmt.Errorf("expected access key %q user name %q, instead got %q", id, userName, aws.ToString(key.UserName))
		}
		if key.Status != status {
			return fmt.Errorf("expected access key %q status %q, instead got %q", id, status, key.Status)
		}
	}
	return nil
}

func iamListAccessKeyIDs(keys []iamtypes.AccessKeyMetadata) []string {
	ids := make([]string, len(keys))
	for i, key := range keys {
		ids[i] = aws.ToString(key.AccessKeyId)
	}
	return ids
}
