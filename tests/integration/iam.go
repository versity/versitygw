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

package integration

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func IAM_user_access_denied(s *S3Conf) error {
	testName := "IAM_user_access_denied"
	runF(testName)

	testuser := getUser("user")
	err := createUsers(s, []user{testuser})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	out, err := execCommand(s.getAdminCommand("-a", testuser.access, "-s", testuser.secret, "-er", s.endpoint, "delete-user", "-a", "random_access")...)
	if err == nil {
		failF("%v: expected cmd error", testName)
		return fmt.Errorf("%v: expected cmd error", testName)
	}
	if !strings.Contains(string(out), s3err.GetAPIError(s3err.ErrAdminAccessDenied).Code) {
		failF("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
		return fmt.Errorf("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
	}

	passF(testName)

	return nil
}

func IAM_userplus_access_denied(s *S3Conf) error {
	testName := "IAM_userplus_access_denied"
	runF(testName)

	testuser := getUser("userplus")
	err := createUsers(s, []user{testuser})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	out, err := execCommand(s.getAdminCommand("-a", testuser.access, "-s", testuser.secret, "-er", s.endpoint, "delete-user", "-a", "random_access")...)
	if err == nil {
		failF("%v: expected cmd error", testName)
		return fmt.Errorf("%v: expected cmd error", testName)
	}
	if !strings.Contains(string(out), s3err.GetAPIError(s3err.ErrAdminAccessDenied).Code) {
		failF("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
		return fmt.Errorf("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
	}

	passF(testName)

	return nil
}

func IAM_userplus_CreateBucket(s *S3Conf) error {
	testName := "IAM_userplus_CreateBucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("userplus")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = testuser.access
		cfg.awsSecret = testuser.secret

		bckt := getBucketName()
		err = setup(&cfg, bckt)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bckt})
		cancel()
		if err != nil {
			return err
		}

		err = teardown(&cfg, bckt)
		if err != nil {
			return err
		}

		return nil
	})
}

func IAM_admin_ChangeBucketOwner(s *S3Conf) error {
	testName := "IAM_admin_ChangeBucketOwner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser, adminuser := getUser("user"), getUser("admin")
		err := createUsers(s, []user{adminuser, testuser})
		if err != nil {
			return err
		}

		err = changeBucketsOwner(s, []string{bucket}, testuser.access)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		if getString(resp.Owner.ID) != testuser.access {
			return fmt.Errorf("expected the bucket owner to be %v, instead got %v",
				testuser.access, getString(resp.Owner.ID))
		}

		return nil
	})
}

func IAM_ChangeBucketOwner_back_to_root(s *S3Conf) error {
	testName := "IAM_ChangeBucketOwner_back_to_root"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		// Change the bucket ownership to a random user
		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		// Change the bucket ownership back to the root user
		if err := changeBucketsOwner(s, []string{bucket}, s.awsID); err != nil {
			return err
		}

		return nil
	})
}

func IAM_ListBuckets(s *S3Conf) error {
	testName := "IAM_ListBuckets"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return listBuckets(s)
	})
}

func IAM_CreateBucket_empty_owner_header(s *S3Conf) error {
	testName := "IAM_CreateBucket_empty_owner_header"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := createSignedReq(
			http.MethodPatch,
			s.endpoint,
			fmt.Sprintf("%s/create", bucket),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			nil,
			time.Now(),
			nil,
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAdminEmptyBucketOwnerHeader))
	})
}

func IAM_CreateBucket_non_existing_user(s *S3Conf) error {
	testName := "IAM_CreateBucket_non_existing_user"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := createSignedReq(
			http.MethodPatch,
			s.endpoint,
			fmt.Sprintf("%s/create", bucket),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			nil,
			time.Now(),
			map[string]string{
				"x-vgw-owner": "non-existing-user",
			},
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAdminUserNotFound))
	})
}

func IAM_CreateBucket_success(s *S3Conf) error {
	testName := "IAM_CreateBucket_success"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		tagSet := []types.Tag{
			{Key: getPtr("key"), Value: getPtr("value")},
		}
		body, err := xml.Marshal(s3response.CreateBucketConfiguration{
			TagSet: tagSet,
		})
		if err != nil {
			return err
		}

		testUser1, testUser2 := getUser("user"), getUser("user")
		err = createUsers(s, []user{testUser1, testUser2})
		if err != nil {
			return err
		}

		req, err := createSignedReq(
			http.MethodPatch,
			s.endpoint,
			fmt.Sprintf("%s/create", bucket),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			body,
			time.Now(),
			map[string]string{
				"x-amz-bucket-object-lock-enabled": "true",
				"x-amz-object-ownership":           string(types.ObjectOwnershipBucketOwnerPreferred),
				"x-amz-grant-read":                 testUser2.access,
				"x-vgw-owner":                      testUser1.access,
			},
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("expected the response status code to be %v, instead got %v", http.StatusCreated, resp.StatusCode)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		tagging, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !areTagsSame(tagSet, tagging.TagSet) {
			return fmt.Errorf("expected the bucket tagging to be %v, instead got %v", tagSet, tagging.TagSet)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		ownership, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		var ownershipControls types.ObjectOwnership
		if ownership.OwnershipControls != nil && len(ownership.OwnershipControls.Rules) == 1 {
			ownershipControls = ownership.OwnershipControls.Rules[0].ObjectOwnership
		}

		if ownershipControls != types.ObjectOwnershipBucketOwnerPreferred {
			return fmt.Errorf("expected the bucket ownership controls to be %s, instaed got %s", types.ObjectOwnershipBucketOwnerPreferred, ownershipControls)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		acl, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(acl.Grants) != 2 {
			return fmt.Errorf("expected the length of acl grants to be 2, instead got %v", len(acl.Grants))
		}

		var granteeChecked bool
		var ownerChecked bool
		for _, grant := range acl.Grants {
			// owner
			if getString(grant.Grantee.ID) == testUser1.access {
				ownerChecked = true
				if grant.Permission != types.PermissionFullControl {
					return fmt.Errorf("expected the owner '%s' to have %s permission, instead got %s", testUser1.access, types.PermissionFullControl, grant.Permission)
				}

				continue
			}

			if getString(grant.Grantee.ID) != testUser2.access {
				return fmt.Errorf("expected the grantee ID to be %v, instaed got %v", testUser2.access, getString(grant.Grantee.ID))
			}
			if grant.Permission != types.PermissionRead {
				return fmt.Errorf("expected the %v user permission to be %s, instead got %s", testUser2.access, types.PermissionRead, grant.Permission)
			}

			granteeChecked = true
		}

		if !ownerChecked {
			return fmt.Errorf("missing the owner '%s' full control acl", testUser1.access)
		}
		if !granteeChecked {
			return fmt.Errorf("missing the user %s in read grantees acl", testUser2.access)
		}

		return teardown(s, bucket)
	})
}
