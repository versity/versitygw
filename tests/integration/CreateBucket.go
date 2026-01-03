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
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func CreateBucket_invalid_bucket_name(s *S3Conf) error {
	testName := "CreateBucket_invalid_bucket_name"
	runF(testName)
	err := setup(s, "aa")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(s, ".gitignore")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(s, "my-bucket.")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(s, "bucket-%")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	passF(testName)
	return nil
}

func CreateBucket_as_user(s *S3Conf) error {
	testName := "CreateBucket_as_user"
	runF(testName)

	testuser := getUser("user")
	cfg := *s
	cfg.awsID = testuser.access
	cfg.awsSecret = testuser.secret
	err := createUsers(s, []user{testuser})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(&cfg, getBucketName())
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_existing_bucket(s *S3Conf) error {
	testName := "CreateBucket_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	adminUser := getUser("admin")
	if err := createUsers(s, []user{adminUser}); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	adminCfg := *s
	adminCfg.awsID = adminUser.access
	adminCfg.awsSecret = adminUser.secret

	err := setup(&adminCfg, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	err = setup(s, bucket)
	var bne *types.BucketAlreadyExists
	if !errors.As(err, &bne) {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	passF(testName)
	return nil
}

func CreateBucket_owned_by_you(s *S3Conf) error {
	testName := "CreateBucket_owned_by_you"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
		})
		cancel()
		var bErr *types.BucketAlreadyOwnedByYou
		if !errors.As(err, &bErr) {
			return fmt.Errorf("expected error to be %w, instead got %w", s3err.GetAPIError(s3err.ErrBucketAlreadyOwnedByYou), err)
		}

		return nil
	})
}

func CreateBucket_invalid_ownership(s *S3Conf) error {
	testName := "CreateBucket_invalid_ownership"
	runF(testName)

	invalidOwnership := types.ObjectOwnership("invalid_ownership")
	err := setup(s, getBucketName(), withOwnership(invalidOwnership))
	if err := checkApiErr(err, s3err.APIError{
		Code:           "InvalidArgument",
		Description:    fmt.Sprintf("Invalid x-amz-object-ownership header: %v", invalidOwnership),
		HTTPStatusCode: http.StatusBadRequest,
	}); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_ownership_with_acl(s *S3Conf) error {
	testName := "CreateBucket_ownership_with_acl"

	runF(testName)
	client := s.GetClient()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:          getPtr(getBucketName()),
		ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
		ACL:             types.BucketCannedACLPublicRead,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketAclWithObjectOwnership)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_default_acl(s *S3Conf) error {
	testName := "CreateBucket_default_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if len(out.Grants) != 1 {
			return fmt.Errorf("expected grants length to be 1, instead got %v",
				len(out.Grants))
		}
		grt := out.Grants[0]
		if grt.Permission != types.PermissionFullControl {
			return fmt.Errorf("expected the grantee to have full-control permission, instead got %v",
				grt.Permission)
		}
		if getString(grt.Grantee.ID) != s.awsID {
			return fmt.Errorf("expected the grantee id to be %v, instead got %v",
				s.awsID, getString(grt.Grantee.ID))
		}

		return nil
	})
}

func CreateBucket_non_default_acl(s *S3Conf) error {
	testName := "CreateBucket_non_default_acl"
	runF(testName)

	testuser1, testuser2, testuser3 := getUser("user"), getUser("user"), getUser("user")
	err := createUsers(s, []user{testuser1, testuser2, testuser3})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	grants := []types.Grant{
		{
			Grantee: &types.Grantee{
				ID:   &s.awsID,
				Type: types.TypeCanonicalUser,
			},
			Permission: types.PermissionFullControl,
		},
		{
			Grantee: &types.Grantee{
				ID:   &testuser1.access,
				Type: types.TypeCanonicalUser,
			},
			Permission: types.PermissionFullControl,
		},
		{
			Grantee: &types.Grantee{
				ID:   &testuser2.access,
				Type: types.TypeCanonicalUser,
			},
			Permission: types.PermissionReadAcp,
		},
		{
			Grantee: &types.Grantee{
				ID:   &testuser3.access,
				Type: types.TypeCanonicalUser,
			},
			Permission: types.PermissionWrite,
		},
	}

	bucket := getBucketName()
	client := s.GetClient()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:           &bucket,
		GrantFullControl: &testuser1.access,
		GrantReadACP:     &testuser2.access,
		GrantWrite:       &testuser3.access,
		ObjectOwnership:  types.ObjectOwnershipBucketOwnerPreferred,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if !compareGrants(out.Grants, grants) {
		failF("%v: expected bucket acl grants to be %v, instead got %v", testName, grants, out.Grants)
		return fmt.Errorf("%v: expected bucket acl grants to be %v, instead got %v", testName, grants, out.Grants)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_default_object_lock(s *S3Conf) error {
	testName := "CreateBucket_default_object_lock"
	runF(testName)

	bucket := getBucketName()
	lockEnabled := true

	client := s.GetClient()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectLockEnabledForBucket: &lockEnabled,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	resp, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: &bucket,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if resp.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		failF("%v: expected object lock to be enabled", testName)
		return fmt.Errorf("%v: expected object lock to be enabled", testName)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_invalid_location_constraint(s *S3Conf) error {
	testName := "CreateBucket_invalid_location_constraint"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		var region types.BucketLocationConstraint
		if types.BucketLocationConstraint(s.awsID) == types.BucketLocationConstraintUsWest1 {
			region = types.BucketLocationConstraintUsWest2
		} else {
			region = types.BucketLocationConstraintUsWest1
		}

		createBucket := func(region types.BucketLocationConstraint) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
				Bucket: &bucket,
				CreateBucketConfiguration: &types.CreateBucketConfiguration{
					LocationConstraint: region,
				},
			})
			cancel()

			return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLocationConstraint))
		}

		for _, lConstraint := range []types.BucketLocationConstraint{region, "us-east-1"} {
			err := createBucket(lConstraint)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func CreateBucket_long_tags(s *S3Conf) error {
	testName := "CreateBucket_long_tags"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := []types.Tag{{Key: getPtr(genRandString(200)), Value: getPtr("val")}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
			CreateBucketConfiguration: &types.CreateBucketConfiguration{
				Tags: tagging,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagKey)); err != nil {
			return err
		}

		tagging = []types.Tag{{Key: getPtr("key"), Value: getPtr(genRandString(300))}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
			CreateBucketConfiguration: &types.CreateBucketConfiguration{
				Tags: tagging,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagValue)); err != nil {
			return err
		}

		return nil
	})
}

func CreateBucket_invalid_tags(s *S3Conf) error {
	testName := "CreateBucket_invalid_tags"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, test := range []struct {
			tags []types.Tag
			err  s3err.APIError
		}{
			// invalid tag key tests
			{[]types.Tag{{Key: getPtr("user!name"), Value: getPtr("value")}}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{[]types.Tag{{Key: getPtr("foo#bar"), Value: getPtr("value")}}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{[]types.Tag{
				{Key: getPtr("validkey"), Value: getPtr("validvalue")},
				{Key: getPtr("data%20"), Value: getPtr("value")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{[]types.Tag{
				{Key: getPtr("abcd"), Value: getPtr("xyz123")},
				{Key: getPtr("a*b"), Value: getPtr("value")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			// invalid tag value tests
			{[]types.Tag{
				{Key: getPtr("hello"), Value: getPtr("world")},
				{Key: getPtr("key"), Value: getPtr("name?test")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{
				{Key: getPtr("foo"), Value: getPtr("bar")},
				{Key: getPtr("key"), Value: getPtr("`path")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{{Key: getPtr("valid"), Value: getPtr("comma,separated")}}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{{Key: getPtr("valid"), Value: getPtr("semicolon;test")}}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{{Key: getPtr("valid"), Value: getPtr("(parentheses)")}}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
				Bucket: &bucket,
				CreateBucketConfiguration: &types.CreateBucketConfiguration{
					Tags: test.tags,
				},
			})
			cancel()
			if err == nil {
				return fmt.Errorf("test %v failed: expected err %w, instead got nil", i+1, test.err)
			}

			if err := checkApiErr(err, test.err); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func CreateBucket_duplicate_keys(s *S3Conf) error {
	testName := "CreateBucket_duplicate_keys"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := []types.Tag{
			{Key: getPtr("key"), Value: getPtr("value")},
			{Key: getPtr("key"), Value: getPtr("value-1")},
			{Key: getPtr("key-1"), Value: getPtr("value-2")},
			{Key: getPtr("key-2"), Value: getPtr("value-3")},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
			CreateBucketConfiguration: &types.CreateBucketConfiguration{
				Tags: tagging,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDuplicateTagKey)); err != nil {
			return err
		}

		return nil
	})
}

func CreateBucket_tag_count_limit(s *S3Conf) error {
	testName := "CreateBucket_tag_count_limit"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		tagSet := []types.Tag{}

		for i := range 51 {
			tagSet = append(tagSet, types.Tag{
				Key:   getPtr(fmt.Sprintf("key-%v", i)),
				Value: getPtr(genRandString(10)),
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
			CreateBucketConfiguration: &types.CreateBucketConfiguration{
				Tags: tagSet,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketTaggingLimited))
	})
}

func CreateBucket_invalid_canned_acl(s *S3Conf) error {
	testName := "CreateBucket_invalid_canned_acl"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACL("invalid_acl"),
		})
		cancel()
		return checkSdkApiErr(err, "InvalidArgument")
	})
}
