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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

// Access control tests (with bucket ACLs and Policies)
func AccessControl_default_ACL_user_access_denied(s *S3Conf) error {
	testName := "AccessControl_default_ACL_user_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		_, err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_default_ACL_userplus_access_denied(s *S3Conf) error {
	testName := "AccessControl_default_ACL_userplus_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("userplus")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		client := s.getUserClient(testuser)

		_, err = putObjects(client, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_default_ACL_admin_successful_access(s *S3Conf) error {
	testName := "AccessControl_default_ACL_admin_successful_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("admin")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		adminClient := s.getUserClient(testuser)

		_, err = putObjects(adminClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_bucket_resource_single_action(s *S3Conf) error {
	testName := "AccessControl_bucket_resource_single_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser1, testuser2 := getUser("user"), getUser("user")
		err := createUsers(s, []user{testuser1, testuser2})
		if err != nil {
			return err
		}

		doc := genPolicyDoc("Allow", fmt.Sprintf(`["%s"]`, testuser1.access), `"s3:PutBucketTagging"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		testuser1Client := s.getUserClient(testuser1)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = testuser1Client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = testuser1Client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		user2Client := s.getUserClient(testuser2)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user2Client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_bucket_resource_all_action(s *S3Conf) error {
	testName := "AccessControl_bucket_resource_all_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser1, testuser2 := getUser("user"), getUser("user")
		err := createUsers(s, []user{testuser1, testuser2})
		if err != nil {
			return err
		}

		bucketResource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		objectResource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)
		doc := genPolicyDoc("Allow", fmt.Sprintf(`["%s"]`, testuser1.access), `"s3:*"`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		testuser1Client := s.getUserClient(testuser1)
		_, err = putObjects(testuser1Client, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		user2Client := s.getUserClient(testuser2)

		_, err = putObjects(user2Client, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_single_object_resource_actions(s *S3Conf) error {
	testName := "AccessControl_single_object_resource_actions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj/nested-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		testuser := getUser("user")

		err = createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		doc := genPolicyDoc("Allow", fmt.Sprintf(`["%s"]`, testuser.access), `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%v/%v"`, bucket, obj))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		testuser1Client := s.getUserClient(testuser)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = testuser1Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = testuser1Client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_multi_statement_policy(s *S3Conf) error {
	testName := "AccessControl_multi_statement_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		policy := fmt.Sprintf(`{
			"Statement": [
				{
					"Effect": "Deny",
					"Principal": ["%s"],
					"Action":  "s3:DeleteBucket",
					"Resource":  "arn:aws:s3:::%s"
				},
				{
					"Effect": "Allow",
					"Principal": "%s",
					"Action": "s3:*",
					"Resource": ["arn:aws:s3:::%s", "arn:aws:s3:::%s/*"]
				}
			]
		}`, testuser.access, bucket, testuser.access, bucket, bucket)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetExplicitDenyAccessErr(
			testuser.access, "s3:DeleteBucket", fmt.Sprintf("arn:aws:s3:::%s", bucket), "a resource-based policy",
		)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_bucket_ownership_to_user(s *S3Conf) error {
	testName := "AccessControl_bucket_ownership_to_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_root_PutBucketAcl(s *S3Conf) error {
	testName := "AccessControl_root_PutBucketAcl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPrivate,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func AccessControl_user_PutBucketAcl_with_policy_access(s *S3Conf) error {
	testName := "AccessControl_user_PutBucketAcl_with_policy_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%v"`, testuser.access), `"s3:PutBucketAcl"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicRead,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedGrants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   &s.awsID,
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("all-users"),
					Type: types.TypeGroup,
				},
				Permission: types.PermissionRead,
			},
		}

		if !compareGrants(res.Grants, expectedGrants) {
			return fmt.Errorf("expected the resulting grants to be %v, instead got %v",
				expectedGrants, res.Grants)
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func AccessControl_copy_object_with_starting_slash_for_user(s *S3Conf) error {
	testName := "AccessControl_copy_object_with_starting_slash_for_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		err = createUsers(s, []user{testuser})
		if err != nil {
			return err
		}
		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		copySource := fmt.Sprintf("/%v/%v", bucket, obj)
		meta := map[string]string{
			"key1": "val1",
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        &copySource,
			Metadata:          meta,
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_policy_normalizes_object_key_for_get_put_delete(s *S3Conf) error {
	testName := "AccessControl_policy_normalizes_object_key_for_get_put_delete"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		privateKey := "private.txt"
		traversalKey := "public/../" + privateKey
		privateBody := []byte("private object body")

		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &privateKey,
			Body:   bytes.NewReader(privateBody),
		}, s3client)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access),
			`["s3:GetObject","s3:PutObject","s3:DeleteObject"]`,
			fmt.Sprintf(`"arn:aws:s3:::%s/public/*"`, bucket))
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &traversalKey,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		copySource := fmt.Sprintf("%s/%s", bucket, traversalKey)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("public/copied.txt"),
			CopySource: &copySource,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		_, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &traversalKey,
			Body:   bytes.NewReader([]byte("overwrite")),
		}, userClient)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &privateKey,
		})
		cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		gotBody, err := io.ReadAll(out.Body)
		if err != nil {
			return fmt.Errorf("read private object body: %w", err)
		}
		if !bytes.Equal(gotBody, privateBody) {
			return fmt.Errorf("expected private object body to remain %q, instead got %q", privateBody, gotBody)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &traversalKey,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &privateKey,
		})
		cancel()
		return err
	})
}

func AccessControl_PutObject_with_tagging_policy(s *S3Conf) error {
	testName := "AccessControl_PutObject_with_tagging_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)

		// Error path: user has s3:PutObject but not s3:PutObjectTagging
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:PutObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		tagging := "key=value"
		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		}, userClient)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:PutObject and s3:PutObjectTagging
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObject","s3:PutObjectTagging"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		_, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		}, userClient)
		return err
	})
}

func AccessControl_PutObject_with_legal_hold_policy(s *S3Conf) error {
	testName := "AccessControl_PutObject_with_legal_hold_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)

		// Error path: user has s3:PutObject but not s3:PutObjectLegalHold
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:PutObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		}, userClient)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:PutObject and s3:PutObjectLegalHold
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObject","s3:PutObjectLegalHold"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		_, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		}, userClient)
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, removeLegalHold: true}})
	}, withLock())
}

func AccessControl_PutObject_with_retention_policy(s *S3Conf) error {
	testName := "AccessControl_PutObject_with_retention_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)
		date := time.Now().Add(time.Hour)

		// Error path: user has s3:PutObject but not s3:PutObjectRetention
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:PutObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &date,
		}, userClient)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:PutObject and s3:PutObjectRetention
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObject","s3:PutObjectRetention"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		_, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &date,
		}, userClient)
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj}})
	}, withLock())
}

func AccessControl_CreateMultipartUpload_with_tagging_policy(s *S3Conf) error {
	testName := "AccessControl_CreateMultipartUpload_with_tagging_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)

		// Error path: user has s3:PutObject but not s3:PutObjectTagging
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:PutObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		tagging := "key=value"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:PutObject and s3:PutObjectTagging
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObject","s3:PutObjectTagging"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		})
		cancel()
		return err
	})
}

func AccessControl_CreateMultipartUpload_with_legal_hold_policy(s *S3Conf) error {
	testName := "AccessControl_CreateMultipartUpload_with_legal_hold_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)

		// Error path: user has s3:PutObject but not s3:PutObjectLegalHold
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:PutObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:PutObject and s3:PutObjectLegalHold
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObject","s3:PutObjectLegalHold"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		return err
	}, withLock())
}

func AccessControl_CreateMultipartUpload_with_retention_policy(s *S3Conf) error {
	testName := "AccessControl_CreateMultipartUpload_with_retention_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)
		date := time.Now().Add(time.Hour)

		// Error path: user has s3:PutObject but not s3:PutObjectRetention
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:PutObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &date,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:PutObject and s3:PutObjectRetention
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObject","s3:PutObjectRetention"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &date,
		})
		cancel()
		return err
	}, withLock())
}

func AccessControl_CopyObject_with_tagging_policy(s *S3Conf) error {
	testName := "AccessControl_CopyObject_with_tagging_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		dstObjectResource := fmt.Sprintf(`"arn:aws:s3:::%s/%s"`, bucket, dstObj)
		srcObjectResource := fmt.Sprintf(`"arn:aws:s3:::%s/%s"`, bucket, srcObj)

		// Error path: user has s3:PutObject, s3:GetObject but not s3:PutObjectTagging
		policy := fmt.Sprintf(`{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:GetObject",
					"Resource":  %s
				},
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:PutObject",
					"Resource":  %s
				}
			]
		}`, testuser.access, srcObjectResource, testuser.access, dstObjectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			Tagging:    getPtr("key=value"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:GetObject, s3:PutObject and s3:PutObjectTagging
		policy = fmt.Sprintf(`{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:GetObject",
					"Resource":  %s
				},
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  ["s3:PutObject","s3:PutObjectTagging"],
					"Resource":  %s
				}
			]
		}`, testuser.access, srcObjectResource, testuser.access, dstObjectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			Tagging:    getPtr("key=value"),
		})
		cancel()
		return err
	})
}

func AccessControl_CopyObject_with_legal_hold_policy(s *S3Conf) error {
	testName := "AccessControl_CopyObject_with_legal_hold_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		dstObjectResource := fmt.Sprintf(`"arn:aws:s3:::%s/%s"`, bucket, dstObj)
		srcObjectResource := fmt.Sprintf(`"arn:aws:s3:::%s/%s"`, bucket, srcObj)

		// Error path: user has s3:PutObject, s3:GetObject but not s3:PutObjectLegalHold
		policy := fmt.Sprintf(`{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:GetObject",
					"Resource":  %s
				},
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:PutObject",
					"Resource":  %s
				}
			]
		}`, testuser.access, srcObjectResource, testuser.access, dstObjectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:GetObject, s3:PutObject and s3:PutObjectLegalHold
		policy = fmt.Sprintf(`{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:GetObject",
					"Resource":  %s
				},
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  ["s3:PutObject","s3:PutObjectLegalHold"],
					"Resource":  %s
				}
			]
		}`, testuser.access, srcObjectResource, testuser.access, dstObjectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: dstObj, removeLegalHold: true}})
	}, withLock())
}

func AccessControl_CopyObject_with_retention_policy(s *S3Conf) error {
	testName := "AccessControl_CopyObject_with_retention_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		dstObjectResource := fmt.Sprintf(`"arn:aws:s3:::%s/%s"`, bucket, dstObj)
		srcObjectResource := fmt.Sprintf(`"arn:aws:s3:::%s/%s"`, bucket, srcObj)

		// Error path: user has s3:PutObject, s3:GetObject but not s3:PutObjectRetention
		policy := fmt.Sprintf(`{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:GetObject",
					"Resource":  %s
				},
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:PutObject",
					"Resource":  %s
				}
			]
		}`, testuser.access, srcObjectResource, testuser.access, dstObjectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: getPtr(time.Now().AddDate(1, 0, 0)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:GetObject, s3:PutObject and s3:PutObjectRetention
		policy = fmt.Sprintf(`{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  "s3:GetObject",
					"Resource":  %s
				},
				{
					"Effect":  "Allow",
					"Principal": "%s",
					"Action":  ["s3:PutObject","s3:PutObjectRetention"],
					"Resource":  %s
				}
			]
		}`, testuser.access, srcObjectResource, testuser.access, dstObjectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: getPtr(time.Now().AddDate(1, 0, 0)),
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: dstObj}})
	}, withLock())
}

// AccessControl_bucket_policy_condition_ip_allow covers a bucket-policy
// Allow statement scoped by an IpAddress Condition matching the caller's
// real source IP: 0.0.0.0/0 matches any IPv4 address, so this exercises
// the Condition machinery without depending on the test runner's actual
// address.
func AccessControl_bucket_policy_condition_ip_allow(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_ip_allow"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			Condition: json.RawMessage(`{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`),
		}); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjects(userClient, []string{"my-obj"}, bucket)
		return err
	})
}

// AccessControl_bucket_policy_condition_ip_deny_no_match covers the same
// shape as AccessControl_bucket_policy_condition_ip_allow with a CIDR
// (TEST-NET-3, RFC 5737) that can never match a real caller, so the Allow
// statement never applies and the request falls through to an implicit
// deny.
func AccessControl_bucket_policy_condition_ip_deny_no_match(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_ip_deny_no_match"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			Condition: json.RawMessage(`{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`),
		}); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjects(userClient, []string{"my-obj"}, bucket)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// AccessControl_bucket_policy_condition_explicit_deny_overrides_allow
// covers a Deny statement scoped by a matching IpAddress Condition
// overriding a broader, unconditional Allow — the same explicit-deny-wins
// precedence bucket policies already have for unconditional statements,
// now confirmed to hold once one side's match depends on Condition
// evaluation too.
func AccessControl_bucket_policy_condition_explicit_deny_overrides_allow(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_explicit_deny_overrides_allow"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			},
			bucketStatement{
				Effect:    "Deny",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
				Condition: json.RawMessage(`{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`),
			},
		); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjects(userClient, []string{"my-obj"}, bucket)
		return checkApiErr(err, s3err.GetExplicitDenyAccessErr(testuser.access, "s3:PutObject",
			fmt.Sprintf("arn:aws:s3:::%s/my-obj", bucket), "a resource-based policy"))
	})
}

// AccessControl_bucket_policy_condition_s3_prefix covers the s3:prefix
// condition key, populated from a ListObjectsV2 request's own Prefix
// parameter: an Allow scoped to a specific prefix grants a request naming
// that exact prefix and denies one that doesn't.
func AccessControl_bucket_policy_condition_s3_prefix(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_s3_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:ListBucket",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
			Condition: json.RawMessage(`{"StringEquals":{"s3:prefix":"photos/"}}`),
		}); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
			Prefix: getPtr("photos/"),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
			Prefix: getPtr("videos/"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// The tests below cover every Condition operator family bucket policies
// support with at least one Allow and one Deny case each, each scoped to a
// real condition-context key the S3 gateway actually populates from the
// request, so the whole round trip - PutBucketPolicy, the live request,
// and the resulting Allow/Deny - is exercised end to end, not just the
// shared evaluator in isolation (already covered exhaustively by
// internal/condition's own unit tests).
//
// ArnEquals/ArnLike/ArnNotEquals/ArnNotLike are deliberately not covered
// here: they'd need aws:PrincipalArn, which bucket-policy Condition doesn't
// populate today (only identity-policy Condition does - see
// project_s3_bucket_policy_condition memory for why). The operator logic
// itself is still covered by internal/condition's unit tests
// (TestEvaluateConditionArn); what's untested is only the wiring, because
// there's nothing to wire yet.

// AccessControl_bucket_policy_condition_string_operators covers the full
// String family (Equals/NotEquals/Like/NotLike, both plain and IgnoreCase)
// against s3:prefix, populated from a ListObjectsV2 request's own Prefix
// parameter.
func AccessControl_bucket_policy_condition_string_operators(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_string_operators"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		for _, tc := range []struct {
			name      string
			condition string
			prefix    string
			wantAllow bool
		}{
			{"StringEquals matches", `{"StringEquals":{"s3:prefix":"photos/"}}`, "photos/", true},
			{"StringEquals mismatches", `{"StringEquals":{"s3:prefix":"photos/"}}`, "videos/", false},
			{"StringNotEquals passes on a different value", `{"StringNotEquals":{"s3:prefix":"photos/"}}`, "videos/", true},
			{"StringNotEquals fails on the same value", `{"StringNotEquals":{"s3:prefix":"photos/"}}`, "photos/", false},
			{"StringLike wildcard matches", `{"StringLike":{"s3:prefix":"photos/*"}}`, "photos/vacation", true},
			{"StringLike wildcard mismatches", `{"StringLike":{"s3:prefix":"photos/*"}}`, "videos/vacation", false},
			{"StringNotLike passes when the pattern doesn't match", `{"StringNotLike":{"s3:prefix":"photos/*"}}`, "videos/vacation", true},
			{"StringNotLike fails when the pattern matches", `{"StringNotLike":{"s3:prefix":"photos/*"}}`, "photos/vacation", false},
			{"StringEqualsIgnoreCase matches regardless of case", `{"StringEqualsIgnoreCase":{"s3:prefix":"Photos/"}}`, "photos/", true},
			{"StringNotEqualsIgnoreCase fails when equal regardless of case", `{"StringNotEqualsIgnoreCase":{"s3:prefix":"Photos/"}}`, "photos/", false},
		} {
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:ListBucket",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
				Condition: json.RawMessage(tc.condition),
			}); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket: &bucket,
				Prefix: getPtr(tc.prefix),
			})
			cancel()

			if tc.wantAllow {
				if err != nil {
					return fmt.Errorf("%s: expected success, got %w", tc.name, err)
				}
				continue
			}
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_numeric_operators covers the full
// Numeric family against s3:max-keys, populated from a ListObjectsV2
// request's own MaxKeys parameter, binding to the request's actual
// MaxKeys value, not some default.
func AccessControl_bucket_policy_condition_numeric_operators(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_numeric_operators"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		for _, tc := range []struct {
			name      string
			condition string
			maxKeys   int32
			wantAllow bool
		}{
			{"NumericEquals matches", `{"NumericEquals":{"s3:max-keys":"5"}}`, 5, true},
			{"NumericEquals mismatches", `{"NumericEquals":{"s3:max-keys":"5"}}`, 6, false},
			{"NumericNotEquals passes on a different value", `{"NumericNotEquals":{"s3:max-keys":"5"}}`, 6, true},
			{"NumericNotEquals fails on the same value", `{"NumericNotEquals":{"s3:max-keys":"5"}}`, 5, false},
			{"NumericLessThan matches", `{"NumericLessThan":{"s3:max-keys":"10"}}`, 5, true},
			{"NumericLessThan boundary does not match", `{"NumericLessThan":{"s3:max-keys":"10"}}`, 10, false},
			{"NumericLessThanEquals boundary matches", `{"NumericLessThanEquals":{"s3:max-keys":"10"}}`, 10, true},
			{"NumericGreaterThan matches", `{"NumericGreaterThan":{"s3:max-keys":"5"}}`, 10, true},
			{"NumericGreaterThan boundary does not match", `{"NumericGreaterThan":{"s3:max-keys":"5"}}`, 5, false},
			{"NumericGreaterThanEquals boundary matches", `{"NumericGreaterThanEquals":{"s3:max-keys":"5"}}`, 5, true},
		} {
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:ListBucket",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
				Condition: json.RawMessage(tc.condition),
			}); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:  &bucket,
				MaxKeys: getPtr(tc.maxKeys),
			})
			cancel()

			if tc.wantAllow {
				if err != nil {
					return fmt.Errorf("%s: expected success, got %w", tc.name, err)
				}
				continue
			}
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_date_operators covers the
// Less/Greater halves of the Date family against aws:CurrentTime, using
// dates 48 hours in the past/future so the outcome is never flaky
// regardless of test-runner clock skew or how long the request takes.
// DateEquals/DateNotEquals aren't covered here - matching an exact instant
// against a live "now" is inherently flaky at this layer - but are
// exercised at internal/condition's unit-test layer
// (TestEvaluateConditionDate), which is what actually implements the
// comparison; only the request-to-context wiring is new here.
func AccessControl_bucket_policy_condition_date_operators(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_date_operators"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		past := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
		future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)

		for _, tc := range []struct {
			name      string
			condition string
			wantAllow bool
		}{
			{"DateLessThan a future date matches", fmt.Sprintf(`{"DateLessThan":{"aws:CurrentTime":%q}}`, future), true},
			{"DateLessThan a past date does not match", fmt.Sprintf(`{"DateLessThan":{"aws:CurrentTime":%q}}`, past), false},
			{"DateLessThanEquals a future date matches", fmt.Sprintf(`{"DateLessThanEquals":{"aws:CurrentTime":%q}}`, future), true},
			{"DateGreaterThan a past date matches", fmt.Sprintf(`{"DateGreaterThan":{"aws:CurrentTime":%q}}`, past), true},
			{"DateGreaterThan a future date does not match", fmt.Sprintf(`{"DateGreaterThan":{"aws:CurrentTime":%q}}`, future), false},
			{"DateGreaterThanEquals a past date matches", fmt.Sprintf(`{"DateGreaterThanEquals":{"aws:CurrentTime":%q}}`, past), true},
		} {
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:ListBucket",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
				Condition: json.RawMessage(tc.condition),
			}); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
			cancel()

			if tc.wantAllow {
				if err != nil {
					return fmt.Errorf("%s: expected success, got %w", tc.name, err)
				}
				continue
			}
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_bool_operator covers Bool against
// aws:SecureTransport, comparing it to whether s's own endpoint is actually
// using TLS - so this passes the same way against either an HTTP or HTTPS
// test target.
func AccessControl_bucket_policy_condition_bool_operator(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_bool_operator"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		secure := strings.HasPrefix(s.endpoint, "https://")

		for _, tc := range []struct {
			name      string
			condition string
			wantAllow bool
		}{
			{"Bool matches the request's actual transport", fmt.Sprintf(`{"Bool":{"aws:SecureTransport":"%t"}}`, secure), true},
			{"Bool mismatches the request's actual transport", fmt.Sprintf(`{"Bool":{"aws:SecureTransport":"%t"}}`, !secure), false},
		} {
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:ListBucket",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
				Condition: json.RawMessage(tc.condition),
			}); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
			cancel()

			if tc.wantAllow {
				if err != nil {
					return fmt.Errorf("%s: expected success, got %w", tc.name, err)
				}
				continue
			}
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_binary_operator covers BinaryEquals
// against s3:prefix: AWS's own condition-operator reference documents the
// match as a literal string comparison between the policy's base64 text and
// the request context value
func AccessControl_bucket_policy_condition_binary_operator(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_binary_operator"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		encoded := base64.StdEncoding.EncodeToString([]byte("photos/"))
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:ListBucket",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
			Condition: json.RawMessage(fmt.Sprintf(`{"BinaryEquals":{"s3:prefix":%q}}`, encoded)),
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
			Prefix: getPtr(encoded),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("matching prefix: expected success, got %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
			Prefix: getPtr("photos/"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// AccessControl_bucket_policy_condition_null_operator covers Null against
// s3:prefix's presence/absence: Null:"true" requires the key be absent (no
// Prefix parameter on the request at all), Null:"false" requires it be
// present.
func AccessControl_bucket_policy_condition_null_operator(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_null_operator"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:ListBucket",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
			Condition: json.RawMessage(`{"Null":{"s3:prefix":"true"}}`),
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err != nil {
			return fmt.Errorf("null:true, no prefix param: expected success, got %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
			Prefix: getPtr("photos/"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("null:true, prefix param present: %w", err)
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:ListBucket",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s", bucket),
			Condition: json.RawMessage(`{"Null":{"s3:prefix":"false"}}`),
		}); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
			Prefix: getPtr("photos/"),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("null:false, prefix param present: expected success, got %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("null:false, no prefix param: %w", err)
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_not_ip_address_allow and
// ..._deny cover NotIpAddress, the negated counterpart of the IpAddress
// coverage above (AccessControl_bucket_policy_condition_ip_allow/
// ..._ip_deny_no_match): it grants access when the caller's address falls
// OUTSIDE the given range.
func AccessControl_bucket_policy_condition_not_ip_address_allow(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_not_ip_address_allow"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		// TEST-NET-3 (RFC 5737) can never match a real caller, so
		// NotIpAddress against it is always true.
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			Condition: json.RawMessage(`{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`),
		}); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjects(userClient, []string{"my-obj"}, bucket)
		return err
	})
}

func AccessControl_bucket_policy_condition_not_ip_address_deny(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_not_ip_address_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		// 0.0.0.0/0 matches any IPv4 address, so NotIpAddress against it is
		// always false.
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			Condition: json.RawMessage(`{"NotIpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`),
		}); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err := putObjects(userClient, []string{"my-obj"}, bucket)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}
