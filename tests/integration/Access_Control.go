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
	"net/http"
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

func AccessControl_UploadPartCopy_malformed_upload_id_without_source_access(s *S3Conf) error {
	testName := "AccessControl_UploadPartCopy_malformed_upload_id_without_source_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket := getBucketName()
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objs, err := putObjects(s3client, []string{"src-obj"}, srcBucket)
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

		userClient := s.getUserClient(testuser)
		obj := "my-obj"
		mp, err := createMp(userClient, bucket, obj)
		if err != nil {
			return err
		}

		// The user can't read the source bucket, but a malformed upload
		// ID is reported first.
		for i, test := range []struct {
			uploadId    string
			expectedErr s3err.S3Error
		}{
			{"../invalid-upload", s3err.GetAPIError(s3err.ErrNoSuchUpload)},
			{*mp.UploadId, s3err.GetAPIError(s3err.ErrAccessDenied)},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   &test.uploadId,
				PartNumber: getPtr(int32(1)),
				CopySource: getPtr(srcBucket + "/" + *objs[0].Key),
			})
			cancel()
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}

		return teardown(s, srcBucket)
	})
}

// A "?versionId=" query in a copy source names a version of the key before
// it, and is authorized as that key's s3:GetObjectVersion: a key the bucket
// policy denies can't be copied by appending an empty, "null" or any other
// versionId to it, and a grant of s3:GetObject doesn't cover a copy of a
// version.
func AccessControl_copy_source_version_id_explicit_deny(s *S3Conf) error {
	testName := "AccessControl_copy_source_version_id_explicit_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket := getBucketName()
		if err := setup(s, srcBucket); err != nil {
			return err
		}
		secretObj, publicObj := "secret.txt", "public.txt"
		if _, err := putObjects(s3client, []string{secretObj, publicObj}, srcBucket); err != nil {
			return err
		}

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		policy := fmt.Sprintf(`{
			"Statement": [
				{
					"Effect": "Allow",
					"Principal": "%s",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::%s/*"
				},
				{
					"Effect": "Deny",
					"Principal": "%s",
					"Action": ["s3:GetObject", "s3:GetObjectVersion"],
					"Resource": "arn:aws:s3:::%s/%s"
				}
			]
		}`, testuser.access, srcBucket, testuser.access, srcBucket, secretObj)
		if err := putBucketPolicy(s3client, srcBucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		dstObj := "dst-obj"
		mp, err := createMp(userClient, bucket, dstObj)
		if err != nil {
			return err
		}

		secretArn := fmt.Sprintf("arn:aws:s3:::%s/%s", srcBucket, secretObj)
		for _, test := range []struct {
			copySource  string
			expectedErr s3err.S3Error
		}{
			{secretObj, s3err.GetExplicitDenyAccessErr(testuser.access, "s3:GetObject", secretArn, "a resource-based policy")},
			{secretObj + "?versionId=", s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEmptyVersionId, "")},
			{secretObj + "?versionId=null", s3err.GetExplicitDenyAccessErr(testuser.access, "s3:GetObjectVersion", secretArn, "a resource-based policy")},
			{secretObj + "?versionId=01BX5ZZKBKACTAV9WEVGEMMVRZ", s3err.GetExplicitDenyAccessErr(testuser.access, "s3:GetObjectVersion", secretArn, "a resource-based policy")},
			{publicObj + "?versionId=null", s3err.GetAPIError(s3err.ErrAccessDenied)},
			{publicObj, nil},
		} {
			copySource := fmt.Sprintf("%s/%s", srcBucket, test.copySource)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &dstObj,
				CopySource: &copySource,
			})
			cancel()
			if test.expectedErr == nil && err != nil {
				return fmt.Errorf("CopyObject from %q: %w", copySource, err)
			}
			if test.expectedErr != nil {
				if err := checkApiErr(err, test.expectedErr); err != nil {
					return fmt.Errorf("CopyObject from %q: %w", copySource, err)
				}
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = userClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        &dstObj,
				UploadId:   mp.UploadId,
				PartNumber: getPtr(int32(1)),
				CopySource: &copySource,
			})
			cancel()
			if test.expectedErr == nil && err != nil {
				return fmt.Errorf("UploadPartCopy from %q: %w", copySource, err)
			}
			if test.expectedErr != nil {
				if err := checkApiErr(err, test.expectedErr); err != nil {
					return fmt.Errorf("UploadPartCopy from %q: %w", copySource, err)
				}
			}
		}

		return teardown(s, srcBucket)
	})
}

// A copy of a specific source version is authorized as s3:GetObjectVersion
// alone: s3:GetObject doesn't grant it, and s3:GetObjectVersion doesn't
// grant a copy of the current object.
func AccessControl_copy_source_version_needs_get_object_version(s *S3Conf) error {
	testName := "AccessControl_copy_source_version_needs_get_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket := getBucketName()
		if err := setup(s, dstBucket); err != nil {
			return err
		}

		obj, dstObj := "doc.txt", "dst-obj"
		v1, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}
		_, err = putObjectWithData(200, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		if err := changeBucketsOwner(s, []string{dstBucket}, testuser.access); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		mp, err := createMp(userClient, dstBucket, dstObj)
		if err != nil {
			return err
		}

		currentSource := fmt.Sprintf("%s/%s", bucket, obj)
		versionSource := fmt.Sprintf("%s/%s?versionId=%s", bucket, obj, getString(v1.res.VersionId))

		for _, test := range []struct {
			action  string
			denied  string
			allowed string
		}{
			{"s3:GetObject", versionSource, currentSource},
			{"s3:GetObjectVersion", currentSource, versionSource},
		} {
			policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access),
				fmt.Sprintf(`"%s"`, test.action), fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			if err := putBucketPolicy(s3client, bucket, policy); err != nil {
				return err
			}

			for _, tc := range []struct {
				copySource  string
				expectedErr s3err.S3Error
			}{
				{test.denied, s3err.GetAPIError(s3err.ErrAccessDenied)},
				{test.allowed, nil},
			} {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := userClient.CopyObject(ctx, &s3.CopyObjectInput{
					Bucket:     &dstBucket,
					Key:        &dstObj,
					CopySource: &tc.copySource,
				})
				cancel()
				if tc.expectedErr == nil && err != nil {
					return fmt.Errorf("%s: CopyObject from %q: %w", test.action, tc.copySource, err)
				}
				if tc.expectedErr != nil {
					if err := checkApiErr(err, tc.expectedErr); err != nil {
						return fmt.Errorf("%s: CopyObject from %q: %w", test.action, tc.copySource, err)
					}
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = userClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
					Bucket:     &dstBucket,
					Key:        &dstObj,
					UploadId:   mp.UploadId,
					PartNumber: getPtr(int32(1)),
					CopySource: &tc.copySource,
				})
				cancel()
				if tc.expectedErr == nil && err != nil {
					return fmt.Errorf("%s: UploadPartCopy from %q: %w", test.action, tc.copySource, err)
				}
				if tc.expectedErr != nil {
					if err := checkApiErr(err, tc.expectedErr); err != nil {
						return fmt.Errorf("%s: UploadPartCopy from %q: %w", test.action, tc.copySource, err)
					}
				}
			}
		}

		// The last copy allowed is the one of the noncurrent version.
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &dstBucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		body, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, v1.data) {
			return fmt.Errorf("expected the copy of version %s, instead got other data", getString(v1.res.VersionId))
		}

		return teardown(s, dstBucket)
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func AccessControl_multipart_malformed_upload_id_without_access(s *S3Conf) error {
	testName := "AccessControl_multipart_malformed_upload_id_without_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObjs, err := putObjects(s3client, []string{"src-obj"}, bucket)
		if err != nil {
			return err
		}
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		err = createUsers(s, []user{testuser})
		if err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		actions := []struct {
			name string
			call func(ctx context.Context, uploadId string) error
		}{
			{"UploadPart", func(ctx context.Context, uploadId string) error {
				_, err := userClient.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:     &bucket,
					Key:        &obj,
					UploadId:   &uploadId,
					PartNumber: getPtr(int32(1)),
					Body:       strings.NewReader("part data"),
				})
				return err
			}},
			{"UploadPartCopy", func(ctx context.Context, uploadId string) error {
				_, err := userClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
					Bucket:     &bucket,
					Key:        &obj,
					UploadId:   &uploadId,
					PartNumber: getPtr(int32(1)),
					CopySource: getPtr(bucket + "/" + *srcObjs[0].Key),
				})
				return err
			}},
			{"ListParts", func(ctx context.Context, uploadId string) error {
				_, err := userClient.ListParts(ctx, &s3.ListPartsInput{
					Bucket:   &bucket,
					Key:      &obj,
					UploadId: &uploadId,
				})
				return err
			}},
			{"CompleteMultipartUpload", func(ctx context.Context, uploadId string) error {
				_, err := userClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &obj,
					UploadId: &uploadId,
					MultipartUpload: &types.CompletedMultipartUpload{
						Parts: []types.CompletedPart{
							{ETag: getPtr("etag"), PartNumber: getPtr(int32(1))},
						},
					},
				})
				return err
			}},
			{"AbortMultipartUpload", func(ctx context.Context, uploadId string) error {
				_, err := userClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &obj,
					UploadId: &uploadId,
				})
				return err
			}},
		}

		// The user has no access to the bucket, but a malformed upload ID
		// is reported first.
		for _, test := range []struct {
			uploadId    string
			expectedErr s3err.S3Error
		}{
			{"../invalid-upload", s3err.GetAPIError(s3err.ErrNoSuchUpload)},
			{*mp.UploadId, s3err.GetAPIError(s3err.ErrAccessDenied)},
		} {
			for _, action := range actions {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				err := action.call(ctx, test.uploadId)
				cancel()
				if err := checkApiErr(err, test.expectedErr); err != nil {
					return fmt.Errorf("%s with upload id %q: %w", action.name, test.uploadId, err)
				}
			}
		}

		return nil
	})
}

// A user granted only "public/*" can't reach "private.txt" through
// "public/../private.txt": posix would resolve that key to the private
// object, so it is rejected before the policy is evaluated.
func AccessControl_dot_segment_key_rejected_before_policy(s *S3Conf) error {
	testName := "AccessControl_dot_segment_key_rejected_before_policy"
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
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
		if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceObject, traversalKey)); err != nil {
			return err
		}

		_, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &traversalKey,
			Body:   bytes.NewReader([]byte("overwrite")),
		}, userClient)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
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
			ChecksumAlgorithm:         types.ChecksumAlgorithmCrc32,
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
			ChecksumAlgorithm:         types.ChecksumAlgorithmCrc32,
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

func AccessControl_GetObjectAttributes_policy(s *S3Conf) error {
	testName := "AccessControl_GetObjectAttributes_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		objectResource := fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket)
		userClient := s.getUserClient(testuser)

		getObjectAttributes := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket:           &bucket,
				Key:              &obj,
				ObjectAttributes: []types.ObjectAttributes{types.ObjectAttributesEtag},
			})
			cancel()
			return err
		}

		// Error path: user has s3:GetObjectAttributes but not s3:GetObject
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObjectAttributes"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		if err := checkApiErr(getObjectAttributes(), s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Error path: user has s3:GetObject but not s3:GetObjectAttributes
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObject"`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		if err := checkApiErr(getObjectAttributes(), s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: user has s3:GetObjectAttributes and s3:GetObject
		policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:GetObjectAttributes","s3:GetObject"]`, objectResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		return getObjectAttributes()
	})
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

// AccessControl_bucket_policy_condition_if_none_match_required is AWS's
// documented "enforce conditional writes" pattern: an unconditional Allow
// paired with a Deny that fires whenever the key is absent, forcing every
// upload to carry If-None-Match.
func AccessControl_bucket_policy_condition_if_none_match_required(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_if_none_match_required"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

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
				Condition: json.RawMessage(`{"Null":{"s3:if-none-match":"true"}}`),
			},
		); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("unconditional"),
			Body:   bytes.NewReader([]byte("data")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetExplicitDenyAccessErr(testuser.access, "s3:PutObject",
			fmt.Sprintf("arn:aws:s3:::%s/unconditional", bucket), "a resource-based policy")); err != nil {
			return fmt.Errorf("an upload without If-None-Match must be denied: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("conditional"),
			Body:        bytes.NewReader([]byte("data")),
			IfNoneMatch: getPtr("*"),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("an upload carrying If-None-Match must be allowed: %w", err)
		}

		// The same request once the key exists is still authorized; it now
		// fails on the precondition itself, which the policy has no say in.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("conditional"),
			Body:        bytes.NewReader([]byte("data")),
			IfNoneMatch: getPtr("*"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrPreconditionFailed))
	})
}

// AccessControl_bucket_policy_condition_if_none_match_copy is the same
// "enforce conditional writes" pattern for a copy: its If-None-Match is a
// conditional write on the destination, so it populates the key just like
// an upload's.
func AccessControl_bucket_policy_condition_if_none_match_copy(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_if_none_match_copy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		src := "src-obj"
		if _, err := putObjects(s3client, []string{src}, bucket); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    []string{"s3:PutObject", "s3:GetObject"},
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			},
			bucketStatement{
				Effect:    "Deny",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
				Condition: json.RawMessage(`{"Null":{"s3:if-none-match":"true"}}`),
			},
		); err != nil {
			return err
		}

		copySource := getPtr(fmt.Sprintf("%s/%s", bucket, src))
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("unconditional"),
			CopySource: copySource,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetExplicitDenyAccessErr(testuser.access, "s3:PutObject",
			fmt.Sprintf("arn:aws:s3:::%s/unconditional", bucket), "a resource-based policy")); err != nil {
			return fmt.Errorf("a copy without If-None-Match must be denied: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("conditional"),
			CopySource:  copySource,
			IfNoneMatch: getPtr("*"),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("a copy carrying If-None-Match must be allowed: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("conditional"),
			CopySource:  copySource,
			IfNoneMatch: getPtr("*"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrPreconditionFailed))
	})
}

// AccessControl_bucket_policy_condition_if_none_match_value covers the
// key's value rather than its presence: the only value S3 accepts in an
// If-None-Match write is "*", and that is what the key carries verbatim -
// under StringEquals "*" is a literal, not a wildcard.
func AccessControl_bucket_policy_condition_if_none_match_value(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_if_none_match_value"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		for i, tc := range []struct {
			name      string
			condition string
			wantAllow bool
		}{
			{"StringEquals on the literal wildcard matches", `{"StringEquals":{"s3:if-none-match":"*"}}`, true},
			{"StringEquals on any other value does not", `{"StringEquals":{"s3:if-none-match":"abc123"}}`, false},
			{"Null:false matches a present key", `{"Null":{"s3:if-none-match":"false"}}`, true},
			{"Null:true does not match a present key", `{"Null":{"s3:if-none-match":"true"}}`, false},
			{"StringLike wildcard matches", `{"StringLike":{"s3:if-none-match":"*"}}`, true},
		} {
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
				Condition: json.RawMessage(tc.condition),
			}); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket:      &bucket,
				Key:         getPtr(fmt.Sprintf("obj-%v", i)),
				Body:        bytes.NewReader([]byte("data")),
				IfNoneMatch: getPtr("*"),
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

// AccessControl_bucket_policy_condition_if_match_value covers
// s3:if-match's value shape: the key carries the ETag with the surrounding
// quotes stripped, so a policy compares against the bare ETag whichever
// form the client puts on the wire.
func AccessControl_bucket_policy_condition_if_match_value(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_if_match_value"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		etag, err := putObjectAndGetETag(s3client, bucket, "obj")
		if err != nil {
			return err
		}
		bare := strings.Trim(etag, `"`)

		for _, tc := range []struct {
			name        string
			condition   func() string
			ifMatch     *string
			wantAllow   bool
			azureUnsupp bool
		}{
			{"quoted header matches a bare policy value",
				func() string { return fmt.Sprintf(`{"StringEquals":{"s3:if-match":%q}}`, bare) }, &etag, true, false},
			{"unquoted header matches the same bare policy value",
				func() string { return fmt.Sprintf(`{"StringEquals":{"s3:if-match":%q}}`, bare) }, &bare, true, false},
			{"a policy value carrying the quotes never matches",
				func() string { return fmt.Sprintf(`{"StringEquals":{"s3:if-match":%q}}`, etag) }, &etag, false, true},
			{"a different ETag does not match",
				func() string { return `{"StringEquals":{"s3:if-match":"0123456789abcdef0123456789abcdef"}}` }, &etag, false, false},
			{"StringLike wildcard matches",
				func() string { return `{"StringLike":{"s3:if-match":"*"}}` }, &etag, true, false},
			{"Null:false matches a present key",
				func() string { return `{"Null":{"s3:if-match":"false"}}` }, &etag, true, false},
		} {
			if tc.azureUnsupp && s.azureTests {
				continue
			}
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
				Condition: json.RawMessage(tc.condition()),
			}); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := userClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     getPtr("obj"),
				Body:    bytes.NewReader([]byte("data")),
				IfMatch: tc.ifMatch,
			})
			cancel()

			if tc.wantAllow {
				if err != nil {
					return fmt.Errorf("%s: expected success, got %w", tc.name, err)
				}
				// The overwrite may have changed the ETag, so every
				// subsequent case has to condition on the current one.
				if etag, err = headObjectETag(s3client, bucket, "obj"); err != nil {
					return err
				}
				bare = strings.Trim(etag, `"`)
				continue
			}
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_if_match_delete_object covers the
// half of s3:if-match that isn't an upload: S3's conditional delete, which
// is the only other action a bucket policy may name the key on.
func AccessControl_bucket_policy_condition_if_match_delete_object(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_if_match_delete_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		etag, err := putObjectAndGetETag(s3client, bucket, "obj")
		if err != nil {
			return err
		}

		// A delete that doesn't name the object's ETag is not authorized
		// at all, so it never reaches the precondition check.
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:DeleteObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			Condition: json.RawMessage(fmt.Sprintf(`{"StringEquals":{"s3:if-match":%q}}`, strings.Trim(etag, `"`))),
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr("obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("an unconditional delete must be denied: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:  &bucket,
			Key:     getPtr("obj"),
			IfMatch: &etag,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("a delete naming the object's ETag must be allowed: %w", err)
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_if_match_versioned_delete pins the
// edge of s3:if-match's action set. A delete naming a version removes that
// version rather than overwriting the current one, so it is authorized as
// s3:DeleteObjectVersion — an action the key doesn't apply to, which is why
// PutBucketPolicy rejects a statement pairing the two. The key has to stay
// absent from the request context to match, or a wildcard-action statement
// would grant on a precondition the policy language can't name.
func AccessControl_bucket_policy_condition_if_match_versioned_delete(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_if_match_versioned_delete"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		etag, err := putObjectAndGetETag(s3client, bucket, "obj")
		if err != nil {
			return err
		}

		// s3:* is the only action a bucket policy can name s3:if-match on
		// and still reach a versioned delete: a wildcard is exempt from
		// the applicability check an explicit s3:DeleteObjectVersion fails.
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:*",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			Condition: json.RawMessage(`{"Null":{"s3:if-match":"false"}}`),
		}); err != nil {
			return err
		}

		// "null" is the version id every object carries until versioning is
		// enabled, so this is a versioned delete on any backend. A versioned
		// delete carrying If-Match is rejected before the policy is
		// evaluated.
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       getPtr("obj"),
			VersionId: getPtr("null"),
			IfMatch:   &etag,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetNotImplementedErr("If-Match", s3err.NmpAdditionalMessageVersionedDelete)); err != nil {
			return fmt.Errorf("a versioned delete carrying If-Match must be rejected: %w", err)
		}

		// The same header on the same object, minus the version, is a plain
		// s3:DeleteObject and does populate the key.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:  &bucket,
			Key:     getPtr("obj"),
			IfMatch: &etag,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("an unversioned delete carrying If-Match must be allowed: %w", err)
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_s3_authType_deny covers a Deny on
// every request a user doesn't sign in its Authorization header, the policy
// that refuses presigned URLs and browser POST uploads while normal signed
// requests keep working: s3:authType is REST-HEADER for a header-signed
// request, so the Deny skips it, and REST-QUERY-STRING or POST for the
// other two, which it refuses.
func AccessControl_bucket_policy_condition_s3_authType_deny(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_s3_authType_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		obj := "my-obj"
		if _, err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    []string{"s3:GetObject", "s3:PutObject"},
				Resource:  objectsArn(bucket),
			},
			bucketStatement{
				Effect:    "Deny",
				Principal: testuser.access,
				Action:    "s3:*",
				Resource:  []string{bucketArn(bucket), objectsArn(bucket)},
				Condition: json.RawMessage(`{"StringNotEquals":{"s3:authType":"REST-HEADER"}}`),
			},
		); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &obj})
		cancel()
		if err != nil {
			return fmt.Errorf("header-signed GetObject: expected success, got %w", err)
		}
		out.Body.Close()

		if _, err := putObjects(userClient, []string{"header-obj"}, bucket); err != nil {
			return fmt.Errorf("header-signed PutObject: expected success, got %w", err)
		}

		req, err := createPresignedReq(http.MethodGet, s.endpoint, fmt.Sprintf("%s/%s", bucket, obj),
			testuser.access, testuser.secret, s.awsRegion, time.Now(), nil)
		if err != nil {
			return err
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, wantExplicitResourceDeny(testuser.access, "s3:GetObject", objectArn(bucket, obj))); err != nil {
			return fmt.Errorf("presigned GetObject: %w", err)
		}

		resp, err = sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "post-obj",
			access:      testuser.access,
			secret:      testuser.secret,
			s3Conf:      s,
			fileContent: []byte("data"),
		})
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, wantExplicitResourceDeny(testuser.access, "s3:PutObject", objectArn(bucket, "post-obj"))); err != nil {
			return fmt.Errorf("POST upload: %w", err)
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_s3_authType_values covers the
// value s3:authType takes for each way of signing a request, each Allow
// granting only the requests signed that one way: REST-QUERY-STRING for a
// presigned URL, POST for a browser POST upload and REST-HEADER for a
// request signed in its Authorization header. The values are
// case-sensitive, so "rest-header" names none of them.
func AccessControl_bucket_policy_condition_s3_authType_values(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_s3_authType_values"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		obj, data := "my-obj", "data"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Body:   strings.NewReader(data),
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:GetObject",
				Resource:  objectsArn(bucket),
				Condition: json.RawMessage(`{"StringEquals":{"s3:authType":"REST-QUERY-STRING"}}`),
			},
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  objectsArn(bucket),
				Condition: json.RawMessage(`{"StringEquals":{"s3:authType":"POST"}}`),
			},
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:ListBucket",
				Resource:  bucketArn(bucket),
				Condition: json.RawMessage(`{"StringEquals":{"s3:authType":"REST-HEADER"}}`),
			},
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:GetBucketTagging",
				Resource:  bucketArn(bucket),
				Condition: json.RawMessage(`{"StringEquals":{"s3:authType":"rest-header"}}`),
			},
		); err != nil {
			return err
		}

		req, err := createPresignedReq(http.MethodGet, s.endpoint, fmt.Sprintf("%s/%s", bucket, obj),
			testuser.access, testuser.secret, s.awsRegion, time.Now(), nil)
		if err != nil {
			return err
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		if err := checkObjectResponse(resp, data); err != nil {
			return fmt.Errorf("presigned GetObject: %w", err)
		}

		resp, err = sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "post-obj",
			access:      testuser.access,
			secret:      testuser.secret,
			s3Conf:      s,
			fileContent: []byte(data),
		})
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST upload: %w", err)
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err != nil {
			return fmt.Errorf("header-signed ListObjectsV2: expected success, got %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &obj})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("header-signed GetObject: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("header-obj")})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("header-signed PutObject: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &bucket})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("header-signed GetBucketTagging under a lowercase value: %w", err)
		}
		return nil
	})
}

// AccessControl_bucket_policy_condition_s3_signatureAge covers a Deny on
// signatures older than a minute, the limit on how long a presigned URL or
// a POST form stays usable. s3:signatureAge is the time since the
// signature's X-Amz-Date in milliseconds, so the same presigned GET and
// POST upload are allowed when just signed and refused when signed two
// minutes earlier. One dated ahead of the clock has a negative age, which
// the Deny allows too. A request signed in its Authorization header has no
// signature age at all, so the Deny never applies to it.
func AccessControl_bucket_policy_condition_s3_signatureAge(s *S3Conf) error {
	testName := "AccessControl_bucket_policy_condition_s3_signatureAge"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		obj, data := "my-obj", "data"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Body:   strings.NewReader(data),
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    []string{"s3:GetObject", "s3:PutObject"},
				Resource:  objectsArn(bucket),
			},
			bucketStatement{
				Effect:    "Deny",
				Principal: testuser.access,
				Action:    []string{"s3:GetObject", "s3:PutObject"},
				Resource:  objectsArn(bucket),
				Condition: json.RawMessage(`{"NumericGreaterThan":{"s3:signatureAge":"60000"}}`),
			},
		); err != nil {
			return err
		}

		if _, err := putObjects(s.getUserClient(testuser), []string{"header-obj"}, bucket); err != nil {
			return fmt.Errorf("header-signed PutObject: expected success, got %w", err)
		}

		for _, tc := range []struct {
			name   string
			signed time.Time
			denied bool
		}{
			{"just signed", time.Now(), false},
			// a signature dated ahead of the clock has a negative age
			{"signed 5 minutes ahead", time.Now().Add(5 * time.Minute), false},
			{"signed 2 minutes ago", time.Now().Add(-2 * time.Minute), true},
		} {
			req, err := createPresignedReq(http.MethodGet, s.endpoint, fmt.Sprintf("%s/%s", bucket, obj),
				testuser.access, testuser.secret, s.awsRegion, tc.signed, nil)
			if err != nil {
				return err
			}
			resp, err := s.httpClient.Do(req)
			if err != nil {
				return err
			}
			if tc.denied {
				err = checkHTTPResponseApiErr(resp, wantExplicitResourceDeny(testuser.access, "s3:GetObject", objectArn(bucket, obj)))
			} else {
				err = checkObjectResponse(resp, data)
			}
			if err != nil {
				return fmt.Errorf("presigned GetObject %s: %w", tc.name, err)
			}

			resp, err = sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         "post-obj",
				access:      testuser.access,
				secret:      testuser.secret,
				date:        tc.signed.UTC(),
				s3Conf:      s,
				fileContent: []byte(data),
			})
			if err != nil {
				return err
			}
			if tc.denied {
				err = checkHTTPResponseApiErr(resp, wantExplicitResourceDeny(testuser.access, "s3:PutObject", objectArn(bucket, "post-obj")))
			} else {
				err = checkPostObjectSuccess(resp)
			}
			if err != nil {
				return fmt.Errorf("POST upload %s: %w", tc.name, err)
			}
		}
		return nil
	})
}

func AccessControl_owner_deny_only_policy_keeps_access(s *S3Conf) error {
	testName := "AccessControl_owner_deny_only_policy_keeps_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		obj, deniedObj := "my-obj", "deny-probe/my-obj"
		if _, err := putObjects(userClient, []string{obj, deniedObj}, bucket); err != nil {
			return err
		}

		policy := genPolicyDoc("Deny", `"*"`, `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/deny-probe/*"`, bucket))
		if err := putBucketPolicy(userClient, bucket, policy); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}
		out.Body.Close()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &deniedObj,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetExplicitDenyAccessErr(
			testuser.access, "s3:GetObject", fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, deniedObj), "a resource-based policy",
		)); err != nil {
			return err
		}

		// A malformed replacement is rejected for what it is, and the
		// policy in place keeps denying.
		err = putBucketPolicy(userClient, bucket, `{"Statement":[`)
		if err := checkApiErr(err, getMalformedPolicyError("This policy contains invalid Json")); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = userClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &deniedObj,
		})
		cancel()
		if err != nil {
			return err
		}
		out.Body.Close()

		return nil
	})
}

func AccessControl_owner_policy_lockout_protection(s *S3Conf) error {
	testName := "AccessControl_owner_policy_lockout_protection"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		if err := changeBucketsOwner(s, []string{bucket}, testuser.access); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		policy := genPolicyDoc("Deny", `"*"`, `"s3:*"`, fmt.Sprintf(`["arn:aws:s3:::%s", "arn:aws:s3:::%s/*"]`, bucket, bucket))
		if err := putBucketPolicy(userClient, bucket, policy); err != nil {
			return err
		}

		bucketArn := fmt.Sprintf("arn:aws:s3:::%s", bucket)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetExplicitDenyAccessErr(
			testuser.access, "s3:ListBucket", bucketArn, "a resource-based policy",
		)); err != nil {
			return err
		}

		// Only the bucket policy APIs are exempt from the owner's own deny.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetExplicitDenyAccessErr(
			testuser.access, "s3:GetBucketPolicyStatus", bucketArn, "a resource-based policy",
		)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putBucketPolicy(userClient, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		return err
	})
}

func AccessControl_acl_grant_with_bucket_policy(s *S3Conf) error {
	testName := "AccessControl_acl_grant_with_bucket_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser, otheruser := getUser("user"), getUser("user")
		if err := createUsers(s, []user{testuser, otheruser}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			GrantRead: &testuser.access,
		})
		cancel()
		if err != nil {
			return err
		}

		// A policy that doesn't name the grantee leaves its ACL grant in
		// effect.
		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, otheruser.access), `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		// An explicit deny overrides the ACL grant.
		policy = genPolicyDoc("Deny", fmt.Sprintf(`"%s"`, testuser.access), `"s3:ListBucket"`, fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket))
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		return checkApiErr(err, s3err.GetExplicitDenyAccessErr(
			testuser.access, "s3:ListBucket", fmt.Sprintf("arn:aws:s3:::%s", bucket), "a resource-based policy",
		))
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func AccessControl_acl_grant_excludes_bucket_configuration(s *S3Conf) error {
	testName := "AccessControl_acl_grant_excludes_bucket_configuration"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:           &bucket,
			GrantFullControl: &testuser.access,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		if _, err := putObjects(userClient, []string{"my-obj"}, bucket); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Deny", `"*"`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket))
		err = putBucketPolicy(userClient, bucket, policy)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}
