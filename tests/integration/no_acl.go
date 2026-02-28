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
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func NoAclMode_CreateBucket_with_acl(s *S3Conf) error {
	testName := "NoAclMode_CreateBucket_with_acl"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		u := getUser("user")
		err := createUsers(s, []user{u})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket:           &bucket,
			ACL:              types.BucketCannedACLPublicReadWrite,
			GrantFullControl: &u.access,
			GrantRead:        &u.access,
			GrantReadACP:     &u.access,
			GrantWrite:       &u.access,
			GrantWriteACP:    &u.access,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
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

		return teardown(s, bucket)
	})
}

func NoAclMode_PutObject_with_acl(s *S3Conf) error {
	testName := "NoAclMode_PutObject_with_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		u := getUser("user")
		err := createUsers(s, []user{u})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:           &bucket,
			Key:              &obj,
			ACL:              types.ObjectCannedACLBucketOwnerFullControl,
			GrantFullControl: &u.access,
			GrantRead:        &u.access,
			GrantReadACP:     &u.access,
			GrantWriteACP:    &u.access,
			Body:             strings.NewReader("dummy data"),
		})
		cancel()

		return err
	})
}

func NoAclMode_CopyObject_with_acl(s *S3Conf) error {
	testName := "NoAclMode_CopyObject_with_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		u := getUser("user")
		err := createUsers(s, []user{u})
		if err != nil {
			return err
		}

		srcObj, dstObj := "source-object", "destination-object"
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
			ACL:    types.ObjectCannedACLAuthenticatedRead,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
		})
		cancel()

		return err
	})
}

func NoAclMode_multipart_upload_with_acl(s *S3Conf) error {
	testName := "NoAclMode_CreateMultipartUpload_with_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		mp, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:           &bucket,
			Key:              &obj,
			ACL:              types.ObjectCannedACLAuthenticatedRead,
			GrantFullControl: getPtr("non_existing_user_1"),
			GrantRead:        getPtr("non_existing_user_2"),
			GrantReadACP:     getPtr("non_existing_user_3"),
			GrantWriteACP:    getPtr("non_existing_user_4"),
		})
		cancel()
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()

		return err
	})
}

func NoAclMode_PutBucketAcl(s *S3Conf) error {
	testName := "NoAclMode_PutBucketAcl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPrivate,
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrACLsDisabled))
	})
}

func NoAclMode_PutObjectAcl_not_implemented(s *S3Conf) error {
	testName := "NoAclMode_PutObjectAcl_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
			Bucket: &bucket,
			Key:    &obj,
			ACL:    types.ObjectCannedACLAuthenticatedRead,
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func NoAclMode_GetObjectAcl_not_implemented(s *S3Conf) error {
	testName := "NoAclMode_GetObjectAcl_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}
