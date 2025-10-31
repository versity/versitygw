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
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func DeleteObject_non_existing_object(s *S3Conf) error {
	testName := "DeleteObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		return err
	})
}

func DeleteObject_directory_object_noslash(s *S3Conf) error {
	testName := "DeleteObject_directory_object_noslash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		obj = "my-obj"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		// the delete above should succeed, but the object should not be deleted
		// since it should not correctly match the directory name
		// so the below head object should also succeed
		obj = "my-obj/"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		return err
	})
}

func DeleteObject_non_empty_dir_obj(s *S3Conf) error {
	testName := "DeleteObject_non_empty_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objToDel := "foo/"
		nestedObj := objToDel + "bar"
		_, err := putObjects(s3client, []string{nestedObj, objToDel}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &objToDel,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Contents) != 1 {
			return fmt.Errorf("expected the object list length to be 1, instead got %v",
				len(res.Contents))
		}
		if getString(res.Contents[0].Key) != nestedObj {
			return fmt.Errorf("expected the object key to be %v, instead got %v",
				nestedObj, getString(res.Contents[0].Key))
		}

		return nil
	})
}

func DeleteObject_conditional_writes(s *S3Conf) error {
	testName := "DeleteObject_conditional_writes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		var etag *string = getPtr("")
		var size *int64 = getPtr(int64(0))
		var modTime *time.Time = getPtr(time.Now())

		createObj := func() error {
			res, err := putObjectWithData(0, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Body:   bytes.NewReader([]byte("dummy")),
			}, s3client)
			if err != nil {
				return err
			}

			// get the exact LastModified time
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			*etag = *res.res.ETag
			*size = *res.res.Size
			*modTime = *out.LastModified

			return nil
		}

		err := createObj()
		if err != nil {
			return err
		}

		errPrecond := s3err.GetAPIError(s3err.ErrPreconditionFailed)

		for i, test := range []struct {
			ifMatch *string
			size    *int64
			modTime *time.Time
			err     error
		}{
			// no error cases
			{etag, size, modTime, nil},
			{etag, nil, nil, nil},
			{nil, size, nil, nil},
			{nil, nil, modTime, nil},
			{etag, size, nil, nil},
			{etag, nil, modTime, nil},
			{nil, size, modTime, nil},
			// error cases
			{getPtr("incorrect_etag"), nil, nil, errPrecond},
			{nil, getPtr(int64(23234)), nil, errPrecond},
			{nil, nil, getPtr(time.Now().AddDate(-1, -1, -1)), errPrecond},
			{getPtr("incorrect_etag"), getPtr(int64(23234)), nil, errPrecond},
			{getPtr("incorrect_etag"), getPtr(int64(23234)), getPtr(time.Now().AddDate(-1, -1, -1)), errPrecond},
		} {
			err := createObj()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:                  &bucket,
				Key:                     &obj,
				IfMatch:                 test.ifMatch,
				IfMatchSize:             test.size,
				IfMatchLastModifiedTime: test.modTime,
			})
			cancel()
			if test.err != nil {
				apiErr, ok := test.err.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type: expected s3err.APIError")
				}
				if err := checkApiErr(err, apiErr); err != nil {
					return fmt.Errorf("test case %d failed: %w", i, err)
				}
			}
		}

		return nil
	})
}

func DeleteObject_directory_not_empty(s *S3Conf) error {
	testName := "DeleteObject_directory_not_empty"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "dir/my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		obj = "dir/"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		// object servers will return no error, but the posix backend returns
		// a non-standard directory not empty. This test is a posix only test
		// to validate the specific error response.
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryNotEmpty)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_non_existing_dir_object(s *S3Conf) error {
	testName := "DeleteObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		obj = "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		return err
	})
}

func DeleteObject_directory_object(s *S3Conf) error {
	testName := "DeleteObject_directory_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "foo/bar/"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		return err
	})
}

func DeleteObject_success(s *S3Conf) error {
	testName := "DeleteObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_success_status_code(s *S3Conf) error {
	testName := "DeleteObject_success_status_code"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint,
			fmt.Sprintf("%v/%v", bucket, obj), s.awsID, s.awsSecret, "s3",
			s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func DeleteObject_incorrect_expected_bucket_owner(s *S3Conf) error {
	testName := "DeleteObject_incorrect_expected_bucket_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			// anyways if object doesn't exist, a 200 response should be received
			Key:                 getPtr("my-obj"),
			ExpectedBucketOwner: getPtr(s.awsID + "something"),
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

func DeleteObject_expected_bucket_owner(s *S3Conf) error {
	testName := "DeleteObject_expected_bucket_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			// anyways if object doesn't exist, a 200 response should be received
			Key:                 getPtr("my-obj"),
			ExpectedBucketOwner: &s.awsID,
		})
		cancel()

		return err
	})
}
