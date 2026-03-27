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
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sync/errgroup"
)

func PutObject_overwrite_dir_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/", "foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "foo/"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj_with_nested_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj_with_nested_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "foo/bar"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_dir_obj_with_data(s *S3Conf) error {
	testName := "PutObject_dir_obj_with_data"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjectWithData(int64(20), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("obj/"),
		}, s3client)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_with_slashes(s *S3Conf) error {
	testName := "PutObject_with_slashes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{
			"/obj", "foo//bar", "/foo/baz/bar", "////////bar", "foo//////quxx",
		}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		// it's en expected bahvior in posix to normalize the object pahts,
		// by removing multiple slashes
		normalizedObjs := []string{
			"bar",
			"foo/bar",
			"foo/baz/bar",
			"foo/quxx",
			"obj",
		}

		for i := range objs {
			objs[i].Key = &normalizedObjs[i]
		}

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the objects to be %vß, instead got %v",
				objStrings(objs), objStrings(res.Contents))
		}

		return nil
	})
}

func CreateMultipartUpload_dir_obj(s *S3Conf) error {
	testName := "CreateMultipartUpload_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := createMp(s3client, bucket, "obj/")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_name_too_long(s *S3Conf) error {
	testName := "PutObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := genRandString(300)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrKeyTooLong)); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_name_too_long(s *S3Conf) error {
	testName := "HeadObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr(genRandString(300)),
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}

		return nil
	})
}

func DeleteObject_name_too_long(s *S3Conf) error {
	testName := "DeleteObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr(genRandString(300)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrKeyTooLong)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_overwrite_same_dir_object(s *S3Conf) error {
	testName := "CopyObject_overwrite_same_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("foo"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, "foo/")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_overwrite_same_file_object(s *S3Conf) error {
	testName := "CopyObject_overwrite_same_file_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("foo/"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, "foo")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}

		return nil
	})
}

// PutObject_race_with_delete tests the race between PutObject and DeleteObject
// in the same subdirectory.
// One goroutine sequentially puts "race-dir/0.txt" … "race-dir/N-1.txt".
// A second goroutine loops for the same number of iterations: it lists all
// objects under "race-dir/" and bulk-deletes them.  When the batch delete
// removes the last visible object in the directory, removeParents() rmdir's
// "race-dir/", which can race with the uploader's final link() step.
// The test asserts that no error is returned from either goroutine.
func PutObject_race_with_delete(s *S3Conf) error {
	testName := "PutObject_race_with_delete"
	const iterations = 100
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		eg := errgroup.Group{}

		// Upload goroutine: sequentially puts objects into race-dir/
		eg.Go(func() error {
			for i := range iterations {
				key := fmt.Sprintf("race-dir/%d.txt", i)
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
					Bucket: &bucket,
					Key:    &key,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("put %d: %w", i, err)
				}
			}
			return nil
		})

		// Delete goroutine: repeatedly lists race-dir/ and bulk-deletes everything.
		// When the last object is removed, removeParents() rmdir's the directory,
		// racing with the concurrent link() call in the upload goroutine.
		eg.Go(func() error {
			for range iterations {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket: &bucket,
					Prefix: getPtr("race-dir/"),
				})
				cancel()
				if err != nil {
					return fmt.Errorf("list: %w", err)
				}
				if len(res.Contents) == 0 {
					continue
				}

				objs := make([]types.ObjectIdentifier, 0, len(res.Contents))
				for _, obj := range res.Contents {
					objs = append(objs, types.ObjectIdentifier{Key: obj.Key})
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: &bucket,
					Delete: &types.Delete{Objects: objs},
				})
				cancel()
				if err != nil {
					return fmt.Errorf("delete objects: %w", err)
				}
				if len(out.Errors) > 0 {
					return fmt.Errorf("delete error: key=%v code=%v msg=%v",
						*out.Errors[0].Key, *out.Errors[0].Code, *out.Errors[0].Message)
				}
			}
			return nil
		})

		return eg.Wait()
	})
}
