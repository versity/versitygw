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
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func GetObjectAttributes_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectAttributes_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:           getPtr(getBucketName()),
			Key:              getPtr("my-obj"),
			ObjectAttributes: []types.ObjectAttributes{},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_non_existing_object(s *S3Conf) error {
	testName := "GetObjectAttributes_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
			},
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_invalid_attrs(s *S3Conf) error {
	testName := "GetObjectAttributes_invalid_attrs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
				types.ObjectAttributes("Invalid_argument"),
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectAttributes)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_invalid_parent(s *S3Conf) error {
	testName := "GetObjectAttributes_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "not-a-dir"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
			},
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_invalid_single_attribute(s *S3Conf) error {
	testName := "GetObjectAttributes_invalid_single_attribute"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributes("invalid_attr"),
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectAttributes)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_empty_attrs(s *S3Conf) error {
	testName := "GetObjectAttributes_empty_attrs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:           &bucket,
			Key:              &obj,
			ObjectAttributes: []types.ObjectAttributes{},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectAttributesInvalidHeader)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_existing_object(s *S3Conf) error {
	testName := "GetObjectAttributes_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, data_len := "my-obj", int64(45679)
		data := make([]byte, data_len)

		_, err := rand.Read(data)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Body:   bytes.NewReader(data),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
				types.ObjectAttributesObjectSize,
				types.ObjectAttributesStorageClass,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ETag == nil || out.ETag == nil {
			return fmt.Errorf("nil ETag output")
		}
		if strings.Trim(*resp.ETag, "\"") != *out.ETag {
			return fmt.Errorf("expected ETag to be %v, instead got %v",
				strings.Trim(*resp.ETag, "\""), *out.ETag)
		}
		if out.ObjectSize == nil {
			return fmt.Errorf("nil object size output")
		}
		if *out.ObjectSize != data_len {
			return fmt.Errorf("expected object size to be %v, instead got %v",
				data_len, *out.ObjectSize)
		}
		if out.Checksum != nil {
			return fmt.Errorf("expected checksum to be nil, instead got %v",
				*out.Checksum)
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}
		if out.LastModified == nil {
			return fmt.Errorf("expected non nil LastModified")
		}

		return nil
	})
}

func GetObjectAttributes_checksums(s *S3Conf) error {
	testName := "GetObjectAttributes_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, checksumAlgo := range types.ChecksumAlgorithmCrc32.Values() {
			key := fmt.Sprintf("obj-%v", i+1)
			out, err := putObjectWithData(int64((i+1)*120), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				ChecksumAlgorithm: checksumAlgo,
			}, s3client, withPutObjectChecksumAlgo(checksumAlgo))
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket: &bucket,
				Key:    &key,
				ObjectAttributes: []types.ObjectAttributes{
					types.ObjectAttributesChecksum,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			if res.Checksum == nil {
				return fmt.Errorf("expected non-nil checksum in the response")
			}
			if res.Checksum.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the %v object checksum type to be %v, instead got %v",
					key, types.ChecksumTypeFullObject, res.Checksum.ChecksumType)
			}
			if got, expected := getString(getObjectAttributesChecksum(res.Checksum, checksumAlgo)), getString(getPutObjectChecksum(out.res, checksumAlgo)); got != expected {
				return fmt.Errorf("expected %s checksum to be %s, instead got %s", checksumAlgo, expected, got)
			}
		}
		return nil
	})
}
