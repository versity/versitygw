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
)

func ListParts_incorrect_uploadId(s *S3Conf) error {
	testName := "ListParts_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("invalid uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_incorrect_object_key(s *S3Conf) error {
	testName := "ListParts_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      getPtr("incorrect-object-key"),
			UploadId: out.UploadId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_invalid_max_parts(s *S3Conf) error {
	testName := "ListParts_invalid_max_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		invMaxParts := int32(-3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MaxParts: &invMaxParts,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxParts)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_default_max_parts(s *S3Conf) error {
	testName := "ListParts_default_max_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.MaxParts == nil {
			return fmt.Errorf("unexpected nil max-parts")
		}
		if *res.MaxParts != 1000 {
			return fmt.Errorf("expected max parts to be 1000, instead got %v",
				*res.MaxParts)
		}

		return nil
	})
}

func ListParts_exceeding_max_parts(s *S3Conf) error {
	testName := "ListParts_exceeding_max_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			UploadId: mp.UploadId,
			Key:      &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.MaxParts == nil {
			return fmt.Errorf("unexpected nil max-parts")
		}
		if *res.MaxParts != 1000 {
			return fmt.Errorf("expected max-parts to be %v, instead got %v",
				1000, *res.MaxParts)
		}

		return nil
	})
}

func ListParts_truncated(s *S3Conf) error {
	testName := "ListParts_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 25*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		maxParts := int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MaxParts: &maxParts,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.IsTruncated == nil {
			return fmt.Errorf("unexpected nil is-truncated")
		}
		if res.MaxParts == nil {
			return fmt.Errorf("unexpected nil max-parts")
		}
		if !*res.IsTruncated {
			return fmt.Errorf("expected the result to be truncated")
		}
		if *res.MaxParts != maxParts {
			return fmt.Errorf("expected max-parts to be %v, instead got %v",
				maxParts, *res.MaxParts)
		}
		if getString(res.NextPartNumberMarker) != fmt.Sprint(*parts[2].PartNumber) {
			return fmt.Errorf("expected next part number marker to be %v, instead got %v",
				fmt.Sprint(*parts[2].PartNumber), getString(res.NextPartNumberMarker))
		}
		if !compareParts(parts[:3], res.Parts) {
			return fmt.Errorf("expected the parts data to be %v, instead got %v",
				parts[:3], res.Parts)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res2, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:           &bucket,
			Key:              &obj,
			UploadId:         out.UploadId,
			PartNumberMarker: res.NextPartNumberMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res2.PartNumberMarker) != getString(res.NextPartNumberMarker) {
			return fmt.Errorf("expected part number marker to be %v, instead got %v",
				getString(res.NextPartNumberMarker), getString(res2.PartNumberMarker))
		}
		if !compareParts(parts[3:], res2.Parts) {
			return fmt.Errorf("expected the parts data to be %v, instead got %v",
				parts[3:], res2.Parts)
		}

		return nil
	})
}

func ListParts_with_checksums(s *S3Conf) error {
	testName := "ListParts_with_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			mp, err := createMp(s3client, bucket, obj, withChecksum(algo))
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, int64((i+1)*5*1024*1024), int64(i+1), bucket, obj, *mp.UploadId, withChecksum(algo))
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareParts(parts, res.Parts) {
				return fmt.Errorf("expected the mp parts to be %v, instead got %v",
					parts, res.Parts)
			}
		}

		return nil
	})
}

func ListParts_null_checksums(s *S3Conf) error {
	testName := "ListParts_null_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, _, err = uploadParts(s3client, 20*1024*1024, 3, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumType != types.ChecksumType("null") {
			return fmt.Errorf("expected the checksum type to be null, instead got %v", res.ChecksumType)
		}
		if res.ChecksumAlgorithm != types.ChecksumAlgorithm("null") {
			return fmt.Errorf("expected the checksum algorithm to be null, instead got %v", res.ChecksumAlgorithm)
		}

		return nil
	})
}

func ListParts_success(s *S3Conf) error {
	testName := "ListParts_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 5*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, res.StorageClass)
		}
		if ok := compareParts(parts, res.Parts); !ok {
			return fmt.Errorf("expected parts %+v, instead got %+v", parts, res.Parts)
		}

		return nil
	})
}
