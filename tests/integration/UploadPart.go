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
	"encoding/base64"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"math/bits"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func UploadPart_non_existing_bucket(s *S3Conf) error {
	testName := "UploadPart_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		partNumber := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucketName,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_invalid_part_number(s *S3Conf) error {
	testName := "UploadPart_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		mp, err := createMp(s3client, bucket, key)
		if err != nil {
			return err
		}
		for _, el := range []int32{0, -1, 10001, 2300000} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     &bucket,
				Key:        &key,
				UploadId:   mp.UploadId,
				PartNumber: &el,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartNumber)); err != nil {
				return err
			}
		}

		return nil
	})
}

func UploadPart_non_existing_mp_upload(s *S3Conf) error {
	testName := "UploadPart_non_existing_mp_upload"
	partNumber := int32(1)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_multiple_checksum_headers(s *S3Conf) error {
	testName := "UploadPart_multiple_checksum_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32c))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			ChecksumCRC32C: getPtr("m0cB1Q=="),
			UploadId:       mp.UploadId,
			PartNumber:     &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		// multiple empty checksums
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr(""),
			ChecksumCRC32C: getPtr(""),
			UploadId:       mp.UploadId,
			PartNumber:     &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_invalid_checksum_header(s *S3Conf) error {
	testName := "UploadPart_invalid_checksum_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		for _, algo := range types.ChecksumAlgorithmCrc32.Values() {
			// tests against:
			// - empty string
			// - invalid base64
			// - valid base64, but invalid checksum
			for _, checksum := range []string{"", "invalid_base64!", "c2RhZnNhZGZzZGFm"} {
				input := &s3.UploadPartInput{
					Bucket:     &bucket,
					Key:        &obj,
					PartNumber: &partNumber,
					UploadId:   mp.UploadId,
				}
				setUploadPartChecksum(input, algo, getPtr(checksum))

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := s3client.UploadPart(ctx, input)
				cancel()
				if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr(checksumHeaderName(algo))); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func UploadPart_checksum_header_and_algo_mismatch(s *S3Conf) error {
	testName := "UploadPart_checksum_header_and_algo_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:            &bucket,
			Key:               &obj,
			UploadId:          mp.UploadId,
			PartNumber:        getPtr(int32(1)),
			Body:              strings.NewReader("dummy"),
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
			ChecksumCRC32C:    getPtr("muDarg=="),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidChecksumHeaderErr("x-amz-sdk-checksum-algorithm"))
	})
}

func UploadPart_checksum_algorithm_mistmatch_on_initialization(s *S3Conf) error {
	testName := "UploadPart_checksum_algorithm_mistmatch_on_initialization"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:            &bucket,
			Key:               &obj,
			UploadId:          mp.UploadId,
			PartNumber:        &partNumber,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetChecksumTypeMismatchErr(types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha1)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value(s *S3Conf) error {
	testName := "UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:         &bucket,
			Key:            &obj,
			UploadId:       mp.UploadId,
			PartNumber:     &partNumber,
			ChecksumSHA256: getPtr("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetChecksumTypeMismatchErr(types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha256)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_incorrect_checksums(s *S3Conf) error {
	testName := "UploadPart_incorrect_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for _, algo := range types.ChecksumAlgorithmCrc32.Values() {
			wrongChecksum, err := wrongChecksumForAlgorithm(algo)
			if err != nil {
				return err
			}

			mp, err := createMp(s3client, bucket, obj, withChecksum(algo))
			if err != nil {
				return err
			}

			body := strings.NewReader("random string body")
			partNumber := int32(1)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			input := &s3.UploadPartInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   mp.UploadId,
				PartNumber: &partNumber,
				Body:       body,
			}
			setUploadPartChecksum(input, algo, &wrongChecksum)
			_, err = s3client.UploadPart(ctx, input)
			cancel()
			if err := checkApiErr(err, s3err.GetChecksumBadDigestErr(algo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func UploadPart_no_checksum_with_full_object_checksum_type(s *S3Conf) error {
	testName := "UploadPart_no_checksum_with_full_object_checksum_type"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		customClient := s3.NewFromConfig(s.Config(), func(o *s3.Options) {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationUnset
		})
		obj := "my-obj"

		for _, algo := range []types.ChecksumAlgorithm{
			types.ChecksumAlgorithmCrc32,
			types.ChecksumAlgorithmCrc32c,
			types.ChecksumAlgorithmCrc64nvme,
		} {
			mp, err := createMp(customClient, bucket, obj, withChecksum(algo), withChecksumType(types.ChecksumTypeFullObject))
			if err != nil {
				return err
			}

			var hashRdr hash.Hash

			switch algo {
			case types.ChecksumAlgorithmCrc32:
				hashRdr = crc32.NewIEEE()
			case types.ChecksumAlgorithmCrc32c:
				hashRdr = crc32.New(crc32.MakeTable(crc32.Castagnoli))
			case types.ChecksumAlgorithmCrc64nvme:
				hashRdr = crc64.New(crc64.MakeTable(bits.Reverse64(0xad93d23594c93659)))
			default:
				return fmt.Errorf("invalid checksum algorithm provided: %s", algo)
			}

			partBuffer := make([]byte, 5*1024*1024)
			rand.Read(partBuffer)
			hashRdr.Write(partBuffer)
			partNumber := int32(1)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := customClient.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   mp.UploadId,
				Body:       bytes.NewReader(partBuffer),
				PartNumber: &partNumber,
			})
			cancel()
			if err != nil {
				return err
			}

			csum := base64.StdEncoding.EncodeToString(hashRdr.Sum(nil))

			switch algo {
			case types.ChecksumAlgorithmCrc32:
				if getString(res.ChecksumCRC32) != csum {
					return fmt.Errorf("expected the uploaded part checksum %s to be %s, instead got %s", algo, csum, getString(res.ChecksumCRC32))
				}
			case types.ChecksumAlgorithmCrc32c:
				if getString(res.ChecksumCRC32C) != csum {
					return fmt.Errorf("expected the uploaded part checksum %s to be %s, instead got %s", algo, csum, getString(res.ChecksumCRC32C))
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if getString(res.ChecksumCRC64NVME) != csum {
					return fmt.Errorf("expected the uploaded part checksum %s to be %s, instead got %s", algo, csum, getString(res.ChecksumCRC64NVME))
				}
			}
		}
		return nil
	})
}

func UploadPart_no_checksum_with_composite_checksum_type(s *S3Conf) error {
	testName := "UploadPart_no_checksum_with_composite_checksum_type"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		customClient := s3.NewFromConfig(s.Config(), func(o *s3.Options) {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationUnset
		})
		obj := "my-obj"

		for _, algo := range []types.ChecksumAlgorithm{
			types.ChecksumAlgorithmCrc32,
			types.ChecksumAlgorithmCrc32c,
			types.ChecksumAlgorithmSha1,
			types.ChecksumAlgorithmSha256,
			types.ChecksumAlgorithmSha512,
			types.ChecksumAlgorithmMd5,
			types.ChecksumAlgorithmXxhash64,
			types.ChecksumAlgorithmXxhash3,
			types.ChecksumAlgorithmXxhash128,
		} {
			mp, err := createMp(customClient, bucket, obj, withChecksum(algo), withChecksumType(types.ChecksumTypeComposite))
			if err != nil {
				return err
			}
			_, _, err = uploadParts(customClient, 10, 1, bucket, obj, *mp.UploadId)
			if err := checkApiErr(err, s3err.GetChecksumTypeMismatchErr(algo, "null")); err != nil {
				return err
			}
		}
		return nil
	})
}

func UploadPart_with_checksums_success(s *S3Conf) error {
	testName := "UploadPart_with_checksums_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		customClient := s3.NewFromConfig(s.Config(), func(o *s3.Options) {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationUnset
		})
		obj := "my-obj"

		for _, test := range []struct {
			chType types.ChecksumType
			chAlgo types.ChecksumAlgorithm
		}{
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmCrc32},
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmCrc32c},
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmCrc64nvme},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmCrc32},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmCrc32c},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmSha1},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmSha256},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmSha512},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmMd5},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmXxhash64},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmXxhash3},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmXxhash128},
		} {
			mp, err := createMp(customClient, bucket, obj, withChecksum(test.chAlgo), withChecksumType(test.chType))
			if err != nil {
				return err
			}

			parts, csum, err := uploadParts(customClient, 5*1024*1024, 1, bucket, obj, *mp.UploadId, withChecksum(test.chAlgo))
			if err != nil {
				return err
			}

			if len(parts) != 1 {
				return fmt.Errorf("expected 1 uploaded part, instaed got %d", len(parts))
			}

			if got := getString(getPartChecksum(parts[0], test.chAlgo)); got != csum {
				return fmt.Errorf("expected the uploaded part checksum %s to be %s, instead got %s", test.chAlgo, csum, got)
			}
		}
		return nil
	})
}

func UploadPart_non_existing_key(s *S3Conf) error {
	testName := "UploadPart_non_existing_key"
	partNumber := int32(1)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("non-existing-object-key"),
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_success(s *S3Conf) error {
	testName := "UploadPart_success"
	partNumber := int32(1)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(res.ETag) == "" {
			return fmt.Errorf("expected a valid etag, instead got empty")
		}
		return nil
	})
}
