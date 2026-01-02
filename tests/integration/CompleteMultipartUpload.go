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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sync/errgroup"
)

func CompletedMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "CompletedMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("non-existing-bucket"),
			Key:      getPtr("some/key"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_part_number(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		partNumber = int32(5)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       res.ETag,
						PartNumber: &partNumber,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_ETag(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_ETag"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       getPtr("invalidETag"),
						PartNumber: &partNumber,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}
func CompleteMultipartUpload_invalid_checksum_type(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumType("invalid_type"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-type")); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})

			if i == 0 {
				cParts[0].ChecksumCRC32 = getPtr("invalid_checksum")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeFullObject,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_multiple_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_multiple_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeComposite))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})

			if i == 0 {
				cParts[0].ChecksumSHA1 = getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0=")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmSha256),
			withChecksumType(types.ChecksumTypeComposite))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmSha256))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:           el.ETag,
				PartNumber:     el.PartNumber,
				ChecksumSHA256: el.ChecksumSHA256,
			})

			if i == 0 {
				cParts[0].ChecksumSHA256 = getPtr("n2alat9FhKiZXkZO18V2LLcZFM3IT8R7DjSMvK//7WU=")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_different_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_different_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32c),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32c))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:           el.ETag,
				PartNumber:     el.PartNumber,
				ChecksumCRC32C: el.ChecksumCRC32C,
			})

			if i == 0 {
				cParts[0].ChecksumSHA256 = getPtr("n2alat9FhKiZXkZO18V2LLcZFM3IT8R7DjSMvK//7WU=")
				cParts[0].ChecksumCRC32C = nil
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeFullObject,
		})
		cancel()
		if err := checkApiErr(err, s3err.APIError{
			Code:           "BadDigest",
			Description:    "The sha256 you specified for part 1 did not match what we received.",
			HTTPStatusCode: http.StatusBadRequest,
		}); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_missing_part_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_missing_part_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmSha1),
			withChecksumType(types.ChecksumTypeComposite))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmSha1))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:         el.ETag,
				PartNumber:   el.PartNumber,
				ChecksumSHA1: el.ChecksumSHA1,
			})

			if i == 0 {
				cParts[0].ChecksumSHA1 = nil
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.APIError{
			Code:           "InvalidRequest",
			Description:    "The upload was created using a sha1 checksum. The complete request must include the checksum for each part. It was missing for part 1 in the request.",
			HTTPStatusCode: http.StatusBadRequest,
		}); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_multiple_final_checksums(s *S3Conf) error {
	testName := "CompleteMultipartUpload_multiple_final_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 5*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32C,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumCRC32:  getPtr("sGc9Hg=="),
			ChecksumCRC32C: getPtr("/2NsFg=="),
			ChecksumType:   types.ChecksumTypeFullObject,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_final_checksums(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_final_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {

			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo),
				withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
				*mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32C,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			mpInput := &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				ChecksumType: el.t,
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				mpInput.ChecksumCRC32 = getPtr("invalid_crc32")
			case types.ChecksumAlgorithmCrc32c:
				mpInput.ChecksumCRC32C = getPtr("invalid_crc32c")
			case types.ChecksumAlgorithmSha1:
				mpInput.ChecksumSHA1 = getPtr("invalid_sha1")
			case types.ChecksumAlgorithmSha256:
				mpInput.ChecksumSHA256 = getPtr("invalid_sha256")
			case types.ChecksumAlgorithmCrc64nvme:
				mpInput.ChecksumCRC64NVME = getPtr("invalid_crc64nvme")
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, mpInput)
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", strings.ToLower(string(el.algo))))); err != nil {
				return err
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_final_checksums(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_final_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo),
				withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
				*mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				// Provide one of the parts checksum. In any case
				// the final checksum will differ from one of the parts checksum
				ChecksumCRC32:     cParts[0].ChecksumCRC32,
				ChecksumCRC32C:    cParts[0].ChecksumCRC32C,
				ChecksumSHA1:      cParts[0].ChecksumSHA1,
				ChecksumSHA256:    cParts[0].ChecksumSHA256,
				ChecksumCRC64NVME: cParts[0].ChecksumCRC64NVME,
				ChecksumType:      el.t,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetChecksumBadDigestErr(el.algo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_should_calculate_the_final_checksum_full_object(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_calculate_the_final_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo), withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, csum, err := uploadParts(s3client, 15*1024*1024, 3, bucket,
				obj, *mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				ChecksumType: el.t,
			})
			cancel()
			if err != nil {
				return err
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				if getString(res.ChecksumCRC32) != csum {
					return fmt.Errorf("expected the final crc32 checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32))
				}
			case types.ChecksumAlgorithmCrc32c:
				if getString(res.ChecksumCRC32C) != csum {
					return fmt.Errorf("expected the final crc32c checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32C))
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if getString(res.ChecksumCRC64NVME) != csum {
					return fmt.Errorf("expected the final crc64nvme checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC64NVME))
				}
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_should_verify_the_final_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_verify_the_final_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo),
				withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, csum, err := uploadParts(s3client, 15*1024*1024, 3, bucket,
				obj, *mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			mpInput := &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				ChecksumType: el.t,
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				mpInput.ChecksumCRC32 = &csum
			case types.ChecksumAlgorithmCrc32c:
				mpInput.ChecksumCRC32C = &csum
			case types.ChecksumAlgorithmCrc64nvme:
				mpInput.ChecksumCRC64NVME = &csum
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.CompleteMultipartUpload(ctx, mpInput)
			cancel()
			if err != nil {
				return err
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				if getString(res.ChecksumCRC32) != csum {
					return fmt.Errorf("expected the final crc32 checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32))
				}
			case types.ChecksumAlgorithmCrc32c:
				if getString(res.ChecksumCRC32C) != csum {
					return fmt.Errorf("expected the final crc32c checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32C))
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if getString(res.ChecksumCRC64NVME) != csum {
					return fmt.Errorf("expected the final crc64nvme checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC64NVME))
				}
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_should_verify_final_composite_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_verify_final_composite_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for i, algo := range []types.ChecksumAlgorithm{
			types.ChecksumAlgorithmCrc32,
			types.ChecksumAlgorithmCrc32c,
			types.ChecksumAlgorithmSha1,
			types.ChecksumAlgorithmSha256,
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksumType(types.ChecksumTypeComposite), withChecksum(algo))
			if err != nil {
				return fmt.Errorf("test %v failed: %s", i, err)
			}

			parts, _, err := uploadParts(s3client, 25*1024*1024, 5, bucket, obj, *mp.UploadId, withChecksum(algo))
			if err != nil {
				return fmt.Errorf("test %v failed: %s", i, err)
			}

			hasher, err := NewHasher(algo)
			if err != nil {
				return fmt.Errorf("test %v failed: %s", i, err)
			}

			completeParts := make([]types.CompletedPart, 0, len(parts))

			for _, part := range parts {
				switch algo {
				case types.ChecksumAlgorithmCrc32:
					err = processCompositeChecksum(hasher, getString(part.ChecksumCRC32))
				case types.ChecksumAlgorithmCrc32c:
					err = processCompositeChecksum(hasher, getString(part.ChecksumCRC32C))
				case types.ChecksumAlgorithmSha1:
					err = processCompositeChecksum(hasher, getString(part.ChecksumSHA1))
				case types.ChecksumAlgorithmSha256:
					err = processCompositeChecksum(hasher, getString(part.ChecksumSHA256))
				}

				if err != nil {
					return fmt.Errorf("test %v failed: %s", i, err)
				}

				completeParts = append(completeParts, types.CompletedPart{
					ETag:           part.ETag,
					PartNumber:     part.PartNumber,
					ChecksumCRC32:  part.ChecksumCRC32,
					ChecksumCRC32C: part.ChecksumCRC32C,
					ChecksumSHA1:   part.ChecksumSHA1,
					ChecksumSHA256: part.ChecksumSHA256,
				})
			}

			checksum := fmt.Sprintf("%s-%v", base64.StdEncoding.EncodeToString(hasher.Sum(nil)), len(parts))

			completeMpInput := &s3.CompleteMultipartUploadInput{
				Bucket: &bucket,
				Key:    &obj,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: completeParts,
				},
				UploadId: mp.UploadId,
			}

			switch algo {
			case types.ChecksumAlgorithmCrc32:
				completeMpInput.ChecksumCRC32 = &checksum
			case types.ChecksumAlgorithmCrc32c:
				completeMpInput.ChecksumCRC32C = &checksum
			case types.ChecksumAlgorithmSha1:
				completeMpInput.ChecksumSHA1 = &checksum
			case types.ChecksumAlgorithmSha256:
				completeMpInput.ChecksumSHA256 = &checksum
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.CompleteMultipartUpload(ctx, completeMpInput)
			cancel()
			if err != nil {
				return fmt.Errorf("test %v failed: %s", i, err)
			}

			var gotSum string
			switch algo {
			case types.ChecksumAlgorithmCrc32:
				gotSum = getString(res.ChecksumCRC32)
			case types.ChecksumAlgorithmCrc32c:
				gotSum = getString(res.ChecksumCRC32C)
			case types.ChecksumAlgorithmSha1:
				gotSum = getString(res.ChecksumSHA1)
			case types.ChecksumAlgorithmSha256:
				gotSum = getString(res.ChecksumSHA256)
			}

			if gotSum != checksum {
				return fmt.Errorf("test %v failed: expected the final checksum to be %s, instead got %s", i, checksum, gotSum)
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_final_composite_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_final_composite_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for i, test := range []struct {
			algo   types.ChecksumAlgorithm
			crc32  *string
			crc32c *string
			sha1   *string
			sha256 *string
		}{
			{types.ChecksumAlgorithmCrc32, getPtr("invalid_checksum"), nil, nil, nil},
			{types.ChecksumAlgorithmCrc32, getPtr("ImIEBA==-smth"), nil, nil, nil},
			{types.ChecksumAlgorithmCrc32c, nil, getPtr("invalid_checksum"), nil, nil},
			{types.ChecksumAlgorithmCrc32c, nil, getPtr("AQIDBA==-12a"), nil, nil},
			{types.ChecksumAlgorithmSha1, nil, nil, getPtr("invalid_checksum"), nil},
			{types.ChecksumAlgorithmSha1, nil, nil, getPtr("2jmj7l5rSw0yVb/vlWAYkK/YBwk=-10-20"), nil},
			{types.ChecksumAlgorithmSha256, nil, nil, nil, getPtr("invalid_checksum")},
			{types.ChecksumAlgorithmSha256, nil, nil, nil, getPtr("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=--3")},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(test.algo), withChecksumType(types.ChecksumTypeComposite))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i, err)
			}

			parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *mp.UploadId, withChecksum(test.algo))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i, err)
			}

			completeParts := make([]types.CompletedPart, 0, len(parts))

			for _, part := range parts {
				completeParts = append(completeParts, types.CompletedPart{
					ETag:           part.ETag,
					PartNumber:     part.PartNumber,
					ChecksumCRC32:  part.ChecksumCRC32,
					ChecksumCRC32C: part.ChecksumCRC32C,
					ChecksumSHA1:   part.ChecksumSHA1,
					ChecksumSHA256: part.ChecksumSHA256,
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: completeParts,
				},
				ChecksumCRC32:  test.crc32,
				ChecksumCRC32C: test.crc32c,
				ChecksumSHA1:   test.sha1,
				ChecksumSHA256: test.sha256,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", strings.ToLower(string(test.algo))))); err != nil {
				return fmt.Errorf("test %v failed: %w", i, err)
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_checksum_type_mismatch(s *S3Conf) error {
	testName := "CompleteMultipartUpload_checksum_type_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetChecksumTypeMismatchOnMpErr(types.ChecksumTypeFullObject)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_should_ignore_the_final_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_ignore_the_final_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumCRC64NVME: getPtr("vqf3hRLTlJw="), // should ignore this
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, insted got %v",
				*res.ChecksumCRC32)
		}
		if res.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, insted got %v",
				*res.ChecksumCRC32C)
		}
		if res.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, insted got %v",
				*res.ChecksumSHA1)
		}
		if res.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, insted got %v",
				*res.ChecksumSHA256)
		}
		// If no checksum is specified on mp creation, it should default
		// to crc64nvme
		if res.ChecksumCRC64NVME == nil {
			return fmt.Errorf("expected non nil crc64nvme checksum")
		}

		return nil
	})
}

func CompleteMultipartUpload_should_succeed_without_final_checksum_type(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_succeed_without_final_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc64nvme),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc64nvme))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:              el.ETag,
				PartNumber:        el.PartNumber,
				ChecksumCRC64NVME: el.ChecksumCRC64NVME,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumType != types.ChecksumTypeFullObject {
			return fmt.Errorf("expected the final checksum type to be %v, instead got %v",
				types.ChecksumTypeFullObject, res.ChecksumType)
		}
		if getString(res.ChecksumCRC64NVME) == "" {
			return fmt.Errorf("expected non empty crc64nvme checksum")
		}

		return nil
	})
}

func CompleteMultipartUpload_small_upload_size(s *S3Conf) error {
	testName := "CompleteMultipartUpload_small_upload_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		// The uploaded parts size is 256 < 5 Mib (the minimum allowed size)
		parts, _, err := uploadParts(s3client, 1024, 4, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}

		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				PartNumber: el.PartNumber,
				ETag:       el.ETag,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrEntityTooSmall)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_empty_parts(s *S3Conf) error {
	testName := "CompleteMultipartUpload_empty_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, _, err = uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{}, // empty parts list
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_parts_order(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_parts_order"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj, *out.UploadId)
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

		compParts[0], compParts[1] = compParts[1], compParts[0]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartOrder)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_mpu_object_size(s *S3Conf) error {
	testName := "CompleteMultipartUpload_mpu_object_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		mpuSize := int64(23 * 1024 * 1024) // 23 mib
		parts, _, err := uploadParts(s3client, mpuSize, 4, bucket, obj, *mp.UploadId)
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

		invMpuSize := int64(-1) // invalid MpuObjectSize
		// Initially provide invalid MpuObjectSize: -3
		input := &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
			MpuObjectSize: &invMpuSize,
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, input)
		cancel()
		if err := checkApiErr(err, s3err.GetNegatvieMpObjectSizeErr(invMpuSize)); err != nil {
			return err
		}

		incorMpuSize := int64(213123) // incorrect object size
		input.MpuObjectSize = &incorMpuSize

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, input)
		cancel()
		if err := checkApiErr(err, s3err.GetIncorrectMpObjectSizeErr(mpuSize, incorMpuSize)); err != nil {
			return err
		}

		// Correct value for MpuObjectSize
		input.MpuObjectSize = &mpuSize
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, input)
		cancel()
		if err != nil {
			return err
		}

		// Make sure the object has been uploaded with proper size
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ContentLength == nil {
			return fmt.Errorf("expected non nil Content-Length")
		}
		if *res.ContentLength != mpuSize {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v",
				mpuSize, *res.ContentLength)
		}

		return nil
	})
}

func CompleteMultipartUpload_conditional_writes(s *S3Conf) error {
	testName := "CompleteMultipartUpload_conditional_writes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		etag := getPtr("")
		var etagTrimmed string
		incorrectEtag := getPtr("incorrect_etag")
		errPrecond := s3err.GetAPIError(s3err.ErrPreconditionFailed)
		errNoSuchKey := s3err.GetAPIError(s3err.ErrNoSuchKey)
		errNotImplemented := s3err.GetAPIError(s3err.ErrNotImplemented)

		for i, test := range []struct {
			obj         string
			ifMatch     *string
			ifNoneMatch *string
			err         error
		}{
			{obj, etag, nil, nil},
			{obj, etag, etag, errNotImplemented},
			{obj, etag, incorrectEtag, errNotImplemented},
			{obj, incorrectEtag, incorrectEtag, errNotImplemented},
			{obj, incorrectEtag, etag, errNotImplemented},
			{obj, incorrectEtag, nil, errPrecond},
			{obj, nil, incorrectEtag, errNotImplemented},
			{obj, nil, etag, errNotImplemented},
			{obj, nil, getPtr("*"), errPrecond},
			{obj, etag, getPtr("*"), errNotImplemented},
			{obj, nil, nil, nil},

			// precondition headers without quotes
			{obj, &etagTrimmed, nil, nil},
			{obj, &etagTrimmed, &etagTrimmed, errNotImplemented},
			{obj, &etagTrimmed, incorrectEtag, errNotImplemented},
			{obj, incorrectEtag, &etagTrimmed, errNotImplemented},
			{obj, nil, &etagTrimmed, errNotImplemented},

			// object deson't exist tests
			{"obj-1", incorrectEtag, etag, errNotImplemented},
			{"obj-2", etag, etag, errNotImplemented},
			{"obj-3", etag, nil, errNoSuchKey},
			{"obj-4", etag, incorrectEtag, errNotImplemented},
			{"obj-5", incorrectEtag, nil, errNoSuchKey},
			{"obj-6", nil, etag, errNotImplemented},
			{"obj-7", nil, getPtr("*"), nil},
			{"obj-8", etag, getPtr("*"), errNotImplemented},
		} {
			res, err := putObjectWithData(0, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Body:   bytes.NewReader([]byte("dummy")),
			}, s3client)
			if err != nil {
				return err
			}
			// azure blob storage generates different ETags for
			// the exact same data.
			// to avoid ETag collision reassign the etag value
			*etag = *res.res.ETag
			etagTrimmed = strings.Trim(*etag, `"`)

			mp, err := createMp(s3client, bucket, test.obj)
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, test.obj, *mp.UploadId)
			if err != nil {
				return err
			}

			part := parts[0]

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &test.obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: []types.CompletedPart{
						{
							ETag:              part.ETag,
							PartNumber:        getPtr(int32(1)),
							ChecksumCRC64NVME: part.ChecksumCRC64NVME,
						},
					},
				},
				IfMatch:     test.ifMatch,
				IfNoneMatch: test.ifNoneMatch,
			})
			cancel()
			if test.err == nil && err != nil {
				return fmt.Errorf("test case %v: expected no error, instead got %w", i, err)
			}
			if test.err != nil {
				apierr, ok := test.err.(s3err.APIError)
				if !ok {
					return fmt.Errorf("test case %v: invalid error type: %w", i, test.err)
				}

				if err := checkApiErr(err, apierr); err != nil {
					return fmt.Errorf("test case %v: %w", i, err)
				}
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_with_metadata(s *S3Conf) error {
	testName := "CompleteMultipartUpload_with_metadata"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		meta := map[string]string{
			"Key":                 "Val",
			"X-Test":              "Example",
			"UPPERCASE":           "should-remain",
			"MiXeD-CaSe":          "normalize-to-lower",
			"with-number-123":     "numeric-test",
			"123numeric-prefix":   "value123",
			"key_with_underscore": "underscore-ok",
			"key-with-dash":       "dash-ok",
			"key.with.dot":        "dot-ok",
			"KeyURL":              "https://example.com/test?query=1",
			"EmptyValue":          "",
			"LongKeyNameThatShouldStillBeValidButQuiteLongToTestLimits": "some long metadata value to ensure nothing breaks at higher header sizes",
			"WhitespaceKey ": " trailing-key",
		}

		obj := "my-object"

		mp, err := createMp(s3client, bucket, obj, withMetadata(meta))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *mp.UploadId)
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

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedMeta := map[string]string{
			"key":                 "Val",
			"x-test":              "Example",
			"uppercase":           "should-remain",
			"mixed-case":          "normalize-to-lower",
			"with-number-123":     "numeric-test",
			"123numeric-prefix":   "value123",
			"key_with_underscore": "underscore-ok",
			"key-with-dash":       "dash-ok",
			"key.with.dot":        "dot-ok",
			"keyurl":              "https://example.com/test?query=1",
			"emptyvalue":          "",
			"longkeynamethatshouldstillbevalidbutquitelongtotestlimits": "some long metadata value to ensure nothing breaks at higher header sizes",
			"whitespacekey": "trailing-key",
		}

		if !areMapsSame(expectedMeta, res.Metadata) {
			return fmt.Errorf("expected the object metadata to be %v, instead got %v", expectedMeta, res.Metadata)
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_part_number(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		invPartNumber := int32(-4)

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: &invPartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCompleteMpPartNumber)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_success(s *S3Conf) error {
	testName := "CompleteMultipartUpload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := int64(25 * 1024 * 1024)
		parts, csum, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
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

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.Key) != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v", obj, *res.Key)
		}
		location := constructObjectLocation(s.endpoint, bucket, obj, s.hostStyle)
		if res.Location == nil {
			return fmt.Errorf("expected non nil Location")
		}
		if *res.Location != location {
			return fmt.Errorf("expected Location to be %s, instead got %s", location, *res.Location)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(resp.ETag) != getString(res.ETag) {
			return fmt.Errorf("expected the uploaded object etag to be %v, instead got %v",
				getString(res.ETag), getString(resp.ETag))
		}
		if resp.ContentLength == nil {
			return fmt.Errorf("expected (head object) non nil Content-Length")
		}
		if *resp.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v",
				objSize, resp.ContentLength)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		rget, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		if err != nil {
			return err
		}

		if rget.ContentLength == nil {
			return fmt.Errorf("expected (get object) non nil Content-Length")
		}
		if *rget.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				objSize, *rget.ContentLength)
		}

		bdy, err := io.ReadAll(rget.Body)
		if err != nil {
			return err
		}
		defer rget.Body.Close()

		sum := sha256.Sum256(bdy)
		getsum := hex.EncodeToString(sum[:])

		if csum != getsum {
			return fmt.Errorf("expected the object checksum to be %v, instead got %v",
				csum, getsum)
		}

		return nil
	})
}

func CompleteMultipartUpload_racey_success(s *S3Conf) error {
	testName := "CompleteMultipartUpload_racey_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		var mu sync.RWMutex
		uploads := make([]mpinfo, 10)
		sums := make([]string, 10)
		objSize := int64(25 * 1024 * 1024)

		eg := errgroup.Group{}
		for i := range 10 {
			func(i int) {
				eg.Go(func() error {
					out, err := createMp(s3client, bucket, obj)
					if err != nil {
						return err
					}

					parts, csum, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
					mu.Lock()
					sums[i] = csum
					mu.Unlock()
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

					mu.Lock()
					uploads[i] = mpinfo{
						uploadId: out.UploadId,
						parts:    compParts,
					}
					mu.Unlock()
					return nil
				})
			}(i)
		}

		err := eg.Wait()
		if err != nil {
			return err
		}

		eg = errgroup.Group{}
		for i := range 10 {
			func(i int) {
				eg.Go(func() error {
					ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
					mu.RLock()
					res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &obj,
						UploadId: uploads[i].uploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: uploads[i].parts,
						},
					})
					mu.RUnlock()
					cancel()
					if err != nil {
						fmt.Println("GOT ERROR: ", err)
						return err
					}

					if getString(res.Key) != obj {
						return fmt.Errorf("expected object key to be %v, instead got %v",
							obj, getString(res.Key))
					}

					return nil
				})
			}(i)
		}

		err = eg.Wait()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		if err != nil {
			return err
		}

		if out.ContentLength == nil {
			return fmt.Errorf("expected (get object) non nil Content-Length")
		}
		if *out.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				objSize, *out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()

		sum := sha256.Sum256(bdy)
		csum := hex.EncodeToString(sum[:])

		mu.RLock()
		defer mu.RUnlock()
		for _, s := range sums {
			if csum == s {
				return nil
			}
		}
		return fmt.Errorf("expected the object checksum to be one of %v, instead got %v",
			sums, csum)
	})
}
