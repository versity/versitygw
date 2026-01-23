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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func CreateMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "CreateMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		_, err := createMp(s3client, bucketName, "my-obj")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_with_metadata(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_metadata"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		meta := map[string]string{
			"prop1": "val1",
			"prop2": "val2",
		}
		cType, cEnc, cDesp, cLang := "application/text", "testenc", "testdesp", "sp"
		cacheControl, expires := "no-cache", time.Now().Add(time.Hour*5)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:             &bucket,
			Key:                &obj,
			Metadata:           meta,
			ContentType:        &cType,
			ContentEncoding:    &cEnc,
			ContentDisposition: &cDesp,
			ContentLanguage:    &cLang,
			CacheControl:       &cacheControl,
			Expires:            &expires,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
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
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
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

		if !areMapsSame(resp.Metadata, meta) {
			return fmt.Errorf("expected uploaded object metadata to be %v, instead got %v",
				meta, resp.Metadata)
		}

		if getString(resp.ContentType) != cType {
			return fmt.Errorf("expected uploaded object content-type to be %v, instead got %v",
				cType, getString(resp.ContentType))
		}
		if getString(resp.ContentEncoding) != cEnc {
			return fmt.Errorf("expected uploaded object content-encoding to be %v, instead got %v",
				cEnc, getString(resp.ContentEncoding))
		}
		if getString(resp.ContentLanguage) != cLang {
			return fmt.Errorf("expected uploaded object content-language to be %v, instead got %v",
				cLang, getString(resp.ContentLanguage))
		}
		if getString(resp.ContentDisposition) != cDesp {
			return fmt.Errorf("expected uploaded object content-disposition to be %v, instead got %v",
				cDesp, getString(resp.ContentDisposition))
		}
		if getString(resp.CacheControl) != cacheControl {
			return fmt.Errorf("expected uploaded object cache-control to be %v, instead got %v",
				cacheControl, getString(resp.CacheControl))
		}
		if getString(resp.ExpiresString) != expires.UTC().Format(timefmt) {
			return fmt.Errorf("expected uploaded object content-encoding to be %v, instead got %v",
				expires.UTC().Format(timefmt), getString(resp.ExpiresString))
		}

		return nil
	})
}

func CreateMultipartUpload_with_object_lock(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		retainUntilDate := time.Now().Add(24 * time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &retainUntilDate,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
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
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
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

		if resp.ObjectLockLegalHoldStatus != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected uploaded object legal hold status to be %v, instead got %v",
				types.ObjectLockLegalHoldStatusOn, resp.ObjectLockLegalHoldStatus)
		}
		if resp.ObjectLockMode != types.ObjectLockModeGovernance {
			return fmt.Errorf("expected uploaded object lock mode to be %v, instead got %v",
				types.ObjectLockModeGovernance, resp.ObjectLockMode)
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, removeLegalHold: true}})
	}, withLock())
}

func CreateMultipartUpload_with_object_lock_not_enabled(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_object_lock_not_enabled"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		// with retention
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: getPtr(time.Now().AddDate(1, 0, 0)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces)); err != nil {
			return err
		}

		// with legal hold
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces))
	})
}

func CreateMultipartUpload_with_object_lock_invalid_retention(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_object_lock_invalid_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		retentionDate := time.Now().Add(24 * time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:         &bucket,
			Key:            &obj,
			ObjectLockMode: types.ObjectLockModeGovernance,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockRetainUntilDate: &retentionDate,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_past_retain_until_date(s *S3Conf) error {
	testName := "CreateMultipartUpload_past_retain_until_date"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		rDate := time.Now().Add(-5 * time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &rDate,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrPastObjectLockRetainDate)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_invalid_legal_hold(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus("invalid_status"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus))
	}, withLock())
}

func CreateMultipartUpload_invalid_object_lock_mode(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_object_lock_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rDate := time.Now().Add(time.Hour * 10)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockMode:            types.ObjectLockMode("invalid_mode"),
			ObjectLockRetainUntilDate: &rDate,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode))
	}, withLock())
}

func CreateMultipartUpload_invalid_checksum_algorithm(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_checksum_algorithm"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:            &bucket,
			Key:               getPtr("my-obj"),
			ChecksumAlgorithm: types.ChecksumAlgorithm("invalid_checksum_algorithm"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_invalid_checksum_type(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := createMp(s3client, bucket, "my-mp", withChecksumType(types.ChecksumType("invalid_checksum_type")))
		if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-type")); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type(s *S3Conf) error {
	testName := "CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, el := range types.ChecksumTypeComposite.Values() {
			_, err := createMp(s3client, bucket, "my-mp", withChecksumType(el))
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrChecksumTypeWithAlgo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func CreateMultipartUpload_type_algo_mismatch(s *S3Conf) error {
	testName := "CreateMultipartUpload_type_algo_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, test := range []struct {
			chType types.ChecksumType
			algo   types.ChecksumAlgorithm
		}{
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmCrc64nvme},
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmSha1},
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmSha256},
		} {
			_, err := createMp(s3client, bucket, "my-obj", withChecksum(test.algo), withChecksumType(test.chType))
			if err := checkApiErr(err, s3err.GetChecksumSchemaMismatchErr(test.algo, test.chType)); err != nil {
				return fmt.Errorf("test %v failed: %w", i, err)
			}
		}

		return nil
	})
}

func CreateMultipartUpload_valid_algo_type(s *S3Conf) error {
	testName := "CreateMultipartUpload_valid_algo_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, test := range []struct {
			chType types.ChecksumType
			chAlgo types.ChecksumAlgorithm
		}{
			// composite type
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmCrc32},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmCrc32c},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmSha1},
			{types.ChecksumTypeComposite, types.ChecksumAlgorithmSha256},
			// full object type
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmCrc64nvme},
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmCrc32},
			{types.ChecksumTypeFullObject, types.ChecksumAlgorithmCrc32c},
		} {
			randChType := types.ChecksumType(randomizeCase(string(test.chType)))
			randChAlgo := types.ChecksumAlgorithm(randomizeCase(string(test.chAlgo)))
			out, err := createMp(s3client, bucket, obj, withChecksum(randChAlgo), withChecksumType(randChType))
			if err != nil {
				return err
			}

			if out.ChecksumAlgorithm != test.chAlgo {
				return fmt.Errorf("expected the checksum algorithm to be %v, instead got %v", test.chAlgo, out.ChecksumAlgorithm)
			}
			if out.ChecksumType != test.chType {
				return fmt.Errorf("expected the checksum type to be %v, instead got %v", test.chType, out.ChecksumType)
			}
		}

		return nil
	})
}

func CreateMultipartUpload_with_tagging(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testTagging := func(tagging string, result map[string]string, expectedErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			mp, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket:  &bucket,
				Key:     &obj,
				Tagging: &tagging,
			})
			cancel()
			if err == nil && expectedErr != nil {
				return fmt.Errorf("expected err %w, instead got nil", expectedErr)
			}
			if err != nil {
				if expectedErr == nil {
					return err
				}
				switch eErr := expectedErr.(type) {
				case s3err.APIError:
					return checkApiErr(err, eErr)
				default:
					return fmt.Errorf("invalid err provided: %w", expectedErr)
				}
			}

			parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *mp.UploadId)
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{
				{
					ETag:          parts[0].ETag,
					PartNumber:    parts[0].PartNumber,
					ChecksumCRC32: parts[0].ChecksumCRC32,
				},
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
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

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if len(res.TagSet) != len(result) {
				return fmt.Errorf("tag lengths are not equal: (expected): %v, (got): %v",
					len(result), len(res.TagSet))
			}

			for _, tag := range res.TagSet {
				val, ok := result[getString(tag.Key)]
				if !ok {
					return fmt.Errorf("tag key not found: %v", getString(tag.Key))
				}

				if val != getString(tag.Value) {
					return fmt.Errorf("expected the %v tag value to be %v, instead got %v",
						getString(tag.Key), val, getString(tag.Value))
				}
			}

			return nil
		}

		for i, el := range []struct {
			tagging     string
			result      map[string]string
			expectedErr error
		}{
			// success cases
			{"&", map[string]string{}, nil},
			{"&&&", map[string]string{}, nil},
			{"key", map[string]string{"key": ""}, nil},
			{"key&", map[string]string{"key": ""}, nil},
			{"key=&", map[string]string{"key": ""}, nil},
			{"key=val&", map[string]string{"key": "val"}, nil},
			{"key1&key2", map[string]string{"key1": "", "key2": ""}, nil},
			{"key1=val1&key2=val2", map[string]string{"key1": "val1", "key2": "val2"}, nil},
			{"key@=val@", map[string]string{"key@": "val@"}, nil},
			// invalid url-encoded
			{"=", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			{"key%", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// duplicate keys
			{"key=val&key=val", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// invalid tag keys
			{"key?=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key(=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key*=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key$=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key#=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key!=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			// invalid tag values
			{"key=val?", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val(", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val*", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val$", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val#", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val!", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			// success special chars
			{"key-key_key.key/key=value-value_value.value/value",
				map[string]string{"key-key_key.key/key": "value-value_value.value/value"},
				nil},
			// should handle supported encoded characters
			{"key%2E=value%2F", map[string]string{"key.": "value/"}, nil},
			{"key%2D=value%2B", map[string]string{"key-": "value+"}, nil},
			{"key++key=value++value", map[string]string{"key  key": "value  value"}, nil},
			{"key%20key=value%20value", map[string]string{"key key": "value value"}, nil},
			{"key%5Fkey=value%5Fvalue", map[string]string{"key_key": "value_value"}, nil},
		} {
			if s.azureTests {
				// azure doesn't support '@' character
				if strings.Contains(el.tagging, "@") {
					continue
				}
			}
			err := testTagging(el.tagging, el.result, el.expectedErr)
			if err != nil {
				return fmt.Errorf("test case %v faild: %w", i+1, err)
			}
		}
		return nil
	})
}

func CreateMultipartUpload_success(s *S3Conf) error {
	testName := "CreateMultipartUpload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		if out.Bucket == nil {
			return fmt.Errorf("expected bucket name to be not nil")
		}
		if out.Key == nil {
			return fmt.Errorf("expected object name to be not nil")
		}
		if *out.Bucket != bucket {
			return fmt.Errorf("expected bucket name %v, instead got %v",
				bucket, *out.Bucket)
		}
		if *out.Key != obj {
			return fmt.Errorf("expected object name %v, instead got %v",
				obj, *out.Key)
		}

		return nil
	})
}

func CreateMultipartUpload_object_acl_not_supported(s *S3Conf) error {
	testName := "CreateMultipartUpload_object_acl_not_supported"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		for i, modifyInput := range []func(*s3.CreateMultipartUploadInput){
			func(poi *s3.CreateMultipartUploadInput) { poi.ACL = types.ObjectCannedACLPublicRead },
			func(poi *s3.CreateMultipartUploadInput) { poi.GrantFullControl = &testuser.access },
			func(poi *s3.CreateMultipartUploadInput) { poi.GrantRead = &testuser.access },
			func(poi *s3.CreateMultipartUploadInput) { poi.GrantReadACP = &testuser.access },
			func(poi *s3.CreateMultipartUploadInput) { poi.GrantWriteACP = &testuser.access },
		} {
			input := &s3.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    &obj,
			}

			modifyInput(input)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateMultipartUpload(ctx, input)
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented)); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}
