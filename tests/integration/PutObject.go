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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sync/errgroup"
)

func PutObject_non_existing_bucket(s *S3Conf) error {
	testName := "PutObject_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"my-obj"}, "non-existing-bucket")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_special_chars(s *S3Conf) error {
	testName := "PutObject_special_chars"

	objnames := []string{
		"my!key", "my-key", "my_key", "my.key", "my'key", "my(key", "my)key",
		"my&key", "my@key", "my=key", "my;key", "my:key", "my key", "my,key",
		"my?key", "my^key", "my{}key", "my%key", "my`key",
		"my[]key", "my~key", "my<>key", "my|key", "my#key",
	}
	if !s.azureTests {
		// azure currently can't handle backslashes in object names
		objnames = append(objnames, "my\\key")
	}

	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, objnames, bucket)
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

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the objects to be %vß, instead got %v",
				objStrings(objs), objStrings(res.Contents))
		}

		return nil
	})
}

func PutObject_tagging(s *S3Conf) error {
	testName := "PutObject_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testTagging := func(taggging string, result map[string]string, expectedErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)

			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     &obj,
				Tagging: &taggging,
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
				return fmt.Errorf("tag lengths are not equal: (expected): %v, (got): %v", len(result), len(res.TagSet))
			}

			for _, tag := range res.TagSet {
				val, ok := result[getString(tag.Key)]
				if !ok {
					return fmt.Errorf("tag key not found: %v", getString(tag.Key))
				}

				if val != getString(tag.Value) {
					return fmt.Errorf("expected the %v tag value to be %v, instead got %v", getString(tag.Key), val, getString(tag.Value))
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
			{"key-key_key.key/key=value-value_value.value/value", map[string]string{"key-key_key.key/key": "value-value_value.value/value"}, nil},
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
				return fmt.Errorf("test case %v failed: %w", i+1, err)
			}
		}
		return nil
	})
}

func PutObject_missing_object_lock_retention_config(s *S3Conf) error {
	testName := "PutObject_missing_object_lock_retention_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:         &bucket,
			Key:            &key,
			ObjectLockMode: types.ObjectLockModeCompliance,
		})
		cancel()
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
		// 	return err
		// }

		retainDate := time.Now().Add(time.Hour * 48)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &key,
			ObjectLockRetainUntilDate: &retainDate,
		})
		cancel()
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
		// 	return err
		// }

		return nil
	})
}

func PutObject_with_object_lock(s *S3Conf) error {
	testName := "PutObject_with_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		retainUntilDate := time.Now().AddDate(1, 0, 0)

		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
			ObjectLockMode:            types.ObjectLockModeCompliance,
			ObjectLockRetainUntilDate: &retainUntilDate,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.ObjectLockMode != types.ObjectLockModeCompliance {
			return fmt.Errorf("expected object lock mode to be %v, instead got %v", types.ObjectLockModeCompliance, out.ObjectLockMode)
		}
		if out.ObjectLockLegalHoldStatus != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected object lock mode to be %v, instead got %v", types.ObjectLockLegalHoldStatusOn, out.ObjectLockLegalHoldStatus)
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, removeLegalHold: true, isCompliance: true}})
	}, withLock())
}

func PutObject_invalid_legal_hold(s *S3Conf) error {
	testName := "PutObject_invalid_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus("invalid_status"),
		}, s3client)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus))
	}, withLock())
}

func PutObject_invalid_object_lock_mode(s *S3Conf) error {
	testName := "PutObject_invalid_object_lock_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rDate := time.Now().Add(time.Hour * 10)
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockRetainUntilDate: &rDate,
			ObjectLockMode:            types.ObjectLockMode("invalid_mode"),
		}, s3client)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode))
	}, withLock())
}

func PutObject_conditional_writes(s *S3Conf) error {
	testName := "PutObject_conditional_writes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		res, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Body:   bytes.NewReader([]byte("dummy")),
		}, s3client)
		if err != nil {
			return err
		}

		etag := res.res.ETag
		etagTrimmed := strings.Trim(*etag, `"`)
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
				Bucket:      &bucket,
				Key:         &test.obj,
				Body:        bytes.NewReader([]byte("dummy")),
				IfMatch:     test.ifMatch,
				IfNoneMatch: test.ifNoneMatch,
			}, s3client)
			if err == nil {
				// azure blob storage generates different ETags for
				// the exact same data.
				// to avoid ETag collision reassign the etag value
				*etag = *res.res.ETag
				etagTrimmed = strings.Trim(*res.res.ETag, `"`)
			}
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

func PutObject_with_metadata(s *S3Conf) error {
	testName := "PutObject_with_metadata"
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
		_, err := putObjectWithData(3, &s3.PutObjectInput{
			Bucket:   &bucket,
			Key:      &obj,
			Metadata: meta,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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

func PutObject_checksum_algorithm_and_header_mismatch(s *S3Conf) error {
	testName := "PutObject_checksum_algorithm_and_header_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
			ChecksumCRC32C:    getPtr("m0cB1Q=="),
		})
		cancel()
		// FIXME: The error message for PutObject is not properly serialized by the sdk
		// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

		// if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr("x-amz-sdk-checksum-algorithm"); err != nil {
		// 	return err
		// }
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_multiple_checksum_headers(s *S3Conf) error {
	testName := "PutObject_multiple_checksum_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			ChecksumCRC32C: getPtr("m0cB1Q=="),
		}, s3client)
		// FIXME: The error message for PutObject is not properly serialized by the sdk
		// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
		// 	return err
		// }
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}

		// Empty checksums case
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr(""),
			ChecksumCRC32C: getPtr(""),
		}, s3client)
		// FIXME: The error message for PutObject is not properly serialized by the sdk
		// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
		// 	return err
		// }
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_invalid_checksum_header(s *S3Conf) error {
	testName := "PutObject_invalid_checksum_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, el := range []struct {
			algo      string
			crc32     *string
			crc32c    *string
			sha1      *string
			sha256    *string
			crc64nvme *string
		}{
			// CRC32 tests
			{
				algo:  "crc32",
				crc32: getPtr(""),
			},
			{
				algo:  "crc32",
				crc32: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:  "crc32",
				crc32: getPtr("YXNrZGpoZ2tqYXNo"), // valid base64 but not crc32
			},
			// CRC32C tests
			{
				algo:   "crc32c",
				crc32c: getPtr(""),
			},
			{
				algo:   "crc32c",
				crc32c: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "crc32c",
				crc32c: getPtr("c2RhZnNhZGZzZGFm"), // valid base64 but not crc32c
			},
			// SHA1 tests
			{
				algo: "sha1",
				sha1: getPtr(""),
			},
			{
				algo: "sha1",
				sha1: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo: "sha1",
				sha1: getPtr("c2RhZmRhc2Zkc2Fmc2RhZnNhZGZzYWRm"), // valid base64 but not sha1
			},
			// SHA256 tests
			{
				algo:   "sha256",
				sha256: getPtr(""),
			},
			{
				algo:   "sha256",
				sha256: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "sha256",
				sha256: getPtr("ZGZnbmRmZ2hoZmRoZmdkaA=="), // valid base64 but not sha56
			},
			// CRC64Nvme tests
			{
				algo:   "crc64nvme",
				sha256: getPtr(""),
			},
			{
				algo:   "crc64nvme",
				sha256: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "crc64nvme",
				sha256: getPtr("ZHNhZmRzYWZzZGFmZHNhZg=="), // valid base64 but not crc64nvme
			},
		} {
			_, err := putObjectWithData(int64(i*100), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumCRC32:     el.crc32,
				ChecksumCRC32C:    el.crc32c,
				ChecksumSHA1:      el.sha1,
				ChecksumSHA256:    el.sha256,
				ChecksumCRC64NVME: el.crc64nvme,
			}, s3client)

			// FIXME: The error message for PutObject is not properly serialized by the sdk
			// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

			// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			// 	return err
			// }
			if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutObject_incorrect_checksums(s *S3Conf) error {
	testName := "PutObject_incorrect_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, el := range []struct {
			algo      types.ChecksumAlgorithm
			crc32     *string
			crc32c    *string
			sha1      *string
			sha256    *string
			crc64nvme *string
		}{
			{
				algo:  types.ChecksumAlgorithmCrc32,
				crc32: getPtr("DUoRhQ=="),
			},
			{
				algo:   types.ChecksumAlgorithmCrc32c,
				crc32c: getPtr("yZRlqg=="),
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				sha1: getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			},
			{
				algo:   types.ChecksumAlgorithmSha256,
				sha256: getPtr("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
			},
			{
				algo:      types.ChecksumAlgorithmCrc64nvme,
				crc64nvme: getPtr("sV264W+gYBI="),
			},
		} {
			_, err := putObjectWithData(int64(i*100), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumCRC32:     el.crc32,
				ChecksumCRC32C:    el.crc32c,
				ChecksumSHA1:      el.sha1,
				ChecksumSHA256:    el.sha256,
				ChecksumCRC64NVME: el.crc64nvme,
			}, s3client)
			if err := checkApiErr(err, s3err.GetChecksumBadDigestErr(el.algo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutObject_default_checksum(s *S3Conf) error {
	testName := "PutObject_default_checksum"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		customClient := s3.NewFromConfig(s.Config(), func(o *s3.Options) {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationUnset
		})

		obj := "my-obj"

		out, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, customClient)
		if err != nil {
			return err
		}

		if out.res.ChecksumCRC64NVME == nil {
			return fmt.Errorf("expected non nil default crc64nvme checksum")
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := customClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &obj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
			return fmt.Errorf("expected the object crc64nvme checksum to be %v, instead got %v", getString(res.ChecksumCRC64NVME), getString(out.res.ChecksumCRC64NVME))
		}

		return nil
	})
}

func PutObject_checksums_success(s *S3Conf) error {
	testName := "PutObject_checksums_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			res, err := putObjectWithData(int64(i*200), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumAlgorithm: algo,
			}, s3client)
			if err != nil {
				return err
			}

			if res.res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the object checksum type to be %v, instead got %v", types.ChecksumTypeFullObject, res.res.ChecksumType)
			}

			switch algo {
			case types.ChecksumAlgorithmCrc32:
				if res.res.ChecksumCRC32 == nil {
					return fmt.Errorf("expected non empty crc32 checksum in the response")
				}
			case types.ChecksumAlgorithmCrc32c:
				if res.res.ChecksumCRC32C == nil {
					return fmt.Errorf("expected non empty crc32c checksum in the response")
				}
			case types.ChecksumAlgorithmSha1:
				if res.res.ChecksumSHA1 == nil {
					return fmt.Errorf("expected non empty sha1 checksum in the response")
				}
			case types.ChecksumAlgorithmSha256:
				if res.res.ChecksumSHA256 == nil {
					return fmt.Errorf("expected non empty sha256 checksum in the response")
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if res.res.ChecksumCRC64NVME == nil {
					return fmt.Errorf("expected non empty crc64nvme checksum in the response")
				}
			}
		}

		return nil
	})
}

func PutObject_racey_success(s *S3Conf) error {
	testName := "PutObject_racey_success"
	runF(testName)
	bucket, obj, lockStatus := getBucketName(), "my-obj", true

	client := s.GetClient()
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectLockEnabledForBucket: &lockStatus,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	eg := errgroup.Group{}
	for range 10 {
		eg.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			return err
		})
	}
	err = eg.Wait()

	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func PutObject_success(s *S3Conf) error {
	testName := "PutObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		lgth := int64(100)
		res, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		}, s3client)
		if err != nil {
			return err
		}

		// skip the ETag check for azure tests
		if !s.azureTests {
			etag, err := calculateEtag(res.data)
			if err != nil {
				return err
			}

			if getString(res.res.ETag) != etag {
				return fmt.Errorf("expected ETag to be %s, intead got %s", getString(res.res.ETag), etag)
			}
		}
		if res.res.Size == nil {
			return fmt.Errorf("unexpected nil object Size")
		}
		if *res.res.Size != lgth {
			return fmt.Errorf("expected the object size to be %v, instead got %v", lgth, *res.res.Size)
		}

		return nil
	})
}

func PutObject_invalid_credentials(s *S3Conf) error {
	testName := "PutObject_invalid_credentials"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		newconf := *s
		newconf.awsSecret = newconf.awsSecret + "badpassword"
		client := newconf.GetClient()
		_, err := putObjects(client, []string{"my-obj"}, bucket)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
	})
}

func PutObject_invalid_object_names(s *S3Conf) error {
	testName := "PutObject_invalid_object_names"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, obj := range []string{
			".",
			"..",
			"./",
			"/.",
			"//",
			"../",
			"/..",
			"/..",
			"../.",
			"../../../.",
			"../../../etc/passwd",
			"../../../../tmp/foo",
			"for/../../bar/",
			"a/a/a/../../../../../etc/passwd",
			"/a/../../b/../../c/../../../etc/passwd",
		} {
			_, err := putObjects(s3client, []string{obj}, bucket)
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutObject_false_negative_object_names(s *S3Conf) error {
	testName := "PutObject_false_negative_object_names"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []string{
			"%252e%252e%252fetc/passwd",            // double encoding
			"%2e%2e/%2e%2e/%2e%2e/.ssh/id_rsa",     // double URL-encoded
			"%u002e%u002e/%u002e%u002e/etc/passwd", // unicode escape
			"..%2f..%2f..%2fsecret/file.txt",       // URL-encoded
			"..%c0%af..%c0%afetc/passwd",           // UTF-8 overlong trick
			".../.../.../target.txt",
			"..\\u2215..\\u2215etc/passwd",             // Unicode division slash
			"dir/%20../file.txt",                       // encoded space
			"dir/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", // overlong UTF-8 encoding
			"logs/latest -> /etc/passwd",               // symlink attacks
			//TODO: add this test case in advanced routing
			// "/etc/passwd" // absolute path injection
		}
		_, err := putObjects(s3client, objs, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Contents) != len(objs) {
			return fmt.Errorf("expected %v objects, instead got %v", len(objs), len(res.Contents))
		}

		for i, obj := range res.Contents {
			if *obj.Key != objs[i] {
				return fmt.Errorf("expected the %vth object name to be %s, instead got %s", i+1, objs[i], *obj.Key)
			}
		}

		return nil
	})
}
