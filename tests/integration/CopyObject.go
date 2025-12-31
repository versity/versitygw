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
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func CopyObject_non_existing_dst_bucket(s *S3Conf) error {
	testName := "CopyObject_non_existing_dst_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr("bucket/obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_not_owned_source_bucket(s *S3Conf) error {
	testName := "CopyObject_not_owned_source_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "my-obj"
		_, err := putObjects(s3client, []string{srcObj}, bucket)
		if err != nil {
			return err
		}

		testuser := getUser("user")

		userClient := s.getUserClient(testuser)

		err = createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		dstBucket := getBucketName()
		err = setup(s, dstBucket)
		if err != nil {
			return err
		}

		err = changeBucketsOwner(s, []string{bucket}, testuser.access)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        getPtr("obj-1"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_copy_to_itself(s *S3Conf) error {
	testName := "CopyObject_copy_to_itself"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopyDest)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_copy_to_itself_invalid_directive(s *S3Conf) error {
	testName := "CopyObject_copy_to_itself_invalid_directive"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			MetadataDirective: types.MetadataDirective("invalid"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMetadataDirective)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_invalid_tagging_directive(s *S3Conf) error {
	testName := "CopyObject_invalid_tagging_directive"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:           &bucket,
			Key:              &obj,
			CopySource:       getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			TaggingDirective: types.TaggingDirective("invalid"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTaggingDirective)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_should_copy_tagging(s *S3Conf) error {
	testName := "CopyObject_should_copy_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dest-object"
		tagging := "foo=bar&baz=quxx"

		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &srcObj,
			Tagging: &tagging,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedTagSet := []types.Tag{
			{Key: getPtr("foo"), Value: getPtr("bar")},
			{Key: getPtr("baz"), Value: getPtr("quxx")},
		}

		if !areTagsSame(res.TagSet, expectedTagSet) {
			return fmt.Errorf("expected the tag set to be %v, instead got %v",
				expectedTagSet, res.TagSet)
		}

		return nil
	})
}

func CopyObject_should_replace_tagging(s *S3Conf) error {
	testName := "CopyObject_should_replace_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: getPtr("key=value&key1=value1"),
		}, s3client)
		if err != nil {
			return err
		}
		testTagging := func(taggging string, result map[string]string, expectedErr error) error {
			dstObj := "destination-object"
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:           &bucket,
				Key:              &dstObj,
				Tagging:          &taggging,
				CopySource:       getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
				TaggingDirective: types.TaggingDirectiveReplace,
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
				Key:    &dstObj,
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
				return fmt.Errorf("test case %v failed: %w", i+1, err)
			}
		}
		return nil
	})
}

func CopyObject_to_itself_with_new_metadata(s *S3Conf) error {
	testName := "CopyObject_to_itself_with_new_metadata"

	meta := map[string]string{
		"Hello": "World",
	}

	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			Metadata:          meta,
			MetadataDirective: types.MetadataDirectiveReplace,
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

		meta = map[string]string{
			"hello": "World",
		}

		if !areMapsSame(resp.Metadata, meta) {
			return fmt.Errorf("expected uploaded object metadata to be %v, instead got %v",
				meta, resp.Metadata)
		}

		// verify updating metadata has correct meta
		meta = map[string]string{
			"new": "Metadata",
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			Metadata:          meta,
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
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

		return nil
	})
}

func CopyObject_copy_source_starting_with_slash(s *S3Conf) error {
	testName := "CopyObject_CopySource_starting_with_slash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "src-obj"
		dstBucket := getBucketName()
		if err := setup(s, dstBucket); err != nil {
			return err
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("/%v/%v", bucket, obj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &dstBucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength == nil {
			return fmt.Errorf("expected content-length to be set, instead got nil")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, *out.ContentLength)
		}

		defer out.Body.Close()

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("invalid object data")
		}

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_invalid_copy_source(s *S3Conf) error {
	testName := "CopyObject_invalid_copy_source"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			copySource  string
			expectedErr s3err.APIError
		}{
			// invalid encoding
			{
				// Invalid hex digits
				copySource:  "bucket/%ZZ",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			{
				// Ends with incomplete escape
				copySource:  "100%/foo/bar/baz",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			{
				// Only one digit after %
				copySource:  "bucket/%A/bar",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			{
				// 'G' is not a hex digit
				copySource:  "bucket/%G1/",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			{
				// Just a single percent sign
				copySource:  "%",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			{
				// Only one hex digit
				copySource:  "bucket/%1",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			{
				// Incomplete multibyte UTF-8
				copySource:  "bucket/%C3%",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
			// invalid bucket name
			{
				// ip v4 address
				copySource:  "192.168.1.1/foo",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceBucket),
			},
			{
				// ip v6 address
				copySource:  "2001:0db8:85a3:0000:0000:8a2e:0370:7334/something",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceBucket),
			},
			{
				// some special chars
				copySource:  "my-buc@k&()t/obj",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceBucket),
			},
			// invalid object key
			{
				// object is missing
				copySource:  "bucket",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceObject),
			},
			{
				// object is missing
				copySource:  "bucket/",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceObject),
			},
			// directory navigation object keys
			{
				copySource:  "bucket/.",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceObject),
			},
			{
				copySource:  "bucket/..",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceObject),
			},
			{
				copySource:  "bucket/../",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceObject),
			},
			{
				copySource:  "bucket/foo/ba/../../../r/baz",
				expectedErr: s3err.GetAPIError(s3err.ErrInvalidCopySourceObject),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        getPtr("obj"),
				CopySource: &test.copySource,
			})
			cancel()
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return err
			}
		}

		return nil
	})
}

func CopyObject_non_existing_dir_object(s *S3Conf) error {
	testName := "CopyObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		_, err = putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "my-obj/"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return nil
		}

		return nil
	})
}

func CopyObject_should_copy_meta_props(s *S3Conf) error {
	testName := "CopyObject_should_copy_meta_props"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dest-object"

		cType, cEnc, cDesp, cLang, cLength := "application/json", "base64", "test-desp", "us", int64(100)
		cacheControl, expires := "no-cache", time.Now().Add(time.Hour*10)
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		_, err := putObjectWithData(cLength, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &srcObj,
			ContentDisposition: &cDesp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			ContentType:        &cType,
			CacheControl:       &cacheControl,
			Expires:            &expires,
			Metadata:           meta,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(bucket + "/" + srcObj),
		})
		cancel()
		if err != nil {
			return err
		}

		return checkObjectMetaProps(s3client, bucket, dstObj, ObjectMetaProps{
			ContentLength:      cLength,
			ContentType:        cType,
			ContentEncoding:    cEnc,
			ContentDisposition: cDesp,
			ContentLanguage:    cLang,
			CacheControl:       cacheControl,
			ExpiresString:      expires.UTC().Format(timefmt),
			Metadata:           meta,
		})
	})
}

func CopyObject_should_replace_meta_props(s *S3Conf) error {
	testName := "CopyObject_should_replace_meta_props"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dest-object"
		expire := time.Now().Add(time.Minute * 10)
		contentLength := int64(200)

		_, err := putObjectWithData(contentLength, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &srcObj,
			ContentDisposition: getPtr("test"),
			ContentEncoding:    getPtr("test"),
			ContentLanguage:    getPtr("test"),
			ContentType:        getPtr("test"),
			CacheControl:       getPtr("test"),
			Expires:            &expire,
			Metadata: map[string]string{
				"key": "val",
			},
		}, s3client)
		if err != nil {
			return err
		}

		cType, cEnc, cDesp, cLang := "application/binary", "hex", "desp", "mex"
		cacheControl, expires := "no-cache", time.Now().Add(time.Hour*10)
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:             &bucket,
			Key:                &dstObj,
			CopySource:         getPtr(bucket + "/" + srcObj),
			MetadataDirective:  types.MetadataDirectiveReplace,
			ContentDisposition: &cDesp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			ContentType:        &cType,
			CacheControl:       &cacheControl,
			Expires:            &expires,
			Metadata:           meta,
		})
		cancel()
		if err != nil {
			return err
		}

		return checkObjectMetaProps(s3client, bucket, dstObj, ObjectMetaProps{
			ContentLength:      contentLength,
			ContentType:        cType,
			ContentEncoding:    cEnc,
			ContentDisposition: cDesp,
			ContentLanguage:    cLang,
			CacheControl:       cacheControl,
			ExpiresString:      expires.UTC().Format(timefmt),
			Metadata:           meta,
		})
	})
}

func CopyObject_invalid_legal_hold(s *S3Conf) error {
	testName := "CopyObject_invalid_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus("invalid_status"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus))
	}, withLock())
}
func CopyObject_invalid_object_lock_mode(s *S3Conf) error {
	testName := "CopyObject_invalid_object_lock_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		rDate := time.Now().Add(time.Hour * 20)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockRetainUntilDate: &rDate,
			ObjectLockMode:            types.ObjectLockMode("invalid_mode"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode))
	}, withLock())
}

func CopyObject_with_legal_hold(s *S3Conf) error {
	testName := "CopyObject_with_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected the copied object legal hold status to be %v, instead got %v",
				types.ObjectLockLegalHoldStatusOn, res.LegalHold.Status)
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: dstObj, removeOnlyLeglHold: true}})
	}, withLock())
}

func CopyObject_with_retention_lock(s *S3Conf) error {
	testName := "CopyObject_with_retention_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(200, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		retDate := time.Now().Add(time.Hour * 7)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &retDate,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Retention.Mode != types.ObjectLockRetentionModeGovernance {
			return fmt.Errorf("expected the copied object retention mode to be %v, instead got %v",
				types.ObjectLockRetentionModeGovernance, res.Retention.Mode)
		}
		if res.Retention.RetainUntilDate.UTC().Unix() != retDate.UTC().Unix() {
			return fmt.Errorf("expected the retention date to be %v, instead got %v",
				retDate.Format(time.RFC1123), res.Retention.RetainUntilDate.Format(time.RFC1123))
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: dstObj}})
	}, withLock())
}

func CopyObject_conditional_reads(s *S3Conf) error {
	testName := "CopyObject_conditional_reads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		obj, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		}, s3client)
		if err != nil {
			return err
		}

		errMod := s3err.GetAPIError(s3err.ErrNotModified)
		errCond := s3err.GetAPIError(s3err.ErrPreconditionFailed)

		// sleep one second to get dates before and after
		// the object creation
		time.Sleep(time.Second * 1)

		before := time.Now().AddDate(0, 0, -3)
		after := time.Now()
		etag := obj.res.ETag
		etagTrimmed := strings.Trim(*etag, `"`)

		for i, test := range []struct {
			ifmatch           *string
			ifnonematch       *string
			ifmodifiedsince   *time.Time
			ifunmodifiedsince *time.Time
			err               error
		}{
			// all the cases when preconditions are either empty, true or false
			{getPtr("invalid_etag"), getPtr("invalid_etag"), &before, &before, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), &before, &after, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), &before, nil, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), &after, &before, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), &after, &after, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), &after, nil, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), nil, &before, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), nil, &after, errCond},
			{getPtr("invalid_etag"), getPtr("invalid_etag"), nil, nil, errCond},

			{getPtr("invalid_etag"), etag, &before, &before, errCond},
			{getPtr("invalid_etag"), etag, &before, &after, errCond},
			{getPtr("invalid_etag"), etag, &before, nil, errCond},
			{getPtr("invalid_etag"), etag, &after, &before, errCond},
			{getPtr("invalid_etag"), etag, &after, &after, errCond},
			{getPtr("invalid_etag"), etag, &after, nil, errCond},
			{getPtr("invalid_etag"), etag, nil, &before, errCond},
			{getPtr("invalid_etag"), etag, nil, &after, errCond},
			{getPtr("invalid_etag"), etag, nil, nil, errCond},

			{getPtr("invalid_etag"), nil, &before, &before, errCond},
			{getPtr("invalid_etag"), nil, &before, &after, errCond},
			{getPtr("invalid_etag"), nil, &before, nil, errCond},
			{getPtr("invalid_etag"), nil, &after, &before, errCond},
			{getPtr("invalid_etag"), nil, &after, &after, errCond},
			{getPtr("invalid_etag"), nil, &after, nil, errCond},
			{getPtr("invalid_etag"), nil, nil, &before, errCond},
			{getPtr("invalid_etag"), nil, nil, &after, errCond},
			{getPtr("invalid_etag"), nil, nil, nil, errCond},

			{etag, getPtr("invalid_etag"), &before, &before, nil},
			{etag, getPtr("invalid_etag"), &before, &after, nil},
			{etag, getPtr("invalid_etag"), &before, nil, nil},
			{etag, getPtr("invalid_etag"), &after, &before, nil},
			{etag, getPtr("invalid_etag"), &after, &after, nil},
			{etag, getPtr("invalid_etag"), &after, nil, nil},
			{etag, getPtr("invalid_etag"), nil, &before, nil},
			{etag, getPtr("invalid_etag"), nil, &after, nil},
			{etag, getPtr("invalid_etag"), nil, nil, nil},

			{etag, etag, &before, &before, errMod},
			{etag, etag, &before, &after, errMod},
			{etag, etag, &before, nil, errMod},
			{etag, etag, &after, &before, errMod},
			{etag, etag, &after, &after, errMod},
			{etag, etag, &after, nil, errMod},
			{etag, etag, nil, &before, errMod},
			{etag, etag, nil, &after, errMod},
			{etag, etag, nil, nil, errMod},

			{etag, nil, &before, &before, nil},
			{etag, nil, &before, &after, nil},
			{etag, nil, &before, nil, nil},
			{etag, nil, &after, &before, errMod},
			{etag, nil, &after, &after, errMod},
			{etag, nil, &after, nil, errMod},
			{etag, nil, nil, &before, nil},
			{etag, nil, nil, &after, nil},
			{etag, nil, nil, nil, nil},

			{nil, getPtr("invalid_etag"), &before, &before, errCond},
			{nil, getPtr("invalid_etag"), &before, &after, nil},
			{nil, getPtr("invalid_etag"), &before, nil, nil},
			{nil, getPtr("invalid_etag"), &after, &before, errCond},
			{nil, getPtr("invalid_etag"), &after, &after, nil},
			{nil, getPtr("invalid_etag"), &after, nil, nil},
			{nil, getPtr("invalid_etag"), nil, &before, errCond},
			{nil, getPtr("invalid_etag"), nil, &after, nil},
			{nil, getPtr("invalid_etag"), nil, nil, nil},

			{nil, etag, &before, &before, errCond},
			{nil, etag, &before, &after, errMod},
			{nil, etag, &before, nil, errMod},
			{nil, etag, &after, &before, errCond},
			{nil, etag, &after, &after, errMod},
			{nil, etag, &after, nil, errMod},
			{nil, etag, nil, &before, errCond},
			{nil, etag, nil, &after, errMod},
			{nil, etag, nil, nil, errMod},

			{nil, nil, &before, &before, errCond},
			{nil, nil, &before, &after, nil},
			{nil, nil, &before, nil, nil},
			{nil, nil, &after, &before, errCond},
			{nil, nil, &after, &after, errMod},
			{nil, nil, &after, nil, errMod},
			{nil, nil, nil, &before, errCond},
			{nil, nil, nil, &after, nil},
			{nil, nil, nil, nil, nil},

			// if-match, if-non-match without quotes
			{&etagTrimmed, getPtr("invalid_etag"), &before, &before, nil},
			{&etagTrimmed, getPtr("invalid_etag"), &before, &after, nil},
			{&etagTrimmed, getPtr("invalid_etag"), &before, nil, nil},
			{&etagTrimmed, getPtr("invalid_etag"), &after, &before, nil},
			{&etagTrimmed, getPtr("invalid_etag"), &after, &after, nil},
			{&etagTrimmed, getPtr("invalid_etag"), &after, nil, nil},
			{&etagTrimmed, getPtr("invalid_etag"), nil, &before, nil},
			{&etagTrimmed, getPtr("invalid_etag"), nil, &after, nil},
			{&etagTrimmed, getPtr("invalid_etag"), nil, nil, nil},

			{&etagTrimmed, &etagTrimmed, &before, &before, errMod},
			{&etagTrimmed, &etagTrimmed, &before, &after, errMod},
			{&etagTrimmed, &etagTrimmed, &before, nil, errMod},
			{&etagTrimmed, &etagTrimmed, &after, &before, errMod},
			{&etagTrimmed, &etagTrimmed, &after, &after, errMod},
			{&etagTrimmed, &etagTrimmed, &after, nil, errMod},
			{&etagTrimmed, &etagTrimmed, nil, &before, errMod},
			{&etagTrimmed, &etagTrimmed, nil, &after, errMod},
			{&etagTrimmed, &etagTrimmed, nil, nil, errMod},

			{&etagTrimmed, nil, &before, &before, nil},
			{&etagTrimmed, nil, &before, &after, nil},
			{&etagTrimmed, nil, &before, nil, nil},
			{&etagTrimmed, nil, &after, &before, errMod},
			{&etagTrimmed, nil, &after, &after, errMod},
			{&etagTrimmed, nil, &after, nil, errMod},
			{&etagTrimmed, nil, nil, &before, nil},
			{&etagTrimmed, nil, nil, &after, nil},
			{&etagTrimmed, nil, nil, nil, nil},

			{nil, &etagTrimmed, &before, &before, errCond},
			{nil, &etagTrimmed, &before, &after, errMod},
			{nil, &etagTrimmed, &before, nil, errMod},
			{nil, &etagTrimmed, &after, &before, errCond},
			{nil, &etagTrimmed, &after, &after, errMod},
			{nil, &etagTrimmed, &after, nil, errMod},
			{nil, &etagTrimmed, nil, &before, errCond},
			{nil, &etagTrimmed, nil, &after, errMod},
			{nil, &etagTrimmed, nil, nil, errMod},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:                      &bucket,
				Key:                         getPtr("dst-obj"),
				CopySource:                  getPtr(fmt.Sprintf("%s/%s", bucket, key)),
				CopySourceIfMatch:           test.ifmatch,
				CopySourceIfNoneMatch:       test.ifnonematch,
				CopySourceIfModifiedSince:   test.ifmodifiedsince,
				CopySourceIfUnmodifiedSince: test.ifunmodifiedsince,
			})
			cancel()
			if test.err == nil && err != nil {
				return fmt.Errorf("test case %d failed: expected no error, but got %v", i, err)
			}
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

func CopyObject_with_metadata(s *S3Conf) error {
	testName := "CopyObject_with_metadata"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "src-obj", "dst-obj"

		_, err := putObjectWithData(2, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
			Metadata: map[string]string{
				"key": "value",
			},
		}, s3client)
		if err != nil {
			return err
		}

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

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &dstObj,
			Metadata:          meta,
			CopySource:        getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &dstObj,
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

func CopyObject_invalid_checksum_algorithm(s *S3Conf) error {
	testName := "CopyObject_invalid_checksum_algorithm"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			ChecksumAlgorithm: types.ChecksumAlgorithm("invalid_checksum_algorithm"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_create_checksum_on_copy(s *S3Conf) error {
	testName := "CopyObject_create_checksum_on_copy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "source-object"
		dstObj := "destination-object"
		_, err := putObjectWithData(300, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &dstObj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.CopyObjectResult.ChecksumSHA256) == "" {
			return fmt.Errorf("expected non nil sha256 checksum")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &dstObj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.ChecksumSHA256) != getString(res.CopyObjectResult.ChecksumSHA256) {
			return fmt.Errorf("expected the sha256 checksum to be %v, instead got %v",
				getString(res.CopyObjectResult.ChecksumSHA256), getString(out.ChecksumSHA256))
		}

		return nil
	})
}

func CopyObject_should_copy_the_existing_checksum(s *S3Conf) error {
	testName := "CopyObject_should_copy_the_existing_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "source-object"
		dstObj := "destination-object"
		out, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32c,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyObjectResult.ChecksumCRC32C == nil {
			return fmt.Errorf("expected non empty crc32c checksum")
		}
		if getString(res.CopyObjectResult.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
			return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
				getString(out.res.ChecksumCRC32C), getString(res.CopyObjectResult.ChecksumCRC32C))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &dstObj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(resp.ChecksumCRC32C) != getString(res.CopyObjectResult.ChecksumCRC32C) {
			return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
				getString(res.CopyObjectResult.ChecksumCRC32C), getString(resp.ChecksumCRC32C))
		}

		return nil
	})
}

func CopyObject_should_replace_the_existing_checksum(s *S3Conf) error {
	testName := "CopyObject_should_replace_the_existing_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "source-object"
		dstObj := "destination-object"

		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &dstObj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1, // replace crc32 with sha1
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyObjectResult.ChecksumSHA1 == nil {
			return fmt.Errorf("expected non empty sha1 checksum")
		}
		if res.CopyObjectResult.ChecksumCRC32 != nil {
			return fmt.Errorf("expected empty crc32 checksum, instead got %v",
				*res.CopyObjectResult.ChecksumCRC32)
		}

		return nil
	})
}

func CopyObject_to_itself_by_replacing_the_checksum(s *S3Conf) error {
	testName := "CopyObject_to_itself_by_replacing_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(400, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32, // replace sh256 with crc32
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.CopyObjectResult.ChecksumCRC32 == nil {
			return fmt.Errorf("expected non empty crc32 checksum")
		}
		if out.CopyObjectResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected empty crc32c checksum")
		}
		if out.CopyObjectResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected empty sha1 checksum")
		}
		if out.CopyObjectResult.ChecksumSHA256 != nil {
			return fmt.Errorf("expected empty sha256 checksum")
		}
		if out.CopyObjectResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected empty crc64nvme checksum")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &obj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumCRC32 == nil {
			return fmt.Errorf("expected non empty crc32 checksum")
		}
		if res.ChecksumCRC32C != nil {
			return fmt.Errorf("expected empty crc32c checksum")
		}
		if res.ChecksumSHA1 != nil {
			return fmt.Errorf("expected empty sha1 checksum")
		}
		if res.ChecksumSHA256 != nil {
			return fmt.Errorf("expected empty sha256 checksum")
		}
		if res.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected empty crc64nvme checksum")
		}

		return nil
	})
}

func CopyObject_success(s *S3Conf) error {
	testName := "CopyObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my obj with spaces"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &dstBucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength == nil {
			return fmt.Errorf("expected content-length to be set, instead got nil")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, *out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("invalid object data")
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return nil
		}

		return nil
	})
}
