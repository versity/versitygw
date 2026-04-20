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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
)

func HeadObject_non_existing_object(s *S3Conf) error {
	testName := "HeadObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_invalid_part_number(s *S3Conf) error {
	testName := "HeadObject_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(-3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_non_existing_dir_object(s *S3Conf) error {
	testName := "HeadObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "my-obj", int64(1234567)
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket:   &bucket,
			Key:      &obj,
			Metadata: meta,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_directory_object_noslash(s *S3Conf) error {
	testName := "HeadObject_directory_object_noslash"
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
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	})
}

const defaultContentType = "binary/octet-stream"

func HeadObject_not_enabled_checksum_mode(s *S3Conf) error {
	testName := "HeadObject_not_enabled_checksum_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(500, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
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

		if res.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, instead got %v", *res.ChecksumCRC32)
		}
		if res.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v", *res.ChecksumCRC32C)
		}
		if res.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v", *res.ChecksumSHA1)
		}
		if res.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, instead got %v", *res.ChecksumSHA256)
		}

		return nil
	})
}

func HeadObject_checksums(s *S3Conf) error {
	testName := "HeadObject_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []struct {
			key          string
			checksumAlgo types.ChecksumAlgorithm
		}{
			{
				key:          "obj-1",
				checksumAlgo: types.ChecksumAlgorithmCrc32,
			},
			{
				key:          "obj-2",
				checksumAlgo: types.ChecksumAlgorithmCrc32c,
			},
			{
				key:          "obj-3",
				checksumAlgo: types.ChecksumAlgorithmSha1,
			},
			{
				key:          "obj-4",
				checksumAlgo: types.ChecksumAlgorithmSha256,
			},
			{
				key:          "obj-5",
				checksumAlgo: types.ChecksumAlgorithmCrc64nvme,
			},
		}

		for i, el := range objs {
			out, err := putObjectWithData(int64(i*200), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &el.key,
				ChecksumAlgorithm: el.checksumAlgo,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:       &bucket,
				Key:          &el.key,
				ChecksumMode: types.ChecksumModeEnabled,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the %v object checksum type to be %v, instaed got %v", el.key, types.ChecksumTypeFullObject, res.ChecksumType)
			}
			if getString(res.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
				return fmt.Errorf("expected crc32 checksum to be %v, instead got %v", getString(out.res.ChecksumCRC32), getString(res.ChecksumCRC32))
			}
			if getString(res.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
				return fmt.Errorf("expected crc32c checksum to be %v, instead got %v", getString(out.res.ChecksumCRC32C), getString(res.ChecksumCRC32C))
			}
			if getString(res.ChecksumSHA1) != getString(out.res.ChecksumSHA1) {
				return fmt.Errorf("expected sha1 checksum to be %v, instead got %v", getString(out.res.ChecksumSHA1), getString(res.ChecksumSHA1))
			}
			if getString(res.ChecksumSHA256) != getString(out.res.ChecksumSHA256) {
				return fmt.Errorf("expected sha256 checksum to be %v, instead got %v", getString(out.res.ChecksumSHA256), getString(res.ChecksumSHA256))
			}
			if getString(res.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
				return fmt.Errorf("expected crc64nvme checksum to be %v, instead got %v", getString(out.res.ChecksumCRC64NVME), getString(res.ChecksumCRC64NVME))
			}
		}

		return nil
	})
}

func HeadObject_invalid_parent_dir(s *S3Conf) error {
	testName := "HeadObject_invalid_parent_dir"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "not-a-dir", int64(1)

		_, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_with_range(s *S3Conf) error {
	testName := "HeadObject_with_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, objLength := "my-obj", int64(100)
		_, err := putObjectWithData(objLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testRange := func(rg, contentRange string, cLength int64, expectErr bool) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Range:  &rg,
			})
			cancel()
			if err == nil && expectErr {
				return fmt.Errorf("%v: expected err 'RequestedRangeNotSatisfiable' error, instead got nil", rg)
			}
			if err != nil {
				if !expectErr {
					return err
				}

				var ae smithy.APIError
				if errors.As(err, &ae) {
					if ae.ErrorCode() != "RequestedRangeNotSatisfiable" {
						return fmt.Errorf("%v: expected RequestedRangeNotSatisfiable, instead got %v", rg, ae.ErrorCode())
					}
					if ae.ErrorMessage() != "Requested Range Not Satisfiable" {
						return fmt.Errorf("%v: expected the error message to be 'Requested Range Not Satisfiable', instead got %v", rg, ae.ErrorMessage())
					}
					return nil
				}
				return fmt.Errorf("%v: invalid error got %w", rg, err)
			}

			if getString(res.AcceptRanges) != "bytes" {
				return fmt.Errorf("%v: expected accept ranges to be 'bytes', instead got %v", rg, getString(res.AcceptRanges))
			}
			if res.ContentLength == nil {
				return fmt.Errorf("%v: expected non nil content-length", rg)
			}
			if *res.ContentLength != cLength {
				return fmt.Errorf("%v: expected content-length to be %v, instead got %v", rg, cLength, *res.ContentLength)
			}
			if getString(res.ContentRange) != contentRange {
				return fmt.Errorf("%v: expected content-range to be %v, instead got %v", rg, contentRange, getString(res.ContentRange))
			}
			return nil
		}

		// Reference server expectations for a 100-byte object.
		for _, el := range []struct {
			objRange      string
			contentRange  string
			contentLength int64
			expectedErr   bool
		}{
			// The following inputs should NOT produce an error and return the full object with empty Content-Range.
			{"bytes=,", "", objLength, false},
			{"bytes= -1", "", objLength, false},
			{"bytes=--1", "", objLength, false},
			{"bytes=0 -1", "", objLength, false},
			{"bytes=0--1", "", objLength, false},
			{"bytes=10-5", "", objLength, false}, // start > end treated as invalid
			{"bytes=abc", "", objLength, false},
			{"bytes=a-z", "", objLength, false},
			{"foo=0-1", "", objLength, false},          // unsupported unit
			{"bytes=00-01", "bytes 0-1/100", 2, false}, // valid numeric despite leading zeros
			{"bytes=abc-xyz", "", objLength, false},    // retain legacy invalid pattern
			{"bytes=100-x", "", objLength, false},
			{"bytes=0-0,1-2", "", objLength, false}, // multiple ranges unsupported -> ignore

			// Valid suffix ranges (negative forms)
			{"bytes=-1", "bytes 99-99/100", 1, false},
			{"bytes=-2", "bytes 98-99/100", 2, false},
			{"bytes=-10", "bytes 90-99/100", 10, false},
			{"bytes=-100", "bytes 0-99/100", objLength, false},
			{"bytes=-101", "bytes 0-99/100", objLength, false}, // larger than object -> entire object

			// Standard byte ranges
			{"bytes=0-0", "bytes 0-0/100", 1, false},
			{"bytes=0-99", "bytes 0-99/100", objLength, false},
			{"bytes=0-100", "bytes 0-99/100", objLength, false}, // end past object -> trimmed
			{"bytes=0-999999", "bytes 0-99/100", objLength, false},
			{"bytes=1-99", "bytes 1-99/100", objLength - 1, false},
			{"bytes=50-99", "bytes 50-99/100", 50, false},
			{"bytes=50-", "bytes 50-99/100", 50, false},
			{"bytes=0-", "bytes 0-99/100", objLength, false},
			{"bytes=99-99", "bytes 99-99/100", 1, false},

			// Ranges expected to produce RequestedRangeNotSatisfiable
			{"bytes=-0", "", 0, true},
			{"bytes=100-100", "", 0, true},
			{"bytes=100-110", "", 0, true},
		} {
			if err := testRange(el.objRange, el.contentRange, el.contentLength, el.expectedErr); err != nil {
				return err
			}
		}
		return nil
	})
}

func HeadObject_zero_len_with_range(s *S3Conf) error {
	testName := "HeadObject_zero_len_with_range"
	return headObject_zero_len_with_range_helper(testName, "my-obj", s)
}

func HeadObject_dir_with_range(s *S3Conf) error {
	testName := "HeadObject_dir_with_range"
	return headObject_zero_len_with_range_helper(testName, "my-dir/", s)
}

func HeadObject_conditional_reads(s *S3Conf) error {
	testName := "HeadObject_conditional_reads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		obj, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		}, s3client)
		if err != nil {
			return err
		}

		errMod := getPtr("NotModified")
		errCond := getPtr("PreconditionFailed")

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
			err               *string
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
			_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				IfMatch:           test.ifmatch,
				IfNoneMatch:       test.ifnonematch,
				IfModifiedSince:   test.ifmodifiedsince,
				IfUnmodifiedSince: test.ifunmodifiedsince,
			})
			cancel()
			if test.err == nil && err != nil {
				return fmt.Errorf("test case %d failed: expected no error, but got %v", i, err)
			}
			if test.err != nil {
				if err := checkSdkApiErr(err, *test.err); err != nil {
					return fmt.Errorf("test case %d failed: %w", i, err)
				}
			}
		}

		return nil
	})
}

func HeadObject_success(s *S3Conf) error {
	testName := "HeadObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "my-obj", int64(1234567)
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}
		ctype, cDisp, cEnc, cLang := defaultContentType, "cont-desp", "json", "eng"
		cacheControl, expires := "cache-ctrl", time.Now().Add(time.Hour*2)

		_, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &obj,
			Metadata:           meta,
			ContentType:        &ctype,
			ContentDisposition: &cDisp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			CacheControl:       &cacheControl,
			Expires:            &expires,
			Tagging:            getPtr("key=value"),
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}
		contentLength := int64(0)
		if out.ContentLength != nil {
			contentLength = *out.ContentLength
		}
		if contentLength != dataLen {
			return fmt.Errorf("expected data length %v, instead got %v",
				dataLen, contentLength)
		}
		if getString(out.ContentType) != defaultContentType {
			return fmt.Errorf("expected Content-Type %v, instead got %v",
				defaultContentType, getString(out.ContentType))
		}
		if getString(out.ContentDisposition) != cDisp {
			return fmt.Errorf("expected Content-Disposition %v, instead got %v",
				cDisp, getString(out.ContentDisposition))
		}
		if getString(out.ContentEncoding) != cEnc {
			return fmt.Errorf("expected Content-Encoding %v, instead got %v",
				cEnc, getString(out.ContentEncoding))
		}
		if getString(out.ContentLanguage) != cLang {
			return fmt.Errorf("expected Content-Language %v, instead got %v",
				cLang, getString(out.ContentLanguage))
		}
		if getString(out.ExpiresString) != expires.UTC().Format(timefmt) {
			return fmt.Errorf("expected Expiress %v, instead got %v",
				expires.UTC().Format(timefmt), getString(out.ExpiresString))
		}
		if getString(out.CacheControl) != cacheControl {
			return fmt.Errorf("expected Cache-Control %v, instead got %v",
				cacheControl, getString(out.CacheControl))
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}
		tagCount := int32(0)
		if out.TagCount != nil {
			tagCount = *out.TagCount
		}

		if tagCount != 1 {
			return fmt.Errorf("expected the tagcount to be 1, instead got %v", tagCount)
		}

		return nil
	})
}

func HeadObject_overrides_success(s *S3Conf) error {
	testName := "HeadObject_overrides_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objKey := "test-object"
		exp := time.Now()

		_, err := s3client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &objKey,
		})
		if err != nil {
			return fmt.Errorf("failed to put object: %v", err)
		}

		for _, test := range []PublicBucketTestCase{
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:               &bucket,
						Key:                  &objKey,
						ResponseCacheControl: getPtr("max-age=90"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:                     &bucket,
						Key:                        &objKey,
						ResponseContentDisposition: getPtr("inline"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentEncoding: getPtr("txt"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentLanguage: getPtr("en"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:              &bucket,
						Key:                 &objKey,
						ResponseContentType: getPtr("application/json"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:          &bucket,
						Key:             &objKey,
						ResponseExpires: &exp,
					})
					return err
				},
				ExpectedErr: nil,
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func HeadObject_overrides_presign_success(s *S3Conf) error {
	testName := "HeadObject_overrides_presign_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objKey := "test-object"

		_, err := s3client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &objKey,
		})
		if err != nil {
			return fmt.Errorf("failed to put object: %v", err)
		}

		testCases := []struct {
			name           string
			queryParam     string
			expectedHeader string
			expectedValue  string
		}{
			{
				name:           "response-cache-control",
				queryParam:     "response-cache-control=no-cache",
				expectedHeader: "Cache-Control",
				expectedValue:  "no-cache",
			},
			{
				name:           "response-content-disposition",
				queryParam:     "response-content-disposition=attachment%3B%20filename%3D%22test.txt%22",
				expectedHeader: "Content-Disposition",
				expectedValue:  "attachment; filename=\"test.txt\"",
			},
			{
				name:           "response-content-encoding",
				queryParam:     "response-content-encoding=txt",
				expectedHeader: "Content-Encoding",
				expectedValue:  "txt",
			},
			{
				name:           "response-content-language",
				queryParam:     "response-content-language=en-US",
				expectedHeader: "Content-Language",
				expectedValue:  "en-US",
			},
			{
				name:           "response-content-type",
				queryParam:     "response-content-type=text%2Fplain",
				expectedHeader: "Content-Type",
				expectedValue:  "text/plain",
			},
			{
				name:           "response-expires",
				queryParam:     "response-expires=Thu%2C%2001%20Dec%202024%2016%3A00%3A00%20GMT",
				expectedHeader: "Expires",
				expectedValue:  "Thu, 01 Dec 2024 16:00:00 GMT",
			},
		}

		for _, tc := range testCases {
			req, err := createSignedReq(
				http.MethodHead,
				s.endpoint,
				fmt.Sprintf("%s/%s?%s", bucket, objKey, tc.queryParam),
				s.awsID,
				s.awsSecret,
				"s3",
				s.awsRegion,
				nil,
				time.Now(),
				nil,
			)
			if err != nil {
				return fmt.Errorf("failed to create signed request for %s: %v", tc.name, err)
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("failed to execute request for %s: %v", tc.name, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("expected status 200 for %s, got %d", tc.name, resp.StatusCode)
			}

			actualValue := resp.Header.Get(tc.expectedHeader)
			if actualValue != tc.expectedValue {
				return fmt.Errorf("expected %s header to be %q for %s, got %q",
					tc.expectedHeader, tc.expectedValue, tc.name, actualValue)
			}
		}

		// Test multiple override parameters together
		multiParam := "response-cache-control=max-age%3D3600&response-content-type=application%2Fjson&response-content-disposition=inline"
		req, err := createSignedReq(
			http.MethodHead,
			s.endpoint,
			fmt.Sprintf("%s/%s?%s", bucket, objKey, multiParam),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			nil,
			time.Now(),
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to create signed request for multiple overrides: %v", err)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute request for multiple overrides: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status 200 for multiple overrides, got %d", resp.StatusCode)
		}

		expectedHeaders := map[string]string{
			"Cache-Control":       "max-age=3600",
			"Content-Type":        "application/json",
			"Content-Disposition": "inline",
		}

		for headerName, expectedValue := range expectedHeaders {
			actualValue := resp.Header.Get(headerName)
			if actualValue != expectedValue {
				return fmt.Errorf("expected %s header to be %q for multiple overrides, got %q",
					headerName, expectedValue, actualValue)
			}
		}

		return nil
	})
}

func HeadObject_range_and_part_number(s *S3Conf) error {
	testName := "HeadObject_range_and_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		pn := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			Range:      getPtr("bytes=0-9"),
			PartNumber: &pn,
		})
		cancel()
		return checkSdkApiErr(err, "BadRequest")
	})
}

func HeadObject_mp_part_number_exceeds_parts_count(s *S3Conf) error {
	testName := "HeadObject_mp_part_number_exceeds_parts_count"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		const partCount = int64(5)
		parts, _, err := uploadParts(s3client, partCount*5*1024*1024, partCount, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := make([]types.CompletedPart, len(parts))
		for i, p := range parts {
			compParts[i] = types.CompletedPart{
				ETag:       p.ETag,
				PartNumber: p.PartNumber,
			}
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
		if err != nil {
			return err
		}

		// partNumber exceeds the number of parts in the completed upload
		pn := int32(partCount + 1)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			PartNumber: &pn,
		})
		cancel()
		return checkSdkApiErr(err, "RequestedRangeNotSatisfiable")
	})
}

func HeadObject_mp_part_number_success(s *S3Conf) error {
	testName := "HeadObject_mp_part_number_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		const partCount = int64(3)
		const partSize = int64(5 * 1024 * 1024)
		const totalSize = partCount * partSize

		parts, _, err := uploadParts(s3client, totalSize, partCount, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := make([]types.CompletedPart, len(parts))
		for i, p := range parts {
			compParts[i] = types.CompletedPart{
				ETag:       p.ETag,
				PartNumber: p.PartNumber,
			}
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
		if err != nil {
			return err
		}

		for i := range partCount {
			pn := int32(i + 1)
			startByte := i * partSize
			endByte := startByte + partSize - 1
			expectedContentRange := fmt.Sprintf("bytes %d-%d/%d", startByte, endByte, totalSize)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:     &bucket,
				Key:        &obj,
				PartNumber: &pn,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("part %d: %w", pn, err)
			}

			if res.PartsCount == nil {
				return fmt.Errorf("part %d: expected non-nil x-amz-mp-parts-count", pn)
			}
			if *res.PartsCount != int32(partCount) {
				return fmt.Errorf("part %d: expected PartsCount %d, got %d", pn, partCount, *res.PartsCount)
			}
			if getString(res.ContentRange) != expectedContentRange {
				return fmt.Errorf("part %d: expected Content-Range %q, got %q", pn, expectedContentRange, getString(res.ContentRange))
			}
			if res.ContentLength == nil || *res.ContentLength != partSize {
				return fmt.Errorf("part %d: expected Content-Length %d, got %v", pn, partSize, res.ContentLength)
			}
			if getString(res.AcceptRanges) != "bytes" {
				return fmt.Errorf("part %d: expected Accept-Ranges 'bytes', got %q", pn, getString(res.AcceptRanges))
			}
		}

		return nil
	})
}

func HeadObject_non_mp_part_number_1_success(s *S3Conf) error {
	testName := "HeadObject_non_mp_part_number_1_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "put-object-part1"
		const objSize = int64(1234)

		_, err := putObjectWithData(objSize, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		pn := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			PartNumber: &pn,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ContentLength == nil || *res.ContentLength != objSize {
			return fmt.Errorf("expected ContentLength %d, got %v", objSize, res.ContentLength)
		}
		if getString(res.ContentRange) != "" {
			return fmt.Errorf("expected empty Content-Range for non-multipart object, got %q", getString(res.ContentRange))
		}
		if res.PartsCount != nil {
			return fmt.Errorf("expected nil PartsCount for non-multipart object, got %d", *res.PartsCount)
		}
		if getString(res.AcceptRanges) != "bytes" {
			return fmt.Errorf("expected Accept-Ranges 'bytes', got %q", getString(res.AcceptRanges))
		}

		return nil
	})
}

func HeadObject_overrides_fail_public(s *S3Conf) error {
	testName := "HeadObject_overrides_fail_public"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		err := grantPublicBucketPolicy(rootClient, bucket, policyTypeObject)
		if err != nil {
			return err
		}

		objKey := "test-object"
		exp := time.Now()

		_, err = rootClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &objKey,
		})
		if err != nil {
			return fmt.Errorf("failed to put object: %v", err)
		}

		for _, test := range []PublicBucketTestCase{
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:               &bucket,
						Key:                  &objKey,
						ResponseCacheControl: getPtr("max-age=90"),
					})
					return err
				},
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:                     &bucket,
						Key:                        &objKey,
						ResponseContentDisposition: getPtr("inline"),
					})
					return err
				},
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentEncoding: getPtr("txt"),
					})
					return err
				},
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentLanguage: getPtr("en"),
					})
					return err
				},
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:              &bucket,
						Key:                 &objKey,
						ResponseContentType: getPtr("application/json"),
					})
					return err
				},
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket:          &bucket,
						Key:             &objKey,
						ResponseExpires: &exp,
					})
					return err
				},
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil {
				return fmt.Errorf("%v: expected a BadRequest error, instead got successful response", test.Action)
			}

			if err := checkSdkApiErr(err, "BadRequest"); err != nil {
				return err
			}
		}

		return nil
	}, withAnonymousClient())
}
