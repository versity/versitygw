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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func GetObject_non_existing_key(s *S3Conf) error {
	testName := "GetObject_non_existing_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("non-existing-key"),
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_directory_object_noslash(s *S3Conf) error {
	testName := "GetObject_directory_object_noslash"
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
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_with_range(s *S3Conf) error {
	testName := "GetObject_with_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Match HeadObject_with_range: 100-byte object
		obj, objLength := "my-obj", int64(100)
		res, err := putObjectWithData(objLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testGetObjectRange := func(rng, contentRange string, cLength int64, expData []byte, expErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			defer cancel()
			out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Range:  &rng,
			})
			if err == nil && expErr != nil {
				return fmt.Errorf("expected err %v, instead got nil", expErr)
			}
			if err != nil {
				if expErr == nil {
					return err
				}
				parsedErr, ok := expErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided, expected s3err.APIError")
				}
				return checkApiErr(err, parsedErr)
			}

			if out.ContentLength == nil {
				return fmt.Errorf("expected non nil content-length")
			}
			if *out.ContentLength != cLength {
				return fmt.Errorf("expected content-length to be %v, instead got %v", cLength, *out.ContentLength)
			}
			if getString(out.AcceptRanges) != "bytes" {
				return fmt.Errorf("expected accept-ranges to be 'bytes', instead got %v", getString(out.AcceptRanges))
			}
			if getString(out.ContentRange) != contentRange {
				return fmt.Errorf("expected content-range to be %v, instead got %v", contentRange, getString(out.ContentRange))
			}

			outData, err := io.ReadAll(out.Body)
			if err != nil {
				return fmt.Errorf("read object data: %w", err)
			}
			out.Body.Close()

			if !isSameData(outData, expData) {
				return fmt.Errorf("incorrect data retrieved")
			}
			return nil
		}

		for _, el := range []struct {
			rng          string
			contentRange string
			cLength      int64
			expData      []byte
			expErr       error
		}{
			// Invalid / ignored ranges (return full object, empty Content-Range)
			{"bytes=,", "", objLength, res.data, nil},
			{"bytes= -1", "", objLength, res.data, nil},
			{"bytes=--1", "", objLength, res.data, nil},
			{"bytes=0 -1", "", objLength, res.data, nil},
			{"bytes=0--1", "", objLength, res.data, nil},
			{"bytes=10-5", "", objLength, res.data, nil},
			{"bytes=abc", "", objLength, res.data, nil},
			{"bytes=a-z", "", objLength, res.data, nil},
			{"foo=0-1", "", objLength, res.data, nil},
			{"bytes=abc-xyz", "", objLength, res.data, nil},
			{"bytes=100-x", "", objLength, res.data, nil},
			{"bytes=0-0,1-2", "", objLength, res.data, nil},
			{fmt.Sprintf("bytes=%v-%v", objLength+2, objLength-100), "", objLength, res.data, nil},

			// Valid numeric with leading zeros
			{"bytes=00-01", "bytes 0-1/100", 2, res.data[0:2], nil},

			// Suffix ranges
			{"bytes=-1", "bytes 99-99/100", 1, res.data[99:], nil},
			{"bytes=-2", "bytes 98-99/100", 2, res.data[98:], nil},
			{"bytes=-10", "bytes 90-99/100", 10, res.data[90:], nil},
			{"bytes=-100", "bytes 0-99/100", objLength, res.data, nil},
			{"bytes=-101", "bytes 0-99/100", objLength, res.data, nil},

			// Standard byte ranges
			{"bytes=0-0", "bytes 0-0/100", 1, res.data[0:1], nil},
			{"bytes=0-99", "bytes 0-99/100", objLength, res.data, nil},
			{"bytes=0-100", "bytes 0-99/100", objLength, res.data, nil},
			{"bytes=0-999999", "bytes 0-99/100", objLength, res.data, nil},
			{"bytes=1-99", "bytes 1-99/100", 99, res.data[1:], nil},
			{"bytes=50-99", "bytes 50-99/100", 50, res.data[50:], nil},
			{"bytes=50-", "bytes 50-99/100", 50, res.data[50:], nil},
			{"bytes=0-", "bytes 0-99/100", objLength, res.data, nil},
			{"bytes=99-99", "bytes 99-99/100", 1, res.data[99:], nil},

			// Unsatisfiable -> error
			{"bytes=-0", "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{"bytes=100-100", "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{"bytes=100-110", "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
		} {
			if err := testGetObjectRange(el.rng, el.contentRange, el.cLength, el.expData, el.expErr); err != nil {
				return err
			}
		}
		return nil
	})
}

func GetObject_zero_len_with_range(s *S3Conf) error {
	testName := "GetObject_zero_len_with_range"
	return getObject_zero_len_with_range_helper(testName, "my-obj", s)
}

func GetObject_dir_with_range(s *S3Conf) error {
	testName := "GetObject_dir_with_range"
	return getObject_zero_len_with_range_helper(testName, "my-dir/", s)
}

func GetObject_invalid_parent(s *S3Conf) error {
	testName := "GetObject_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "not-a-dir"

		_, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("not-a-dir/bad-obj"),
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_checksums(s *S3Conf) error {
	testName := "GetObject_checksums"
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
			out, err := putObjectWithData(int64(i*120), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &el.key,
				ChecksumAlgorithm: el.checksumAlgo,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:       &bucket,
				Key:          &el.key,
				ChecksumMode: types.ChecksumModeEnabled,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the %v object checksum type to be %v, instaed got %v",
					el.key, types.ChecksumTypeFullObject, res.ChecksumType)
			}
			if getString(res.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
				return fmt.Errorf("expected crc32 checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC32), getString(res.ChecksumCRC32))
			}
			if getString(res.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
				return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC32C), getString(res.ChecksumCRC32C))
			}
			if getString(res.ChecksumSHA1) != getString(out.res.ChecksumSHA1) {
				return fmt.Errorf("expected sha1 checksum to be %v, instead got %v",
					getString(out.res.ChecksumSHA1), getString(res.ChecksumSHA1))
			}
			if getString(res.ChecksumSHA256) != getString(out.res.ChecksumSHA256) {
				return fmt.Errorf("expected sha256 checksum to be %v, instead got %v",
					getString(out.res.ChecksumSHA256), getString(res.ChecksumSHA256))
			}
			if getString(res.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
				return fmt.Errorf("expected crc64nvme checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC64NVME), getString(res.ChecksumCRC64NVME))
			}
		}

		return nil
	})
}

func GetObject_dir_object_checksum(s *S3Conf) error {
	testName := "GetObject_dir_object_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, obj := range []struct {
			key          string
			expectedSum  string
			checksumAlgo types.ChecksumAlgorithm
		}{
			{
				key:          "obj-1/",
				expectedSum:  "AAAAAA==",
				checksumAlgo: types.ChecksumAlgorithmCrc32,
			},
			{
				key:          "obj-2/",
				expectedSum:  "AAAAAA==",
				checksumAlgo: types.ChecksumAlgorithmCrc32c,
			},
			{
				key:          "obj-3/",
				expectedSum:  "AAAAAAAAAAA=",
				checksumAlgo: types.ChecksumAlgorithmCrc64nvme,
			},
			{
				key:          "obj-4/",
				expectedSum:  "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
				checksumAlgo: types.ChecksumAlgorithmSha1,
			},
			{
				key:          "obj-5/",
				expectedSum:  "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				checksumAlgo: types.ChecksumAlgorithmSha256,
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj.key,
				ChecksumAlgorithm: obj.checksumAlgo,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:       &bucket,
				Key:          &obj.key,
				ChecksumMode: types.ChecksumModeEnabled,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("test %v failed: expected the %v object checksum type to be %v, instaed got %v",
					i+1, obj.key, types.ChecksumTypeFullObject, res.ChecksumType)
			}

			var gotSum *string
			switch obj.checksumAlgo {
			case types.ChecksumAlgorithmCrc32:
				gotSum = res.ChecksumCRC32
			case types.ChecksumAlgorithmCrc32c:
				gotSum = res.ChecksumCRC32C
			case types.ChecksumAlgorithmCrc64nvme:
				gotSum = res.ChecksumCRC64NVME
			case types.ChecksumAlgorithmSha1:
				gotSum = res.ChecksumSHA1
			case types.ChecksumAlgorithmSha256:
				gotSum = res.ChecksumSHA256
			}

			if getString(gotSum) != obj.expectedSum {
				return fmt.Errorf("test %v failed: expected the object %s to be %s, instead got %s", i+1, obj.checksumAlgo, obj.expectedSum, getString(gotSum))
			}
		}

		return nil
	})
}

func GetObject_large_object(s *S3Conf) error {
	testName := "GetObject_large_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		//FIXME: make the object size larger after
		// resolving the context deadline exceeding issue
		// in the github actions
		dataLength, obj := int64(100*1024*1024), "my-obj"
		ctype := defaultContentType

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         &obj,
			ContentType: &ctype,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), longTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil content length")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("expected the output data checksum to be %v, instead got %v",
				r.csum, outCsum)
		}
		return nil
	})
}

func GetObject_conditional_reads(s *S3Conf) error {
	testName := "GetObject_conditional_reads"
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
			_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
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

func GetObject_success(s *S3Conf) error {
	testName := "GetObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		ctype, cDisp, cEnc, cLang := defaultContentType, "cont-desp", "json", "eng"
		cacheControl, expires := "cache-ctrl", time.Now().Add(time.Hour*2)
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &obj,
			ContentType:        &ctype,
			ContentDisposition: &cDisp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			Expires:            &expires,
			CacheControl:       &cacheControl,
			Metadata:           meta,
			Tagging:            getPtr("key=value&key1=val1"),
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, out.ContentLength)
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
		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("expected the object metadata to be %v, instead got %v",
				meta, out.Metadata)
		}
		var tagCount int32
		if out.TagCount != nil {
			tagCount = *out.TagCount
		}
		if tagCount != 2 {
			return fmt.Errorf("expected tag count to be 2, instead got %v", tagCount)
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
		return nil
	})
}

const directoryContentType = "application/x-directory"

func GetObject_directory_success(s *S3Conf) error {
	testName := "GetObject_directory_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(0), "my-dir/"

		_, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil content length")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, out.ContentLength)
		}
		if getString(out.ContentType) != directoryContentType {
			return fmt.Errorf("expected content type %v, instead got %v",
				directoryContentType, getString(out.ContentType))
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}

		out.Body.Close()
		return nil
	})
}

func GetObject_by_range_resp_status(s *S3Conf) error {
	testName := "GetObject_by_range_resp_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dLen := "my-obj", int64(4000)
		_, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/%v", bucket, obj),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			nil,
			time.Now(),
			map[string]string{
				"Range": "bytes=100-200",
			},
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusPartialContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusPartialContent, resp.StatusCode)
		}

		return nil
	})
}

func GetObject_non_existing_dir_object(s *S3Conf) error {
	testName := "GetObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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

func GetObject_overrides_success(s *S3Conf) error {
	testName := "GetObject_overrides_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Test data
		objKey := "test-object"
		objContent := "test content for response overrides"
		exp := time.Now()

		// Put an object first
		_, err := s3client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &objKey,
			Body:   strings.NewReader(objContent),
		})
		if err != nil {
			return fmt.Errorf("failed to put object: %v", err)
		}

		for _, test := range []PublicBucketTestCase{
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:               &bucket,
						Key:                  &objKey,
						ResponseCacheControl: getPtr("max-age=90"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:                     &bucket,
						Key:                        &objKey,
						ResponseContentDisposition: getPtr("inline"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentEncoding: getPtr("txt"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentLanguage: getPtr("en"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:              &bucket,
						Key:                 &objKey,
						ResponseContentType: getPtr("application/json"),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
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

func GetObject_overrides_presign_success(s *S3Conf) error {
	testName := "GetObject_overrides_presign_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Test data
		objKey := "test-object"
		objContent := "test content for response overrides"

		// Put an object first
		_, err := s3client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &objKey,
			Body:   strings.NewReader(objContent),
		})
		if err != nil {
			return fmt.Errorf("failed to put object: %v", err)
		}

		// Test cases for each response override parameter
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

		// Test each override parameter individually
		for _, tc := range testCases {
			// Create a signed request with the response override parameter
			req, err := createSignedReq(
				http.MethodGet,
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
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("expected status 200 for %s, got %d", tc.name, resp.StatusCode)
			}

			// Verify the response override header is set correctly
			actualValue := resp.Header.Get(tc.expectedHeader)
			if actualValue != tc.expectedValue {
				return fmt.Errorf("expected %s header to be %q for %s, got %q",
					tc.expectedHeader, tc.expectedValue, tc.name, actualValue)
			}

			// Verify content is still correct
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read response body for %s: %v", tc.name, err)
			}

			if string(body) != objContent {
				return fmt.Errorf("expected content %q for %s, got %q", objContent, tc.name, string(body))
			}
		}

		// Test multiple override parameters together
		multiParam := "response-cache-control=max-age%3D3600&response-content-type=application%2Fjson&response-content-disposition=inline"
		req, err := createSignedReq(
			http.MethodGet,
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
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status 200 for multiple overrides, got %d", resp.StatusCode)
		}

		// Verify all override headers are set correctly
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

func GetObject_overrides_fail_public(s *S3Conf) error {
	testName := "GetObject_overrides_fail_public"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		// Grant public access to the bucket for bucket operations
		err := grantPublicBucketPolicy(rootClient, bucket, policyTypeObject)
		if err != nil {
			return err
		}

		// Test data
		objKey := "test-object"
		objContent := "test content for response overrides"
		exp := time.Now()

		// Put an object first
		_, err = rootClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &objKey,
			Body:   strings.NewReader(objContent),
		})
		if err != nil {
			return fmt.Errorf("failed to put object: %v", err)
		}

		for _, test := range []PublicBucketTestCase{
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:               &bucket,
						Key:                  &objKey,
						ResponseCacheControl: getPtr("max-age=90"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:                     &bucket,
						Key:                        &objKey,
						ResponseContentDisposition: getPtr("inline"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentEncoding: getPtr("txt"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:                  &bucket,
						Key:                     &objKey,
						ResponseContentLanguage: getPtr("en"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:              &bucket,
						Key:                 &objKey,
						ResponseContentType: getPtr("application/json"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
						Bucket:          &bucket,
						Key:             &objKey,
						ResponseExpires: &exp,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders),
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
	}, withAnonymousClient())
}

func GetObject_invalid_part_number(s *S3Conf) error {
	testName := "GetObject_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("obj"),
			PartNumber: getPtr(int32(-3)),
		})

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartNumber))
	})
}

func GetObject_part_number_not_supported(s *S3Conf) error {
	testName := "GetObject_part_number_not_supported"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("obj"),
			PartNumber: getPtr(int32(3)),
		})

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}
