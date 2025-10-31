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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func UploadPartCopy_non_existing_bucket(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucketName,
			CopySource: getPtr("Copy-Source"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("my-obj"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPartCopy_incorrect_uploadId(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		_, err = createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   getPtr("incorrect-upload-id"),
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_incorrect_object_key(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        getPtr("non-existing-object-key"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_part_number(s *S3Conf) error {
	testName := "UploadPartCopy_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(-10)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("bucket/key"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("non-existing-object-key"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartNumber)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_copy_source(s *S3Conf) error {
	testName := "UploadPartCopy_invalid_copy_source"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(1)
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
			_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        getPtr("obj"),
				UploadId:   getPtr("mock-upload-id"),
				CopySource: &test.copySource,
				PartNumber: &partNumber,
			})
			cancel()
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return err
			}
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_bucket(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_source_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("src/bucket/src/obj"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_object_key(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_source_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket := "my-obj", getBucketName()

		err := setup(s, srcBucket)
		if err != nil {
			return nil
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/non/existing/obj/key"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_success(s *S3Conf) error {
	testName := "UploadPartCopy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v",
				len(res.Parts))
		}
		if res.Parts[0].PartNumber == nil || *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v",
				res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil || *res.Parts[0].Size != int64(objSize) {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				objSize, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_invalid_ranges(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_invalid_ranges"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := int64(5 * 1024 * 1024)
		_, err = putObjectWithData(objSize, &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		uploadPartCopy := func(csRange string, ptNumber int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				CopySource:      getPtr(srcBucket + "/" + srcObj),
				UploadId:        out.UploadId,
				Key:             &obj,
				PartNumber:      &ptNumber,
				CopySourceRange: &csRange,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopySourceRange)); err != nil {
				return err
			}

			return nil
		}

		for i, rg := range []string{
			"byte=100-200",
			"bytes=invalid-range",
			"bytes=200-100",
			"bytes=-2-300",
			"bytes=aa-12",
			"bytes=12-aa",
			"bytes=bb-",
		} {
			err := uploadPartCopy(rg, int32(i+1))
			if err != nil {
				return err
			}
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_exceeding_copy_source_range(s *S3Conf) error {
	testName := "UploadPartCopy_exceeding_copy_source_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := int64(1000)
		_, err = putObjectWithData(objSize, &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		uploadPartCopy := func(csRange string, ptNumber int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				CopySource:      getPtr(srcBucket + "/" + srcObj),
				UploadId:        out.UploadId,
				Key:             &obj,
				PartNumber:      &ptNumber,
				CopySourceRange: &csRange,
			})
			cancel()
			return checkApiErr(err, s3err.CreateExceedingRangeErr(objSize))
		}

		for i, rg := range []string{
			"bytes=100-1005",
			"bytes=1250-3000",
			"bytes=100-1000",
		} {
			err := uploadPartCopy(rg, int32(i+1))
			if err != nil {
				return err
			}
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_greater_range_than_obj_size(s *S3Conf) error {
	testName := "UploadPartCopy_greater_range_than_obj_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		srcObjSize := 5 * 1024 * 1024
		_, err = putObjectWithData(int64(srcObjSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			UploadId:        out.UploadId,
			Key:             &obj,
			CopySourceRange: getPtr(fmt.Sprintf("bytes=0-%v", srcObjSize+50)), // The specified range is greater than the actual object size
			PartNumber:      &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.CreateExceedingRangeErr(int64(srcObjSize))); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_success(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			CopySourceRange: getPtr("bytes=100-200"),
			UploadId:        out.UploadId,
			Key:             &obj,
			PartNumber:      &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v",
				len(res.Parts))
		}
		if res.Parts[0].PartNumber == nil {
			return fmt.Errorf("expected part-number to be 1, instead got nil")
		}
		if *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v",
				res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil {
			return fmt.Errorf("expected part size to be non nil, instead got nil")
		}
		if *res.Parts[0].Size != 101 {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				101, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_conditional_reads(s *S3Conf) error {
	testName := "UploadPartCopy_conditional_reads"
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
		} {
			mpKey := "mp-key"
			mp, err := createMp(s3client, bucket, mpKey)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:                      &bucket,
				Key:                         &mpKey,
				UploadId:                    mp.UploadId,
				PartNumber:                  getPtr(int32(1)),
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

func UploadPartCopy_should_copy_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_copy_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		out, err := putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.CopyPartResult.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
			return fmt.Errorf("expected crc32 checksum to be %v, instead got %v",
				getString(out.res.ChecksumCRC32), getString(res.CopyPartResult.ChecksumCRC32))
		}
		if res.CopyPartResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32C)
		}
		if res.CopyPartResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA1)
		}
		if res.CopyPartResult.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA256)
		}
		if res.CopyPartResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC64NVME)
		}

		return nil
	})
}

func UploadPartCopy_should_not_copy_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_not_copy_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, err = putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyPartResult.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32)
		}
		if res.CopyPartResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32C)
		}
		if res.CopyPartResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA1)
		}
		if res.CopyPartResult.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA256)
		}
		if res.CopyPartResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC64NVME)
		}

		return nil
	})
}

func UploadPartCopy_should_calculate_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_calculate_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmSha256))
		if err != nil {
			return err
		}

		_, err = putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1, // different from the mp checksum (sha256)
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyPartResult.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32)
		}
		if res.CopyPartResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32C)
		}
		if res.CopyPartResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC64NVME)
		}
		if res.CopyPartResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA1)
		}
		if getString(res.CopyPartResult.ChecksumSHA256) == "" {
			return fmt.Errorf("expected non empty sha256 checksum")
		}

		return nil
	})
}
