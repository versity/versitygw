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
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func AbortMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "AbortMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("incorrect-bucket"),
			Key:      getPtr("my-obj"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_incorrect_uploadId(s *S3Conf) error {
	testName := "AbortMultipartUpload_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("invalid uploadId"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchUpload"); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_incorrect_object_key(s *S3Conf) error {
	testName := "AbortMultipartUpload_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("incorrect-object-key"),
			UploadId: out.UploadId,
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchUpload"); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_success(s *S3Conf) error {
	testName := "AbortMultipartUpload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Uploads) != 0 {
			return fmt.Errorf("expected 0 upload, instead got %v", len(res.Uploads))
		}

		return nil
	})
}

func AbortMultipartUpload_success_status_code(s *S3Conf) error {
	testName := "AbortMultipartUpload_success_status_code"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint,
			fmt.Sprintf("%v/%v?uploadId=%v", bucket, obj, *out.UploadId),
			s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func AbortMultipartUpload_if_match_initiated_time(s *S3Conf) error {
	testName := "AbortMultipartUpload_if_match_initiated_time"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var initiated *time.Time = getPtr(time.Now())

		// createMpUpload creates a multipart uplod
		// and retruns the uploadId and creation date
		abortMp := func(date *time.Time) error {
			mpObj := "my-obj"
			mp, err := createMp(s3client, bucket, mpObj)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket: &bucket,
			})
			cancel()
			if err != nil {
				return err
			}

			var initiatedTime *time.Time

			for _, up := range res.Uploads {
				if getString(up.UploadId) == getString(mp.UploadId) {
					initiatedTime = up.Initiated
					break
				}
			}

			if initiatedTime == nil {
				return fmt.Errorf("unexpected err: the multipart upload is not found")
			}

			*initiated = *initiatedTime

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:               &bucket,
				Key:                  &mpObj,
				UploadId:             mp.UploadId,
				IfMatchInitiatedTime: date,
			})
			cancel()

			return err
		}

		for i, test := range []struct {
			date *time.Time
			err  error
		}{
			{nil, nil},
			// match: success case
			{initiated, nil},
			// should ignore future dates
			{getPtr(initiated.AddDate(1, 0, 0)), nil},
			// should fail if the initation date doesn't match
			{getPtr(initiated.AddDate(-1, 0, 1)), s3err.GetAPIError(s3err.ErrPreconditionFailed)},
		} {
			err := abortMp(test.date)
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
