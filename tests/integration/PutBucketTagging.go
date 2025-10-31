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
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutBucketTagging_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketTagging_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  getPtr(getBucketName()),
			Tagging: &types.Tagging{TagSet: []types.Tag{}},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_long_tags(s *S3Conf) error {
	testName := "PutBucketTagging_long_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr(genRandString(200)), Value: getPtr("val")}}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagKey)); err != nil {
			return err
		}

		tagging = types.Tagging{TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr(genRandString(300))}}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagValue)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_invalid_tags(s *S3Conf) error {
	testName := "PutBucketTagging_invalid_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, test := range []struct {
			tags []types.Tag
			err  s3err.APIError
		}{
			// invalid tag key tests
			{[]types.Tag{{Key: getPtr("user!name"), Value: getPtr("value")}}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{[]types.Tag{{Key: getPtr("foo#bar"), Value: getPtr("value")}}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{[]types.Tag{
				{Key: getPtr("validkey"), Value: getPtr("validvalue")},
				{Key: getPtr("data%20"), Value: getPtr("value")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{[]types.Tag{
				{Key: getPtr("abcd"), Value: getPtr("xyz123")},
				{Key: getPtr("a*b"), Value: getPtr("value")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			// invalid tag value tests
			{[]types.Tag{
				{Key: getPtr("hello"), Value: getPtr("world")},
				{Key: getPtr("key"), Value: getPtr("name?test")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{
				{Key: getPtr("foo"), Value: getPtr("bar")},
				{Key: getPtr("key"), Value: getPtr("`path")},
			}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{{Key: getPtr("valid"), Value: getPtr("comma,separated")}}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{{Key: getPtr("valid"), Value: getPtr("semicolon;test")}}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{[]types.Tag{{Key: getPtr("valid"), Value: getPtr("(parentheses)")}}, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
				Bucket: &bucket,
				Tagging: &types.Tagging{
					TagSet: test.tags,
				},
			})
			cancel()
			if err == nil {
				return fmt.Errorf("test %v failed: expected err %w, instead got nil", i+1, test.err)
			}

			if err := checkApiErr(err, test.err); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func PutBucketTagging_duplicate_keys(s *S3Conf) error {
	testName := "PutBucketTagging_duplicate_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{
			TagSet: []types.Tag{
				{Key: getPtr("key"), Value: getPtr("value")},
				{Key: getPtr("key"), Value: getPtr("value-1")},
				{Key: getPtr("key-1"), Value: getPtr("value-2")},
				{Key: getPtr("key-2"), Value: getPtr("value-3")},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDuplicateTagKey)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_tag_count_limit(s *S3Conf) error {
	testName := "PutBucketTagging_tag_count_limit"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagSet := []types.Tag{}

		for i := range 51 {
			tagSet = append(tagSet, types.Tag{
				Key:   getPtr(fmt.Sprintf("key-%v", i)),
				Value: getPtr(genRandString(10)),
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket: &bucket,
			Tagging: &types.Tagging{
				TagSet: tagSet,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketTaggingLimited))
	})
}

func PutBucketTagging_success(s *S3Conf) error {
	testName := "PutBucketTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_success_status(s *S3Conf) error {
	testName := "PutBucketTagging_success_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{
			TagSet: []types.Tag{
				{
					Key:   getPtr("key"),
					Value: getPtr("val"),
				},
			},
		}

		taggingParsed, err := xml.Marshal(tagging)
		if err != nil {
			return fmt.Errorf("err parsing tagging: %w", err)
		}

		hasher := md5.New()
		_, err = hasher.Write(taggingParsed)
		if err != nil {
			return err
		}

		sum := hasher.Sum(nil)
		md5Sum := base64.StdEncoding.EncodeToString(sum)

		req, err := createSignedReq(http.MethodPut, s.endpoint, fmt.Sprintf("%v?tagging=", bucket), s.awsID, s.awsSecret, "s3", s.awsRegion, taggingParsed, time.Now(), map[string]string{
			"Content-Md5": md5Sum,
		})
		if err != nil {
			return fmt.Errorf("err signing the request: %w", err)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("err sending request: %w", err)
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected the response status code to be %v, instad got %v", http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}
