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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutObjectTagging_non_existing_object(s *S3Conf) error {
	testName := "PutObjectTagging_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     getPtr("my-obj"),
			Tagging: &types.Tagging{TagSet: []types.Tag{}}})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectTagging_long_tags(s *S3Conf) error {
	testName := "PutObjectTagging_long_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{
			{Key: getPtr(genRandString(129)), Value: getPtr("val")},
		}}
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagKey)); err != nil {
			return err
		}

		tagging = types.Tagging{TagSet: []types.Tag{
			{Key: getPtr("key"), Value: getPtr(genRandString(257))},
		}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagValue)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectTagging_duplicate_keys(s *S3Conf) error {
	testName := "PutObjectTagging_duplicate_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		tagging := types.Tagging{
			TagSet: []types.Tag{
				{Key: getPtr("key-1"), Value: getPtr("value-1")},
				{Key: getPtr("key-2"), Value: getPtr("value-2")},
				{Key: getPtr("same-key"), Value: getPtr("value-3")},
				{Key: getPtr("same-key"), Value: getPtr("value-4")},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDuplicateTagKey)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectTagging_tag_count_limit(s *S3Conf) error {
	testName := "PutObjectTagging_tag_count_limit"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		tagSet := []types.Tag{}
		for i := range 11 {
			tagSet = append(tagSet, types.Tag{
				Key:   getPtr(fmt.Sprintf("key-%v", i)),
				Value: getPtr(genRandString(15)),
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
			Tagging: &types.Tagging{
				TagSet: tagSet,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectTaggingLimited))
	})
}

func PutObjectTagging_invalid_tags(s *S3Conf) error {
	testName := "PutObjectTagging_invalid_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

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
			_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
				Bucket: &bucket,
				Key:    &obj,
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

func PutObjectTagging_invalid_tag_error_fields(s *S3Conf) error {
	testName := "PutObjectTagging_invalid_tag_error_fields"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		var overLimit strings.Builder
		for i := range 10 {
			fmt.Fprintf(&overLimit, "<Tag><Key>key-%v</Key><Value>value</Value></Tag>", i)
		}
		overLimit.WriteString("<Tag><Key></Key><Value>value</Value></Tag>")

		for i, test := range []struct {
			tagSet string
			err    s3err.S3Error
		}{
			// an empty key is reported in an empty TagKey element
			{"<Tag><Key></Key><Value>value</Value></Tag>", s3err.GetInvalidTagErr(s3err.ErrInvalidTagKey, "", "")},
			{"<Tag><Key>key</Key><Value>a</Value></Tag><Tag><Key>key</Key><Value>b</Value></Tag>", s3err.GetInvalidTagErr(s3err.ErrDuplicateTagKey, "key", "")},
			// the tags are validated before the tag count
			{overLimit.String(), s3err.GetInvalidTagErr(s3err.ErrInvalidTagKey, "", "")},
			// a missing Key or Value element fails ahead of any tag check
			{"<Tag><Value>value</Value></Tag>", s3err.GetAPIError(s3err.ErrMalformedXML)},
			{"<Tag><Key>key</Key></Tag>", s3err.GetAPIError(s3err.ErrMalformedXML)},
		} {
			body := []byte(`<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>` + test.tagSet + `</TagSet></Tagging>`)
			sum := md5.Sum(body)

			req, err := createSignedReq(http.MethodPut, s.endpoint, fmt.Sprintf("%v/%v?tagging=", bucket, obj), s.awsID, s.awsSecret, "s3", s.awsRegion, "", body, time.Now(), map[string]string{
				"Content-Md5": base64.StdEncoding.EncodeToString(sum[:]),
			})
			if err != nil {
				return fmt.Errorf("test %v: err signing the request: %w", i+1, err)
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("test %v: err sending request: %w", i+1, err)
			}

			if err := checkHTTPResponseApiErr(resp, test.err); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func PutObjectTagging_success(s *S3Conf) error {
	testName := "PutObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{
			{Key: getPtr("key1"), Value: getPtr("val2")},
			{Key: getPtr("key2"), Value: getPtr("val2")},
		}}
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func PutObjectTagging_empty_version_id(s *S3Conf) error {
	return testEmptyVersionId(s, "PutObjectTagging_empty_version_id", http.MethodPut, "tagging", []byte("<Tagging><TagSet><Tag><Key>key</Key><Value>val</Value></Tag></TagSet></Tagging>"))
}
