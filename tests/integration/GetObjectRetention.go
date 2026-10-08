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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func GetObjectRetention_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectRetention_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: getPtr(getBucketName()),
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_non_existing_object(s *S3Conf) error {
	testName := "GetObjectRetention_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_disabled_lock(s *S3Conf) error {
	testName := "GetObjectRetention_disabled_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_unset_config(s *S3Conf) error {
	testName := "GetObjectRetention_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)); err != nil {
			return err
		}

		var respErr *awshttp.ResponseError
		if !errors.As(err, &respErr) || respErr.HTTPStatusCode() != http.StatusNotFound {
			return fmt.Errorf("expected status %d, instead got %w", http.StatusNotFound, err)
		}

		return nil
	}, withLock())
}

func GetObjectRetention_success(s *S3Conf) error {
	testName := "GetObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(complianceTestRetention)
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionModeCompliance,
			RetainUntilDate: &date,
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &key,
			Retention: &retention,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.Retention == nil {
			return fmt.Errorf("got nil object lock retention")
		}

		ret := resp.Retention

		if ret.Mode != retention.Mode {
			return fmt.Errorf("expected retention mode to be %v, instead got %v", retention.Mode, ret.Mode)
		}
		// FIXME: There's a problem with storing retainUnitDate, most probably SDK changes the date before sending
		// if ret.RetainUntilDate.Format(iso8601Format)[:8] != retention.RetainUntilDate.Format(iso8601Format)[:8] {
		// 	return fmt.Errorf("expected retain until date to be %v, instead got %v", retention.RetainUntilDate.Format(iso8601Format), ret.RetainUntilDate.Format(iso8601Format))
		// }

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: key, isCompliance: true}})
	}, withLock())
}

func GetObjectRetention_empty_version_id(s *S3Conf) error {
	return testEmptyVersionId(s, "GetObjectRetention_empty_version_id", http.MethodGet, "retention", nil)
}

// GetObjectRetention_retain_until_date_format covers the retain until date
// on the wire. It is kept to the millisecond, in UTC. GetObjectRetention
// gives it with three fraction digits, and the HeadObject and GetObject
// headers with them left out when they are zero.
func GetObjectRetention_retain_until_date_format(s *S3Conf) error {
	testName := "GetObjectRetention_retain_until_date_format"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		base := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		whole := base.Format("2006-01-02T15:04:05")

		send := func(method, path string, headers map[string]string, body []byte) (*http.Response, error) {
			req, err := createSignedReq(method, s.endpoint, path, s.awsID, s.awsSecret, "s3",
				s.awsRegion, "", body, time.Now(), headers)
			if err != nil {
				return nil, err
			}
			return s.httpClient.Do(req)
		}
		checkFormats := func(key, header, xmlDate string) error {
			for _, method := range []string{http.MethodHead, http.MethodGet} {
				resp, err := send(method, bucket+"/"+key, nil, nil)
				if err != nil {
					return err
				}
				resp.Body.Close()
				if got := resp.Header.Get("x-amz-object-lock-retain-until-date"); got != header {
					return fmt.Errorf("%s: expected the retain until date header %q, instead got %q", method, header, got)
				}
			}

			resp, err := send(http.MethodGet, bucket+"/"+key+"?retention", nil, nil)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			want := "<RetainUntilDate>" + xmlDate + "</RetainUntilDate>"
			if !strings.Contains(string(body), want) {
				return fmt.Errorf("expected the retention to contain %s, instead got %s", want, body)
			}
			return nil
		}

		for i, test := range []struct {
			date   string
			header string
			xml    string
		}{
			{date: whole + "Z", header: whole + "Z", xml: whole + ".000Z"},
			{date: whole + ".5Z", header: whole + ".500Z", xml: whole + ".500Z"},
			{date: whole + ".123999Z", header: whole + ".123Z", xml: whole + ".123Z"},
			{date: base.In(time.FixedZone("", 2*60*60)).Format(time.RFC3339), header: whole + "Z", xml: whole + ".000Z"},
			{date: strings.Replace(whole, "T", "t", 1) + "z", header: whole + "Z", xml: whole + ".000Z"},
		} {
			key := fmt.Sprintf("my-obj-%d", i)
			body := []byte("data")
			sum := md5.Sum(body)
			resp, err := send(http.MethodPut, bucket+"/"+key, map[string]string{
				"x-amz-object-lock-mode":              "GOVERNANCE",
				"x-amz-object-lock-retain-until-date": test.date,
				"Content-Md5":                         base64.StdEncoding.EncodeToString(sum[:]),
			}, body)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("PutObject with retain until date %s: expected status 200, instead got %d", test.date, resp.StatusCode)
			}

			if err := checkFormats(key, test.header, test.xml); err != nil {
				return fmt.Errorf("retain until date %s: %w", test.date, err)
			}
		}

		key := "my-obj-retention"
		if _, err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}
		retention := []byte(`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>GOVERNANCE</Mode><RetainUntilDate>` +
			whole + `.123456789Z</RetainUntilDate></Retention>`)
		sum := md5.Sum(retention)
		resp, err := send(http.MethodPut, bucket+"/"+key+"?retention", map[string]string{
			"Content-Md5": base64.StdEncoding.EncodeToString(sum[:]),
		}, retention)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("PutObjectRetention: expected status 200, instead got %d", resp.StatusCode)
		}

		if err := checkFormats(key, whole+".123Z", whole+".123Z"); err != nil {
			return fmt.Errorf("PutObjectRetention: %w", err)
		}

		return nil
	}, withLock())
}
