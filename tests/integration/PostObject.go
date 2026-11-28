// Copyright 2026 Versity Software
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
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func PostObject_invalid_content_type(s *S3Conf) error {
	testName := "PostObject_invalid_content_type"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/"+bucket, strings.NewReader("body"))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 4

		resp, err := s.httpClient.Do(req)
		cancel()
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetPreconditionFailedErr(s3err.ConditionPostBucket))
	})
}

func PostObject_missing_boundary(s *S3Conf) error {
	testName := "PostObject_missing_boundary"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		body := []byte("irrelevant body")
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/"+bucket, bytes.NewReader(body))
		if err != nil {
			cancel()
			return err
		}
		// multipart/form-data without boundary parameter
		req.Header.Set("Content-Type", "multipart/form-data")
		req.ContentLength = int64(len(body))

		resp, err := s.httpClient.Do(req)
		cancel()
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest))
	})
}

func PostObject_partial_auth_fields(s *S3Conf) error {
	testName := "PostObject_partial_auth_fields"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, field := range []string{
			"policy", "x-amz-signature",
			"x-amz-credential", "x-amz-date",
			"x-amz-algorithm",
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         "test-object",
				s3Conf:      s,
				fileContent: []byte("data"),
				extraFields: map[string]string{
					field: "",
				},
			})
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := checkHTTPResponseApiErr(resp, s3err.PostAuth.MissingField(field)); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func PostObject_invalid_algorithm(s *S3Conf) error {
	testName := "PostObject_invalid_algorithm"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"x-amz-algorithm": "invalid",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidArgumentErr(s3err.InvalidArgOnlyAws4HmacSha256, "invalid"))
	})
}

func PostObject_invalid_date(s *S3Conf) error {
	testName := "PostObject_invalid_date"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"x-amz-date": "invalid_date",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidArgumentErr(s3err.InvalidArgDateHeader, "invalid_date"))
	})
}

func PostObject_invalid_credential_format(s *S3Conf) error {
	testName := "PostObject_invalid_credential_format"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"x-amz-credential": "malformed-no-slashes",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.PostAuth.MalformedCredential("malformed-no-slashes"))
	})
}

func PostObject_incorrect_region(s *S3Conf) error {
	testName := "PostObject_incorrect_region"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		wrongRegion := "us-west-2"
		if s.awsRegion == wrongRegion {
			wrongRegion = "eu-west-1"
		}

		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			region:      wrongRegion,
			fileContent: []byte("data"),
		})
		if err != nil {
			return err
		}

		expectedCreds := fmt.Sprintf("%s/%s/%s/s3/aws4_request", s.awsID, time.Now().UTC().Format("20060102"), wrongRegion)
		return checkHTTPResponseApiErr(resp, s3err.PostAuth.IncorrectRegion(expectedCreds, s.awsRegion, wrongRegion))
	})
}

func PostObject_non_existing_access_key(s *S3Conf) error {
	testName := "PostObject_non_existing_access_key"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		accessKeyID := "this_access_key_id_can_not_really_exist"
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			access:      accessKeyID,
			secret:      "a_very_secure_secret_access_key",
			fileContent: []byte("data"),
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidAccessKeyIdErr(accessKeyID))
	})
}

func PostObject_signature_mismatch(s *S3Conf) error {
	testName := "PostObject_signature_mismatch"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		const signature = "incorrect_signature"
		req, fields, err := newPostObjectRequest(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"x-amz-signature": signature,
			},
		})
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		var errResp APIErrorResponse
		err = xml.Unmarshal(body, &errResp)
		if err != nil {
			return err
		}

		expected := s3err.GetSignatureDoesNotMatchErr(s.awsID, fields["policy"], signature, hexBytes(fields["policy"]), "", "")

		if resp.StatusCode != expected.HTTPStatusCode {
			return fmt.Errorf("expected response status code to be %v, instead got %v", expected.HTTPStatusCode, resp.StatusCode)
		}
		return compareS3ApiErrFields(
			compareErrField("AWSAccessKeyId", expected.AWSAccessKeyId, errResp.AWSAccessKeyId),
			compareErrField("StringToSign", expected.StringToSign, errResp.StringToSign),
			compareErrField("SignatureProvided", expected.SignatureProvided, errResp.SignatureProvided),
			compareErrField("StringToSignBytes", expected.StringToSignBytes, errResp.StringToSignBytes),
			checkErrFieldEmptiness("CanonicalRequest", expected.CanonicalRequest, false),
			checkErrFieldEmptiness("CanonicalRequestBytes", expected.CanonicalRequestBytes, false),
		)
	})
}

func PostObject_expired_due_to_date(s *S3Conf) error {
	testName := "PostObject_expired_due_to_date"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// any x-amz-date older than 1 hour are considered as invalid
		// and an expired policy is returned
		expiredDate := time.Now().UTC().Add(-1 * time.Hour).Add(-1 * time.Minute)

		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			date:        expiredDate,
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.InvalidPolicyDocument.PolicyExpired())
	})
}

func PostObject_access_denied(s *S3Conf) error {
	testName := "PostObject_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Anonymous request: suppress all five auth fields so the middleware
		// treats this as an unauthenticated POST to a private bucket.
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"x-amz-algorithm":  "",
				"x-amz-credential": "",
				"x-amz-date":       "",
				"policy":           "",
				"x-amz-signature":  "",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// PostObject_bucket_policy_object_resource covers a user whose only upload
// grant is a bucket policy scoped to a key prefix. A POST upload is an
// s3:PutObject on the object its key field names, so it is authorized
// against that object's ARN, as PutObject is: the grant on
// "bucket/uploads/*" allows a key under uploads/ and denies any other.
func PostObject_bucket_policy_object_resource(s *S3Conf) error {
	testName := "PostObject_bucket_policy_object_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/uploads/*", bucket),
		}); err != nil {
			return err
		}

		post := func(key string) (*http.Response, error) {
			return sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         key,
				access:      testuser.access,
				secret:      testuser.secret,
				s3Conf:      s,
				fileContent: []byte("data"),
			})
		}

		allowedKey := "uploads/my-obj"
		resp, err := post(allowedKey)
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST %s: %w", allowedKey, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &allowedKey,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected %s to be uploaded: %w", allowedKey, err)
		}

		resp, err = post("private/my-obj")
		if err != nil {
			return err
		}
		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// PostObject_bucket_policy_explicit_deny covers a Deny statement scoped to
// a key prefix overriding a bucket-wide Allow for POST uploads, the way it
// does for PutObject: the Deny on "bucket/private/*" matches the object ARN
// a POST to a private/ key is authorized against, and nothing else.
func PostObject_bucket_policy_explicit_deny(s *S3Conf) error {
	testName := "PostObject_bucket_policy_explicit_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			},
			bucketStatement{
				Effect:    "Deny",
				Principal: testuser.access,
				Action:    "s3:PutObject",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/private/*", bucket),
			},
		); err != nil {
			return err
		}

		post := func(key string) (*http.Response, error) {
			return sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         key,
				access:      testuser.access,
				secret:      testuser.secret,
				s3Conf:      s,
				fileContent: []byte("data"),
			})
		}

		allowedKey := "public/my-obj"
		resp, err := post(allowedKey)
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST %s: %w", allowedKey, err)
		}

		deniedKey := "private/my-obj"
		resp, err = post(deniedKey)
		if err != nil {
			return err
		}
		return checkHTTPResponseApiErr(resp, s3err.GetExplicitDenyAccessErr(testuser.access, "s3:PutObject",
			fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, deniedKey), "a resource-based policy"))
	})
}

func PostObject_tagging_requires_put_object_tagging(s *S3Conf) error {
	testName := "PostObject_tagging_requires_put_object_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		key := "my-obj"
		taggingXML := `<Tagging><TagSet><Tag><Key>env</Key><Value>test</Value></Tag></TagSet></Tagging>`
		post := func() (*http.Response, error) {
			return sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         key,
				access:      testuser.access,
				secret:      testuser.secret,
				s3Conf:      s,
				fileContent: []byte("data"),
				policyConditions: []any{
					[]any{"eq", "$tagging", taggingXML},
				},
				extraFields: map[string]string{
					"tagging": taggingXML,
				},
			})
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		resp, err := post()
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("POST with s3:PutObject only: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return fmt.Errorf("expected the denied POST not to create %s: %w", key, err)
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    []string{"s3:PutObject", "s3:PutObjectTagging"},
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		resp, err = post()
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST with s3:PutObject and s3:PutObjectTagging: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		tagging, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedTagging := []types.Tag{{Key: getPtr("env"), Value: getPtr("test")}}
		if !areTagsSame(expectedTagging, tagging.TagSet) {
			return fmt.Errorf("expected %v tagging, instead got %v", expectedTagging, tagging.TagSet)
		}

		return nil
	})
}

// PostObject_tagging_bucket_policy_explicit_deny covers a Deny on
// s3:PutObjectTagging scoped to a key prefix. It refuses a tagged POST
// upload to a key under that prefix although a bucket-wide Allow grants
// both actions, and leaves an untagged upload there, which needs only
// s3:PutObject, alone.
func PostObject_tagging_bucket_policy_explicit_deny(s *S3Conf) error {
	testName := "PostObject_tagging_bucket_policy_explicit_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket,
			bucketStatement{
				Effect:    "Allow",
				Principal: testuser.access,
				Action:    []string{"s3:PutObject", "s3:PutObjectTagging"},
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			},
			bucketStatement{
				Effect:    "Deny",
				Principal: testuser.access,
				Action:    "s3:PutObjectTagging",
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/private/*", bucket),
			},
		); err != nil {
			return err
		}

		cfg := func(key string) PostRequestConfig {
			return PostRequestConfig{
				bucket:      bucket,
				key:         key,
				access:      testuser.access,
				secret:      testuser.secret,
				s3Conf:      s,
				fileContent: []byte("data"),
			}
		}
		taggingXML := `<Tagging><TagSet><Tag><Key>env</Key><Value>test</Value></Tag></TagSet></Tagging>`
		tagged := func(key string) PostRequestConfig {
			c := cfg(key)
			c.policyConditions = []any{
				[]any{"eq", "$tagging", taggingXML},
			}
			c.extraFields = map[string]string{
				"tagging": taggingXML,
			}
			return c
		}

		allowedKey := "public/my-obj"
		resp, err := sendPostObject(tagged(allowedKey))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("tagged POST %s: %w", allowedKey, err)
		}

		deniedKey := "private/my-obj"
		resp, err = sendPostObject(tagged(deniedKey))
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetExplicitDenyAccessErr(testuser.access, "s3:PutObjectTagging",
			fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, deniedKey), "a resource-based policy")); err != nil {
			return fmt.Errorf("tagged POST %s: %w", deniedKey, err)
		}

		resp, err = sendPostObject(cfg(deniedKey))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("untagged POST %s: %w", deniedKey, err)
		}
		return nil
	})
}

// PostObject_empty_tag_set_requires_only_put_object covers a tagging field
// whose tag set is empty. It tags nothing, so the upload needs only
// s3:PutObject, as it does on S3.
func PostObject_empty_tag_set_requires_only_put_object(s *S3Conf) error {
	testName := "PostObject_empty_tag_set_requires_only_put_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: testuser.access,
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		key := "my-obj"
		taggingXML := `<Tagging><TagSet></TagSet></Tagging>`
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         key,
			access:      testuser.access,
			secret:      testuser.secret,
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				[]any{"eq", "$tagging", taggingXML},
			},
			extraFields: map[string]string{
				"tagging": taggingXML,
			},
		})
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		tagging, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}
		if len(tagging.TagSet) != 0 {
			return fmt.Errorf("expected no tags, instead got %v", tagging.TagSet)
		}

		return nil
	})
}

func PostObject_invalid_object_names(s *S3Conf) error {
	testName := "PostObject_invalid_object_names"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, obj := range []string{
			"/",
			"//",
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         obj,
				s3Conf:      s,
				fileContent: []byte("data"),
			})
			if err != nil {
				return err
			}

			if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PostObject_policy_access_control(s *S3Conf) error {
	testName := "PostObject_policy_access_control"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, test := range []struct {
			conditions  []any
			extraFields map[string]string
			expectedErr error
		}{
			// success: eq condition on content-type matches submitted value
			{
				conditions: []any{
					[]any{"eq", "$content-type", "text/plain"},
				},
				extraFields: map[string]string{
					"content-type": "text/plain",
				},
			},
			// success: starts-with condition on a custom meta field matches submitted value
			{
				conditions: []any{
					[]any{"starts-with", "$x-amz-meta-env", "prod"},
				},
				extraFields: map[string]string{
					"x-amz-meta-env": "production",
				},
			},
			// success: starts-with with an empty prefix acts as a wildcard — any value is accepted
			{
				conditions: []any{
					[]any{"starts-with", "$x-amz-meta-tag", ""},
				},
				extraFields: map[string]string{
					"x-amz-meta-tag": "anything-goes",
				},
			},
			// success: object-form (map) condition matches submitted content-type
			{
				conditions: []any{
					map[string]any{"content-type": "image/png"},
				},
				extraFields: map[string]string{
					"content-type": "image/png",
				},
			},
			// success: eq condition on $bucket matches the actual bucket in the request
			{
				conditions: []any{
					[]any{"eq", "$bucket", bucket},
				},
			},
			// success: x-ignore-* prefixed fields are exempt from policy coverage
			{
				extraFields: map[string]string{
					"x-ignore-custom": "value",
				},
			},
			// success: content-length-range — body size is within the allowed bounds
			{
				conditions: []any{
					[]any{"content-length-range", 1, 100},
				},
			},
			// success: starts-with on content-type where all comma-separated parts satisfy the prefix
			{
				conditions: []any{
					[]any{"starts-with", "$content-type", "text/"},
				},
				extraFields: map[string]string{
					"content-type": "text/plain, text/html",
				},
			},
			// condition failed: eq on content-type — submitted value doesn't match policy
			{
				conditions: []any{
					[]any{"eq", "$content-type", "text/plain"},
				},
				extraFields: map[string]string{
					"content-type": "image/jpeg",
				},
				expectedErr: s3err.InvalidPolicyDocument.ConditionFailed(`["eq","$content-type","text/plain"]`),
			},
			// condition failed: starts-with on a meta field — value doesn't begin with the required prefix
			{
				conditions: []any{
					[]any{"starts-with", "$x-amz-meta-path", "allowed/"},
				},
				extraFields: map[string]string{
					"x-amz-meta-path": "forbidden/value",
				},
				expectedErr: s3err.InvalidPolicyDocument.ConditionFailed(`["starts-with","$x-amz-meta-path","allowed/"]`),
			},
			// condition failed: eq on $bucket — policy expects a different bucket name
			{
				conditions: []any{
					[]any{"eq", "$bucket", "wrong-bucket-name"},
				},
				expectedErr: s3err.InvalidPolicyDocument.ConditionFailed(`["eq","$bucket","wrong-bucket-name"]`),
			},
			// condition failed: object-form condition — submitted content-type doesn't match the policy value
			{
				conditions: []any{
					map[string]any{"content-type": "application/xml"},
				},
				extraFields: map[string]string{
					"content-type": "text/html",
				},
				expectedErr: s3err.InvalidPolicyDocument.ConditionFailed(`["eq", "$content-type", "application/xml"]`),
			},
			// condition failed: starts-with on content-type — comma-separated value contains a non-matching part
			{
				conditions: []any{
					[]any{"starts-with", "$content-type", "text/"},
				},
				extraFields: map[string]string{
					"content-type": "text/plain, image/jpeg",
				},
				expectedErr: s3err.InvalidPolicyDocument.ConditionFailed(`["starts-with","$content-type","text/"]`),
			},
			// extra input field: x-amz-meta field submitted without a matching policy condition
			{
				extraFields: map[string]string{
					"x-amz-meta-custom": "value",
				},
				expectedErr: s3err.InvalidPolicyDocument.ExtraInputField("x-amz-meta-custom"),
			},
			// extra input field: content-type submitted without a matching policy condition
			{
				extraFields: map[string]string{
					"content-type": "text/plain",
				},
				expectedErr: s3err.InvalidPolicyDocument.ExtraInputField("content-type"),
			},
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:           bucket,
				key:              "test-object",
				s3Conf:           s,
				fileContent:      []byte("data"),
				extraFields:      test.extraFields,
				policyConditions: test.conditions,
			})
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if test.expectedErr != nil {
				if err := checkHTTPResponseApiErr(resp, test.expectedErr.(s3err.APIError)); err != nil {
					return fmt.Errorf("test %v failed: %w", i+1, err)
				}
			}

			if test.expectedErr == nil && resp.StatusCode >= 400 {
				return fmt.Errorf("test %v failed: expected a successful response, instead got %d response status", i+1, resp.StatusCode)
			}
		}

		return nil
	})
}

func PostObject_policy_expired(s *S3Conf) error {
	testName := "PostObject_policy_expired"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		expiredAt := time.Now().UTC().Add(-5 * time.Minute)

		resp, err := sendPostObject(PostRequestConfig{
			bucket:           bucket,
			key:              "test-object",
			s3Conf:           s,
			fileContent:      []byte("data"),
			policyExpiration: expiredAt,
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.InvalidPolicyDocument.PolicyExpired())
	})
}

func PostObject_invalid_policy_document(s *S3Conf) error {
	testName := "PostObject_invalid_policy_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		validExp := time.Now().AddDate(0, 0, 1)
		for i, test := range []struct {
			policy     *string
			expiration time.Time
			conditions []any
			err        s3err.S3Error
		}{
			// empty policy document
			{getPtr(""), time.Time{}, []any{}, s3err.InvalidPolicyDocument.EmptyPolicy()},
			// invalid base64
			{getPtr("invalid_base64"), time.Time{}, []any{}, s3err.InvalidPolicyDocument.InvalidBase64Encoding()},
			// invalid json
			{getPtr("aW52YWxpZCBqc29u"), time.Time{}, []any{}, s3err.InvalidPolicyDocument.InvalidJSON()},
			// missing expiration
			{getPtr("ewogICAgImNvbmRpdGlvbnMiOiBbXQp9"), time.Time{}, []any{}, s3err.InvalidPolicyDocument.MissingExpiration()},
			// invalid expiration
			{getPtr("ewogICAgImV4cGlyYXRpb24iOiB0cnVlLAogICAgImNvbmRpdGlvbnMiOiBbeyJoZWxsbyI6IndvcmxkIn1dCn0="), time.Time{}, []any{}, s3err.InvalidPolicyDocument.InvalidJSON()},
			// invalid expiration date string
			{getPtr("ewogICAgImV4cGlyYXRpb24iOiAiaW52YWxpZCIsCiAgICAiY29uZGl0aW9ucyI6IFt7ImhlbGxvIjoid29ybGQifV0KfQ=="), time.Time{}, []any{}, s3err.InvalidPolicyDocument.InvalidExpiration("invalid")},
			// missing conditions
			{getPtr("ewogICAgImV4cGlyYXRpb24iOiAiMjE0NC0xMS0wOFQwNDoxOTozM1oiCn0="), time.Time{}, []any{}, s3err.InvalidPolicyDocument.MissingConditions()},
			// invalid 'conditions'
			{getPtr("ewogICAgImV4cGlyYXRpb24iOiAiMjE0NC0xMS0wOFQwNDoxOTozM1oiLAogICAgImNvbmRpdGlvbnMiOiB0cnVlCn0="), time.Time{}, []any{}, s3err.InvalidPolicyDocument.InvalidConditions()},
			// invalid condition
			{getPtr("ewogICAgImV4cGlyYXRpb24iOiAiMjE0NC0xMS0wOFQwNDoxOTozM1oiLAogICAgImNvbmRpdGlvbnMiOiBbdHJ1ZV0KfQ=="), time.Time{}, []any{}, s3err.InvalidPolicyDocument.InvalidCondition()},
			// extra field in policy document
			{getPtr("ewogICJjb25kaXRpb25zIjogW3sieC1hbXotZGF0ZSI6ICIyMDI2MDMyN1QwOTE4MjJaIn1dLAogICJleHBpcmF0aW9uIjogIjIwMjYtMDMtMjhUMDk6MTg6MjJaIiwKICAiZXh0cmEiOiAiZmllbGQiCn0="), time.Time{}, []any{}, s3err.InvalidPolicyDocument.UnexpectedField("extra")},
			// expired policy
			{nil, time.Now().AddDate(0, 0, -1), []any{}, s3err.InvalidPolicyDocument.PolicyExpired()},
			// missing condition operation(eq, starts-with ...) identifier
			{nil, validExp, []any{[]any{}}, s3err.InvalidPolicyDocument.MissingConditionOperationIdentifier()},
			// unknown/invalid condition operator
			{nil, validExp, []any{[]any{"invalid", "$content-type", "application/json"}}, s3err.InvalidPolicyDocument.UnknownConditionOperation("invalid")},
			// incorrect number of argument in a condition
			{nil, validExp, []any{[]any{"eq", "$content-type", "application/json", "something"}}, s3err.InvalidPolicyDocument.IncorrectConditionArgumentsNumber("eq")},
			// invalid field argument
			{nil, validExp, []any{[]any{"eq", false, "application/json"}}, s3err.InvalidPolicyDocument.InvalidJSON()},
			// invalid value argument
			{nil, validExp, []any{[]any{"eq", "$content-type", true}}, s3err.InvalidPolicyDocument.InvalidJSON()},
			// no $ sign in field
			{nil, validExp, []any{[]any{"eq", "content-type", "binary/octet-stream"}}, s3err.InvalidPolicyDocument.ConditionFailed(`["eq","content-type","binary/octet-stream"]`)},
			// invalid content-length-range
			{nil, validExp, []any{[]any{"content-length-range", 12, false}}, s3err.InvalidPolicyDocument.InvalidJSON()},
			// invalid content-length-range 2
			{nil, validExp, []any{[]any{"content-length-range", "invalid", "14"}}, s3err.InvalidPolicyDocument.InvalidJSON()},
			// multiple property simple condition
			{nil, validExp, []any{map[string]any{"expires": "exp", "cache": "smth"}}, s3err.InvalidPolicyDocument.OnePropSimpleCondition()},
			// invalid simple condition value
			{nil, validExp, []any{map[string]any{"expires": true}}, s3err.InvalidPolicyDocument.InvalidSimpleCondition()},
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:           bucket,
				key:              "test-object",
				s3Conf:           s,
				fileContent:      []byte("data"),
				rawPolicy:        test.policy,
				policyExpiration: test.expiration,
				policyConditions: test.conditions,
			})
			if err != nil {
				return fmt.Errorf("test %d failed: %w", i+1, err)
			}

			if err := checkHTTPResponseApiErr(resp, test.err); err != nil {
				return fmt.Errorf("test %d failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func PostObject_policy_condition_key_mismatch(s *S3Conf) error {
	testName := "PostObject_policy_condition_key_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "expected-key",
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				[]any{"eq", "$key", "expected-key"},
			},
			omitPolicyConditions: map[string]struct{}{
				"key": {},
			},
			extraFields: map[string]string{
				"key": "other-key",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.InvalidPolicyDocument.ConditionFailed(`["eq","$key","expected-key"]`))
	})
}

func PostObject_policy_extra_field(s *S3Conf) error {
	testName := "PostObject_policy_extra_field"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"content-type": "text/plain",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.InvalidPolicyDocument.ExtraInputField("content-type"))
	})
}

func PostObject_policy_missing_bucket_condition(s *S3Conf) error {
	testName := "PostObject_policy_missing_bucket_condition"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			omitPolicyConditions: map[string]struct{}{
				"bucket": {},
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.InvalidPolicyDocument.ExtraInputField("bucket"))
	})
}

func PostObject_policy_content_length_too_large(s *S3Conf) error {
	testName := "PostObject_policy_content_length_too_large"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Allow at most 5 bytes; we upload 10 bytes.
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("0123456789"),
			policyConditions: []any{
				[]any{"content-length-range", 0, 5},
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetEntityTooLargeErr(10, 5))
	})
}

func PostObject_policy_content_length_too_small(s *S3Conf) error {
	testName := "PostObject_policy_content_length_too_small"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Require at least 100 bytes; we upload 2 bytes.
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("hi"),
			policyConditions: []any{
				[]any{"content-length-range", 100, 1024},
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetEntityTooSmallErr(2, 100))
	})
}

func PostObject_success(s *S3Conf) error {
	testName := "PostObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "my-object",
			s3Conf:      s,
			fileContent: []byte("some dummy data"),
		})
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected status 204, instead got %d", resp.StatusCode)
		}
		if resp.Header.Get("ETag") == "" {
			return fmt.Errorf("expected ETag response header to be set")
		}
		location := constructObjectLocation(s.endpoint, bucket, "my-object", s.hostStyle)
		if resp.Header.Get("Location") != location {
			return fmt.Errorf("expected Location to be %s, instead got %s", location, resp.Header.Get("Location"))
		}
		return nil
	})
}

func PostObject_success_status_200(s *S3Conf) error {
	testName := "PostObject_success_status_200"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("hello"),
			policyConditions: []any{
				[]any{"eq", "$success_action_status", "200"},
			},
			extraFields: map[string]string{
				"success_action_status": "200",
			},
		})
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		return nil
	})
}

func PostObject_success_status_201(s *S3Conf) error {
	testName := "PostObject_success_status_201"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "test-object"
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         key,
			s3Conf:      s,
			fileContent: []byte("hello"),
			policyConditions: []any{
				[]any{"eq", "$success_action_status", "201"},
			},
			extraFields: map[string]string{
				"success_action_status": "201",
			},
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("expected status 201, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var postResp s3response.PostResponse
		if err := xml.Unmarshal(body, &postResp); err != nil {
			return fmt.Errorf("failed to unmarshal PostResponse XML: %w", err)
		}
		if postResp.Bucket != bucket {
			return fmt.Errorf("expected Bucket to be %q, instead got %q", bucket, postResp.Bucket)
		}
		if postResp.Key != key {
			return fmt.Errorf("expected Key to be %q ,instead got %q", key, postResp.Key)
		}
		if postResp.ETag == "" {
			return fmt.Errorf("expected non-empty ETag in response")
		}
		location := constructObjectLocation(s.endpoint, bucket, key, s.hostStyle)
		if resp.Header.Get("Location") != location {
			return fmt.Errorf("expected Location to be %s, instead got %s", location, resp.Header.Get("Location"))
		}

		return nil
	})
}

func PostObject_should_ignore_anything_after_file(s *S3Conf) error {
	testName := "PostObject_should_ignore_anything_after_file"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "test-object"
		objData := []byte("dummy data")
		signingDate := time.Now().UTC()
		fields := buildSignedPostFields(bucket, key, s.awsID, s.awsRegion, signingDate)
		// the policy allows the file's size and no more, so the size checked
		// is the file's, not the body's with the tail
		conditions := []any{[]any{"content-length-range", 1, len(objData)}}
		policy, err := encodePostPolicy(conditions, time.Now().UTC().Add(time.Minute*10), fields, make(map[string]struct{}))
		if err != nil {
			return err
		}

		fields["policy"] = policy
		fields["x-amz-signature"] = signPostPolicy(policy, signingDate.Format("20060102"), s.awsRegion, s.awsSecret)

		body, boundary, err := buildPostObjectBody(fields, map[string]string{}, objData, nil, nil)
		if err != nil {
			return err
		}

		body = append(body, []byte("tail data that should be ignored")...)

		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", s.endpoint, bucket), bytes.NewReader(body))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected status code to be 204, instead got %d", resp.StatusCode)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		defer res.Body.Close()
		gotObjData, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}

		if !bytes.Equal(gotObjData, objData) {
			return fmt.Errorf("expected the object data to be %s, instead got %s", objData, gotObjData)
		}

		return nil
	})
}

func PostObject_success_with_meta_properties(s *S3Conf) error {
	testName := "PostObject_success_with_meta_properties"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "test-object"
		cType := "image/png"
		cacheControl := "max-age=100"
		expires := "Fri, 21 Mar 2026 00:00:00 GMT"
		cLanguage := "en-US"
		cDisposition := "inline"
		cEncoding := "gzip"
		redirectLocation := "/post-object-redirect"

		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         key,
			s3Conf:      s,
			fileContent: []byte("dummy data"),
			policyConditions: []any{
				[]any{"eq", "$Content-Type", cType},
				[]any{"eq", "$Content-Disposition", cDisposition},
				[]any{"eq", "$Content-Language", cLanguage},
				[]any{"eq", "$Content-Encoding", cEncoding},
				[]any{"eq", "$Cache-Control", cacheControl},
				[]any{"eq", "$Expires", expires},
				[]any{"eq", "$x-amz-website-redirect-location", redirectLocation},
				[]any{"eq", "$x-amz-meta-foo", "bar"},
				[]any{"eq", "$x-amz-meta-baz", "quxx"},
			},
			extraFields: map[string]string{
				"Content-Type":                    cType,
				"Cache-Control":                   cacheControl,
				"Expires":                         expires,
				"Content-Language":                cLanguage,
				"Content-Disposition":             cDisposition,
				"Content-Encoding":                cEncoding,
				"x-amz-website-redirect-location": redirectLocation,
				"x-amz-meta-foo":                  "bar",
				"x-amz-meta-baz":                  "quxx",
			},
		})
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected status code to be 204, instead got %d", resp.StatusCode)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(out.ContentType) != cType {
			return fmt.Errorf("expected Content-Type %s, instead got %s",
				cType, getString(out.ContentType))
		}
		if getString(out.ContentDisposition) != cDisposition {
			return fmt.Errorf("expected Content-Disposition %s, instead got %s",
				cDisposition, getString(out.ContentDisposition))
		}
		if getString(out.ContentEncoding) != cEncoding {
			return fmt.Errorf("expected Content-Encoding %s, instead got %s",
				cEncoding, getString(out.ContentEncoding))
		}
		if getString(out.ContentLanguage) != cLanguage {
			return fmt.Errorf("expected Content-Language %s, instead got %s",
				cLanguage, getString(out.ContentLanguage))
		}
		if getString(out.ExpiresString) != expires {
			return fmt.Errorf("expected Expires %s, instead got %s",
				expires, getString(out.ExpiresString))
		}
		if getString(out.CacheControl) != cacheControl {
			return fmt.Errorf("expected Cache-Control %s, instead got %s",
				cacheControl, getString(out.CacheControl))
		}
		if getString(out.WebsiteRedirectLocation) != redirectLocation {
			return fmt.Errorf("expected WebsiteRedirectLocation %s, instead got %s",
				redirectLocation, getString(out.WebsiteRedirectLocation))
		}

		expectedMeta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		if !areMapsSame(expectedMeta, out.Metadata) {
			return fmt.Errorf("expected the object metadata to be %v, instead got %v", expectedMeta, out.Metadata)
		}

		return nil
	})
}

func PostObject_default_content_type(s *S3Conf) error {
	testName := "PostObject_default_content_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, tt := range []struct {
			key              string
			policyConditions []any
			extraFields      map[string]string
		}{
			{
				key: "omitted-content-type",
			},
			{
				key: "empty-content-type",
				policyConditions: []any{
					[]any{"starts-with", "$Content-Type", ""},
				},
				extraFields: map[string]string{
					"Content-Type": "",
				},
			},
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:           bucket,
				key:              tt.key,
				s3Conf:           s,
				fileContent:      []byte("dummy data"),
				policyConditions: tt.policyConditions,
				extraFields:      tt.extraFields,
			})
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("%s: expected status code to be 204, instead got %d",
					tt.key, resp.StatusCode)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &tt.key,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(out.ContentType) != defaultContentType {
				return fmt.Errorf("%s: expected default %s Content-Type, instead got %s",
					tt.key, defaultContentType, getString(out.ContentType))
			}
		}

		return nil
	})
}

func PostObject_invalid_website_redirect_location(s *S3Conf) error {
	testName := "PostObject_invalid_website_redirect_location"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		redirectLocation := "ftp://example.com"
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				[]any{"eq", "$x-amz-website-redirect-location", redirectLocation},
			},
			extraFields: map[string]string{
				"x-amz-website-redirect-location": redirectLocation,
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrInvalidRedirectLocation))
	})
}

func PostObject_invalid_tagging(s *S3Conf) error {
	testName := "PostObject_invalid_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := "invalid"
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				[]any{"eq", "$tagging", tagging},
			},
			extraFields: map[string]string{
				"tagging": tagging,
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMalformedXML))
	})
}

func PostObject_success_with_tagging(s *S3Conf) error {
	testName := "PostObject_success_with_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "test-object"
		taggingXML := `<Tagging><TagSet><Tag><Key>env</Key><Value>test</Value></Tag></TagSet></Tagging>`

		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         key,
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				[]any{"eq", "$tagging", taggingXML},
			},
			extraFields: map[string]string{
				"tagging": taggingXML,
			},
		})
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected status 204, got %d", resp.StatusCode)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		tagging, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedTagging := []types.Tag{{Key: getPtr("env"), Value: getPtr("test")}}
		if !areTagsSame(expectedTagging, tagging.TagSet) {
			return fmt.Errorf("expected %v tagging, instead got %v", expectedTagging, tagging.TagSet)
		}

		return nil
	})
}

func PostObject_invalid_checksum_value(s *S3Conf) error {
	testName := "PostObject_invalid_checksum_value"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, algo := range types.ChecksumAlgorithmCrc32.Values() {
			algoHdr := fmt.Sprintf("x-amz-checksum-%s", strings.ToLower(string(algo)))

			resp, err := sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         "test-object",
				s3Conf:      s,
				fileContent: []byte("data"),
				policyConditions: []any{
					map[string]string{
						algoHdr: "invalid",
					},
				},
				extraFields: map[string]string{
					algoHdr: "invalid",
				},
			})
			if err != nil {
				return err
			}

			if err := checkHTTPResponseApiErr(resp, s3err.GetInvalidChecksumHeaderErr(algoHdr)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PostObject_invalid_checksum_algorithm(s *S3Conf) error {
	testName := "PostObject_invalid_checksum_algorithm"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		invalidAlgoHdr := "x-amz-checksum-invalid"

		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				map[string]string{
					invalidAlgoHdr: "invalid",
				},
			},
			extraFields: map[string]string{
				invalidAlgoHdr: "invalid",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrInvalidChecksumHeader))
	})
}

func PostObject_multiple_checksum_headers(s *S3Conf) error {
	testName := "PostObject_multiple_checksum_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("test data"),
			policyConditions: []any{
				map[string]string{
					"x-amz-checksum-crc32": "0wiusg==",
				},
				map[string]string{
					"x-amz-checksum-crc32c": "M3m0yg==",
				},
			},
			extraFields: map[string]string{
				"x-amz-checksum-crc32":  "0wiusg==",
				"x-amz-checksum-crc32c": "M3m0yg==",
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders))
	})
}

func PostObject_checksums_success(s *S3Conf) error {
	testName := "PostObject_checksums_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, test := range []struct {
			algo     string
			checksum string
		}{
			{"x-amz-checksum-crc32", "0wiusg=="},
			{"x-amz-checksum-crc32c", "M3m0yg=="},
			{"x-amz-checksum-crc64nvme", "rsrzr5yYqFU="},
			{"x-amz-checksum-sha1", "9I3YU4IIYIFsddVND1hNyGMyenw="},
			{"x-amz-checksum-sha256", "kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk="},
			{"x-amz-checksum-sha512", "Dh4h7PEF7IU9JNcohnrXBhPCFmOkaTB0sqNhnBvTnWa1iMM3I7tGbHJCToDjymPCSQeKs0e6uUKFAOfuQwWdDQ=="},
			{"x-amz-checksum-md5", "63M6AMDJ0zbmVpGjerVCkw=="},
			{"x-amz-checksum-xxhash64", "+lb36/ER8bo="},
			{"x-amz-checksum-xxhash3", "jw+pSh/pbMQ="},
			{"x-amz-checksum-xxhash128", "8BLDqqIWji+ITOsp/JjN/Q=="},
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         "test-object",
				s3Conf:      s,
				fileContent: []byte("test data"),
				policyConditions: []any{
					map[string]string{
						test.algo: test.checksum,
					},
				},
				extraFields: map[string]string{
					test.algo: test.checksum,
				},
			})
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("test %d failed: expected the response status code to be 204, instead got %d", i+1, resp.StatusCode)
			}
		}

		return nil
	})
}

func PostObject_success_double_dash_boundary(s *S3Conf) error {
	testName := "PostObject_success_double_dash_boundary"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "test-object"
		objData := []byte("hello world")
		signingDate := time.Now().UTC()

		fields := buildSignedPostFields(bucket, key, s.awsID, s.awsRegion, signingDate)
		policy, err := encodePostPolicy([]any{}, time.Now().UTC().Add(10*time.Minute), fields, make(map[string]struct{}))
		if err != nil {
			return err
		}
		fields["policy"] = policy
		fields["x-amz-signature"] = signPostPolicy(policy, signingDate.Format("20060102"), s.awsRegion, s.awsSecret)

		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.SetBoundary("--custom-post-boundary"); err != nil {
			return fmt.Errorf("failed to set boundary: %w", err)
		}

		for k, v := range fields {
			if err := w.WriteField(k, v); err != nil {
				return err
			}
		}

		fw, err := w.CreateFormFile("file", "upload.bin")
		if err != nil {
			return err
		}
		if _, err = fw.Write(objData); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}

		boundary := w.Boundary()
		body := buf.Bytes()

		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", s.endpoint, bucket), bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
		req.ContentLength = int64(len(body))

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected status 204, got %d", resp.StatusCode)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}
		defer res.Body.Close()

		gotData, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		if !bytes.Equal(gotData, objData) {
			return fmt.Errorf("expected object data %q, got %q", objData, gotData)
		}

		return nil
	})
}

// PostObject_file_without_filename posts the file part with no filename and
// with an empty one, which S3 takes as text content.
func PostObject_file_without_filename(s *S3Conf) error {
	testName := "PostObject_file_without_filename"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for key, disposition := range map[string]string{
			"no-filename":    `form-data; name="file"`,
			"empty-filename": `form-data; name="file"; filename=""`,
		} {
			data := []byte("hello world")
			resp, err := sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         key,
				s3Conf:      s,
				fileContent: data,
				fileHeader:  textproto.MIMEHeader{"Content-Disposition": {disposition}},
			})
			if err != nil {
				return err
			}
			if err := checkPostObjectSuccess(resp); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			if err := checkObjectData(s3client, bucket, key, "", data); err != nil {
				return err
			}
		}

		return nil
	})
}

// PostObject_file_before_key posts the key after the file part. S3 reads no
// field after the file, so the form has no key.
func PostObject_file_before_key(s *S3Conf) error {
	testName := "PostObject_file_before_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:          bucket,
			key:             "my-obj",
			s3Conf:          s,
			fileContent:     []byte("data"),
			fieldsAfterFile: []string{"key"},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.PostAuth.MissingField("key"))
	})
}

// PostObject_ignores_fields_after_file posts a content-type after the file
// part. The policy does not allow it, so the upload succeeds only if it is
// ignored, and the object holds the file alone. The policy also allows the
// file's size and no more, so the size checked is the file's, not the form's.
func PostObject_ignores_fields_after_file(s *S3Conf) error {
	testName := "PostObject_ignores_fields_after_file"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key, data := "my-obj", []byte("data")
		resp, err := sendPostObject(PostRequestConfig{
			bucket:           bucket,
			key:              key,
			s3Conf:           s,
			fileContent:      data,
			extraFields:      map[string]string{"content-type": "text/plain"},
			fieldsAfterFile:  []string{"content-type"},
			policyConditions: []any{[]any{"content-length-range", 1, len(data)}},
		})
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return err
		}

		return checkObjectData(s3client, bucket, key, "", data)
	})
}

// PostObject_content_length_range_fields_after_file posts a content-type after
// a file that is out of the size range the policy allows. The size in the
// error is the file's, not the form's, which holds the field as well.
func PostObject_content_length_range_fields_after_file(s *S3Conf) error {
	testName := "PostObject_content_length_range_fields_after_file"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		cfg := func(data string, lo, hi int) PostRequestConfig {
			return PostRequestConfig{
				bucket:           bucket,
				key:              "my-obj",
				s3Conf:           s,
				fileContent:      []byte(data),
				extraFields:      map[string]string{"content-type": "text/plain"},
				fieldsAfterFile:  []string{"content-type"},
				policyConditions: []any{[]any{"content-length-range", lo, hi}},
			}
		}

		resp, err := sendPostObject(cfg("hello world", 0, 5))
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetEntityTooLargeErr(int64(len("hello world")), 5)); err != nil {
			return fmt.Errorf("over the max: %w", err)
		}

		resp, err = sendPostObject(cfg("hi", 3, 100))
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetEntityTooSmallErr(int64(len("hi")), 3)); err != nil {
			return fmt.Errorf("under the min: %w", err)
		}

		return nil
	})
}

// PostObject_content_length_range_large_file posts a file that takes many
// reads of the body. One in the size range the policy allows is stored, and
// one over it is refused with the size of the file.
func PostObject_content_length_range_large_file(s *S3Conf) error {
	testName := "PostObject_content_length_range_large_file"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key, data := "my-obj", bytes.Repeat([]byte("0123456789abcdef"), 4<<10)
		cfg := func(lo, hi int) PostRequestConfig {
			return PostRequestConfig{
				bucket:           bucket,
				key:              key,
				s3Conf:           s,
				fileContent:      data,
				policyConditions: []any{[]any{"content-length-range", lo, hi}},
			}
		}

		resp, err := sendPostObject(cfg(len(data), len(data)))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("in the range: %w", err)
		}
		if err := checkObjectData(s3client, bucket, key, "", data); err != nil {
			return err
		}

		resp, err = sendPostObject(cfg(0, 5))
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetEntityTooLargeErr(int64(len(data)), 5)); err != nil {
			return fmt.Errorf("over the max: %w", err)
		}

		return nil
	})
}

// PostObject_content_length_range_under_min_keeps_object posts a file under
// the min of the size range to a key that holds an object, and an empty one.
// Both are refused and the object stays as it was. A gateway that sends the
// file to its backend before it sees that the file ends under the min would
// replace the object.
func PostObject_content_length_range_under_min_keeps_object(s *S3Conf) error {
	testName := "PostObject_content_length_range_under_min_keeps_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key, original := "my-obj", []byte("the object that is kept")

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
			Body:   bytes.NewReader(original),
		})
		cancel()
		if err != nil {
			return err
		}

		for _, data := range [][]byte{[]byte("short"), {}} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:           bucket,
				key:              key,
				s3Conf:           s,
				fileContent:      data,
				policyConditions: []any{[]any{"content-length-range", 10, 100}},
			})
			if err != nil {
				return err
			}
			if err := checkHTTPResponseApiErr(resp, s3err.GetEntityTooSmallErr(int64(len(data)), 10)); err != nil {
				return fmt.Errorf("file of %d bytes: %w", len(data), err)
			}
			if err := checkObjectData(s3client, bucket, key, "", original); err != nil {
				return fmt.Errorf("file of %d bytes: %w", len(data), err)
			}
		}

		return nil
	})
}

// PostObject_content_length_range_body_without_final_crlf posts a body that
// ends with "--boundary--" and no CRLF, with a file whose size is the min of
// the size range. The file is too large for its end to be in the bytes the
// gateway reads ahead of it, so the length that the request proposes is not
// known to be wrong. It is two bytes less than the file has, which is under the
// min. The request is refused, and the object at the key stays as it was: it is
// not replaced with an empty one.
func PostObject_content_length_range_body_without_final_crlf(s *S3Conf) error {
	testName := "PostObject_content_length_range_body_without_final_crlf"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key, original, data := "my-obj", []byte("the object that is kept"), bytes.Repeat([]byte("0123456789a"), 1000)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
			Body:   bytes.NewReader(original),
		})
		cancel()
		if err != nil {
			return err
		}

		req, _, err := newPostObjectRequest(PostRequestConfig{
			bucket:           bucket,
			key:              key,
			s3Conf:           s,
			fileContent:      data,
			policyConditions: []any{[]any{"content-length-range", len(data), len(data)}},
		})
		if err != nil {
			return err
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		body = bytes.TrimSuffix(body, []byte("\r\n"))
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)); err != nil {
			return err
		}

		return checkObjectData(s3client, bucket, key, "", original)
	})
}

// postObjectClosings are the ends of a body that S3 takes though they are not
// the final boundary and its CRLF. missing is how many bytes of that boundary
// and CRLF the end lacks: the request proposes that many bytes less than the
// file has.
var postObjectClosings = []struct {
	name    string
	missing int
	closing func(boundary string) string
}{
	{"no closing dashes", 4, func(boundary string) string { return "\r\n--" + boundary }},
	{"no final CRLF", 2, func(boundary string) string { return "\r\n--" + boundary + "--" }},
}

// putObjectBytes stores data at key, for a test that refuses an upload to it
// and checks that the object is as it was.
func putObjectBytes(s3client *s3.Client, bucket, key string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   bytes.NewReader(data),
	})

	return err
}

// PostObject_short_closing_boundary_keeps_object posts a large file in a body
// that ends with "--boundary" and no closing dashes, or with "--boundary--" and
// no CRLF, to a key that holds an object. The length that the request proposes
// for the file is less than the file has. The gateway cannot tell that from a
// form that ends with the file, as the end of the file is not in the bytes it
// reads ahead of the file. A backend that sends the length it is given would
// store the file cut short. The request is refused, and the object stays as it
// was.
func PostObject_short_closing_boundary_keeps_object(s *S3Conf) error {
	testName := "PostObject_short_closing_boundary_keeps_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key, original := "my-obj", []byte("the object that is kept")
		if err := putObjectBytes(s3client, bucket, key, original); err != nil {
			return err
		}

		for _, closing := range postObjectClosings {
			req, _, err := newPostObjectRequestClosing(PostRequestConfig{
				bucket:      bucket,
				key:         key,
				s3Conf:      s,
				fileContent: bytes.Repeat([]byte("a"), 16<<10),
			}, closing.closing)
			if err != nil {
				return fmt.Errorf("%s: %w", closing.name, err)
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("%s: %w", closing.name, err)
			}
			if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)); err != nil {
				return fmt.Errorf("%s: %w", closing.name, err)
			}
			if err := checkObjectData(s3client, bucket, key, "", original); err != nil {
				return fmt.Errorf("%s: %w", closing.name, err)
			}
		}

		return nil
	})
}

// PostObject_small_file_with_short_closing_boundary posts a small file in a
// body that ends with "--boundary" and no closing dashes, or with
// "--boundary--" and no CRLF. The boundary that ends the file is in the bytes
// the gateway reads ahead of the file, so the length that it gives the backend
// is the file's own size, and S3 stores the whole file. That is so wherever the
// reads of the body end: the file is posted with data before it of many sizes,
// and with the end of the form sent after a pause.
func PostObject_small_file_with_short_closing_boundary(s *S3Conf) error {
	testName := "PostObject_small_file_with_short_closing_boundary"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		post := func(key string, cfg PostRequestConfig, closing func(string) string, inParts bool) error {
			cfg.bucket, cfg.key, cfg.s3Conf = bucket, key, s
			req, parts, err := newPostObjectRequestClosing(cfg, closing)
			if err != nil {
				return err
			}

			var resp *http.Response
			if inParts {
				resp, err = sendInParts(s, req, parts)
			} else {
				resp, err = s.httpClient.Do(req)
			}
			if err != nil {
				return err
			}
			if err := checkPostObjectSuccess(resp); err != nil {
				return err
			}

			return checkObjectData(s3client, bucket, key, "", cfg.fileContent)
		}

		for _, closing := range postObjectClosings {
			prefix := strings.ReplaceAll(closing.name, " ", "-")

			for _, size := range []int{0, 1, closing.missing, closing.missing + 1} {
				key := fmt.Sprintf("%s-%d", prefix, size)
				if err := post(key, PostRequestConfig{fileContent: bytes.Repeat([]byte("a"), size)}, closing.closing, false); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			}

			for padding := 0; padding <= 8500; padding += 64 {
				key := fmt.Sprintf("%s-%d-bytes-before", prefix, padding)
				cfg := PostRequestConfig{
					fileContent: bytes.Repeat([]byte("a"), 3000),
					extraFields: map[string]string{"x-ignore-padding": strings.Repeat("a", padding)},
				}
				if err := post(key, cfg, closing.closing, false); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			}

			// The gateway handles the request once it has read 8 KiB, so the
			// data before the file is longer than that.
			key := prefix + "-sent-after-a-pause"
			cfg := PostRequestConfig{
				fileContent: bytes.Repeat([]byte("a"), closing.missing+1),
				extraFields: map[string]string{"x-ignore-padding": strings.Repeat("a", 9<<10)},
			}
			if err := post(key, cfg, closing.closing, true); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}

		return nil
	})
}

// PostObject_small_file_with_field_after_file posts a file of 1, 1000 and 3000
// bytes with a field after it, as the submit button of a form is, with data
// before the file of many sizes. A backend that sends the length it is given as
// the Content-Length, as the S3 proxy does, takes the file only if that length
// is the file's own size. The gateway reads ahead of the file for the end of
// the file, so the length is the file's own whatever the length of the data
// before it is. posix takes a length that is too large, so only the S3 proxy
// fails this test without that read.
func PostObject_small_file_with_field_after_file(s *S3Conf) error {
	testName := "PostObject_small_file_with_field_after_file"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, size := range []int{1, 1000, 3000} {
			data := bytes.Repeat([]byte("a"), size)
			for padding := 0; padding <= 5000; padding += 64 {
				key := fmt.Sprintf("file-of-%d-bytes-%d-bytes-before", size, padding)
				resp, err := sendPostObject(PostRequestConfig{
					bucket:      bucket,
					key:         key,
					s3Conf:      s,
					fileContent: data,
					extraFields: map[string]string{
						"submit":           "Upload to Amazon S3",
						"x-ignore-padding": strings.Repeat("a", padding),
					},
					fieldsAfterFile: []string{"submit"},
				})
				if err != nil {
					return err
				}
				if err := checkPostObjectSuccess(resp); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
				if err := checkObjectData(s3client, bucket, key, "", data); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			}
		}

		return nil
	})
}

// PostObject_empty_file_with_field_after_file posts an empty file with a field
// after it, as the submit button of a form is, to a key and to a key that ends
// in a slash. The boundary that ends the file follows its headers, so the
// length that the gateway gives the backend is 0 and not the size of the field.
// A backend refuses data for a key that ends in a slash. The gateway reads the
// body in parts, whose ends fall at different places in the form. So the key
// that ends in a slash is posted with data before the file of many sizes, for
// the end of a part to fall before, in and after the boundary.
func PostObject_empty_file_with_field_after_file(s *S3Conf) error {
	testName := "PostObject_empty_file_with_field_after_file"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		post := func(key string, padding int) error {
			resp, err := sendPostObject(PostRequestConfig{
				bucket: bucket,
				key:    key,
				s3Conf: s,
				extraFields: map[string]string{
					"submit":           "Upload to Amazon S3",
					"x-ignore-padding": strings.Repeat("a", padding),
				},
				fieldsAfterFile: []string{"submit"},
			})
			if err != nil {
				return err
			}
			if err := checkPostObjectSuccess(resp); err != nil {
				return err
			}

			return checkObjectData(s3client, bucket, key, "", nil)
		}

		for _, key := range []string{"my-obj", "my-dir/"} {
			if err := post(key, 0); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
		for padding := 3500; padding <= 8500; padding += 32 {
			if err := post("my-dir/", padding); err != nil {
				return fmt.Errorf("%d bytes of data before the file: %w", padding, err)
			}
		}

		return nil
	})
}

// PostObject_preamble_and_folded_header posts a body with a preamble before
// the first boundary and the file part's Content-Disposition folded over two
// lines.
func PostObject_preamble_and_folded_header(s *S3Conf) error {
	testName := "PostObject_preamble_and_folded_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key, data := "my-obj", []byte("data")
		req, _, err := newPostObjectRequest(PostRequestConfig{
			bucket:      bucket,
			key:         key,
			s3Conf:      s,
			fileContent: data,
			fileHeader:  textproto.MIMEHeader{"Content-Disposition": {"form-data;\r\n name=\"file\"; filename=\"upload.bin\""}},
		})
		if err != nil {
			return err
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		body = append([]byte("\r\nThis is the preamble.\r\n"), body...)
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return err
		}

		return checkObjectData(s3client, bucket, key, "", data)
	})
}

// PostObject_data_before_file_limit checks S3's 20 KB limit on the bytes
// before the file content: a form at the limit is stored, one a byte over it
// is refused.
func PostObject_data_before_file_limit(s *S3Conf) error {
	testName := "PostObject_data_before_file_limit"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		data := []byte("data")
		cfg := func(padding int) PostRequestConfig {
			return PostRequestConfig{
				bucket:      bucket,
				key:         "my-obj",
				s3Conf:      s,
				fileContent: data,
				extraFields: map[string]string{"x-ignore-padding": strings.Repeat("a", padding)},
			}
		}

		req, _, err := newPostObjectRequest(cfg(0))
		if err != nil {
			return err
		}
		_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil {
			return err
		}
		trailer := "\r\n--" + params["boundary"] + "--\r\n"
		padding := 20<<10 - (int(req.ContentLength) - len(data) - len(trailer))

		resp, err := sendPostObject(cfg(padding))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("at the limit: %w", err)
		}

		resp, err = sendPostObject(cfg(padding + 1))
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetMaxPostPreDataLengthExceededErr(20<<10)); err != nil {
			return fmt.Errorf("over the limit: %w", err)
		}

		return nil
	})
}

// PostObject_object_lock_success covers the Object Lock fields of a POST
// upload: a retention and a legal hold set on the object, the date kept to
// the millisecond.
func PostObject_object_lock_success(s *S3Conf) error {
	testName := "PostObject_object_lock_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		retainUntil := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		fields := map[string]string{
			"x-amz-object-lock-mode":              "GOVERNANCE",
			"x-amz-object-lock-retain-until-date": retainUntil.Format("2006-01-02T15:04:05") + ".123999Z",
			"x-amz-object-lock-legal-hold":        "ON",
		}

		var policyConditions []any
		for field, value := range fields {
			policyConditions = append(policyConditions, map[string]string{field: value})
		}

		resp, err := sendPostObject(PostRequestConfig{
			bucket:           bucket,
			key:              key,
			s3Conf:           s,
			fileContent:      []byte("data"),
			policyConditions: policyConditions,
			extraFields:      fields,
		})
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		ret, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}
		if ret.Retention.Mode != types.ObjectLockRetentionModeGovernance {
			return fmt.Errorf("expected retention mode %v, instead got %v",
				types.ObjectLockRetentionModeGovernance, ret.Retention.Mode)
		}
		wantUntil := retainUntil.Add(123 * time.Millisecond)
		if ret.Retention.RetainUntilDate == nil || !ret.Retention.RetainUntilDate.Equal(wantUntil) {
			return fmt.Errorf("expected retain until date %v, instead got %v", wantUntil, ret.Retention.RetainUntilDate)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		legalHold, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}
		if legalHold.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected legal hold %v, instead got %v",
				types.ObjectLockLegalHoldStatusOn, legalHold.LegalHold.Status)
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: key, removeLegalHold: true}})
	}, withLock())
}

// PostObject_object_lock_invalid_fields covers invalid Object Lock fields of
// a POST upload, checked after the POST policy and the tagging, in the order
// S3 checks them: the mode and the date set together, then the legal hold,
// the date and the mode values. A field sent empty is invalid.
func PostObject_object_lock_invalid_fields(s *S3Conf) error {
	testName := "PostObject_object_lock_invalid_fields"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		past := "2020-01-01T00:00:00Z"

		for _, test := range []struct {
			name      string
			fields    map[string]string
			uncovered string
			expected  s3err.S3Error
		}{
			{
				name:     "mode without a date",
				fields:   map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-legal-hold": "INVALID"},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgMissingObjectLockRetainDate, ""),
			},
			{
				name:     "date without a mode",
				fields:   map[string]string{"x-amz-object-lock-retain-until-date": date},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgMissingObjectLockMode, ""),
			},
			{
				name:     "invalid legal hold before a past date",
				fields:   map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": past, "x-amz-object-lock-legal-hold": "on"},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgLegalHoldStatus, "on"),
			},
			{
				name:     "empty legal hold",
				fields:   map[string]string{"x-amz-object-lock-legal-hold": ""},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgLegalHoldStatus, ""),
			},
			{
				name:     "invalid date before an invalid mode",
				fields:   map[string]string{"x-amz-object-lock-mode": "INVALID", "x-amz-object-lock-retain-until-date": "2026-10-04"},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgRetainUntilDate, "2026-10-04"),
			},
			{
				name:     "past date before an invalid mode",
				fields:   map[string]string{"x-amz-object-lock-mode": "INVALID", "x-amz-object-lock-retain-until-date": past},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgPastObjectLockRetainDate, past),
			},
			{
				name:     "lowercase mode",
				fields:   map[string]string{"x-amz-object-lock-mode": "governance", "x-amz-object-lock-retain-until-date": date},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockMode, "governance"),
			},
			{
				name:     "empty mode",
				fields:   map[string]string{"x-amz-object-lock-mode": "", "x-amz-object-lock-retain-until-date": date},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockMode, ""),
			},
			{
				name:     "malformed tagging before an invalid mode",
				fields:   map[string]string{"x-amz-object-lock-mode": "INVALID", "x-amz-object-lock-retain-until-date": date, "tagging": "<Tagging>"},
				expected: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
			{
				name:      "field not in the POST policy",
				fields:    map[string]string{"x-amz-object-lock-legal-hold": "INVALID"},
				uncovered: "x-amz-object-lock-legal-hold",
				expected:  s3err.InvalidPolicyDocument.ExtraInputField("x-amz-object-lock-legal-hold"),
			},
		} {
			var policyConditions []any
			for field, value := range test.fields {
				if field != test.uncovered {
					policyConditions = append(policyConditions, map[string]string{field: value})
				}
			}

			resp, err := sendPostObject(PostRequestConfig{
				bucket:           bucket,
				key:              "my-obj",
				s3Conf:           s,
				fileContent:      []byte("data"),
				policyConditions: policyConditions,
				extraFields:      test.fields,
			})
			if err != nil {
				return err
			}
			if err := checkHTTPResponseApiErr(resp, test.expected); err != nil {
				return fmt.Errorf("%s: %w", test.name, err)
			}
		}

		return nil
	}, withLock())
}

// PostObject_object_lock_missing_bucket_config covers Object Lock fields of
// a POST upload to a bucket without Object Lock: a legal hold of either
// status or a retention is rejected, once the fields are found valid.
func PostObject_object_lock_missing_bucket_config(s *S3Conf) error {
	testName := "PostObject_object_lock_missing_bucket_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

		for _, test := range []struct {
			name     string
			fields   map[string]string
			expected s3err.S3Error
		}{
			{
				name:     "legal hold off",
				fields:   map[string]string{"x-amz-object-lock-legal-hold": "OFF"},
				expected: s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces),
			},
			{
				name:     "retention",
				fields:   map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": date},
				expected: s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces),
			},
			{
				name:     "invalid mode",
				fields:   map[string]string{"x-amz-object-lock-mode": "INVALID", "x-amz-object-lock-retain-until-date": date},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgObjectLockMode, "INVALID"),
			},
		} {
			var policyConditions []any
			for field, value := range test.fields {
				policyConditions = append(policyConditions, map[string]string{field: value})
			}

			resp, err := sendPostObject(PostRequestConfig{
				bucket:           bucket,
				key:              "my-obj",
				s3Conf:           s,
				fileContent:      []byte("data"),
				policyConditions: policyConditions,
				extraFields:      test.fields,
			})
			if err != nil {
				return err
			}
			if err := checkHTTPResponseApiErr(resp, test.expected); err != nil {
				return fmt.Errorf("%s: %w", test.name, err)
			}
		}

		return nil
	})
}

// PostObject_object_lock_default_retention covers POST uploads to a bucket
// with a default retention rule: a plain upload gets the rule's retention,
// one setting a retention keeps its own, and one setting a legal hold, of
// either status, gets none.
func PostObject_object_lock_default_retention(s *S3Conf) error {
	testName := "PostObject_object_lock_default_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: getPtr(int32(1)),
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		retainUntil := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		// the margin absorbs clock skew between this process and the gateway
		earliest := time.Now().Add(24*time.Hour - time.Minute)

		for _, test := range []struct {
			key    string
			fields map[string]string
		}{
			{key: "plain"},
			{key: "retention", fields: map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": retainUntil.Format(time.RFC3339)}},
			{key: "legal-hold-off", fields: map[string]string{"x-amz-object-lock-legal-hold": "OFF"}},
		} {
			cfg := PostRequestConfig{
				bucket:      bucket,
				key:         test.key,
				s3Conf:      s,
				fileContent: []byte("data"),
				extraFields: test.fields,
			}
			for field, value := range test.fields {
				cfg.policyConditions = append(cfg.policyConditions, map[string]string{field: value})
			}
			resp, err := sendPostObject(cfg)
			if err != nil {
				return err
			}
			if err := checkPostObjectSuccess(resp); err != nil {
				return fmt.Errorf("%s: %w", test.key, err)
			}
		}
		latest := time.Now().Add(24*time.Hour + time.Minute)

		getRetention := func(key string) (*types.ObjectLockRetention, error) {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return nil, err
			}
			return out.Retention, nil
		}

		ret, err := getRetention("plain")
		if err != nil {
			return err
		}
		if ret.Mode != types.ObjectLockRetentionModeGovernance || ret.RetainUntilDate == nil ||
			ret.RetainUntilDate.Before(earliest) || ret.RetainUntilDate.After(latest) {
			return fmt.Errorf("plain: expected the default retention, instead got %v until %v", ret.Mode, ret.RetainUntilDate)
		}

		ret, err = getRetention("retention")
		if err != nil {
			return err
		}
		if ret.RetainUntilDate == nil || !ret.RetainUntilDate.Equal(retainUntil) {
			return fmt.Errorf("retention: expected retain until date %v, instead got %v", retainUntil, ret.RetainUntilDate)
		}

		_, err = getRetention("legal-hold-off")
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration))
	}, withLock())
}
