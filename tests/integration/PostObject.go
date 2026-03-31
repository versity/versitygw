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
	"net/http"
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

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrPreconditionFailed))
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

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrOnlyAws4HmacSha256))
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

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrInvalidDateHeader))
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

		return checkHTTPResponseApiErr(resp, s3err.PostAuth.MalformedCredential())
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

		return checkHTTPResponseApiErr(resp, s3err.PostAuth.IncorrectRegion(s.awsRegion, wrongRegion))
	})
}

func PostObject_non_existing_access_key(s *S3Conf) error {
	testName := "PostObject_non_existing_access_key"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			access:      "this_access_key_id_can_not_really_exist",
			secret:      "a_very_secure_secret_access_key",
			fileContent: []byte("data"),
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID))
	})
}

func PostObject_signature_mismatch(s *S3Conf) error {
	testName := "PostObject_signature_mismatch"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "test-object",
			s3Conf:      s,
			fileContent: []byte("data"),
			extraFields: map[string]string{
				"x-amz-signature": "incorrect_signature",
			},
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
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
			err        s3err.APIError
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

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrEntityTooLarge))
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

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrEntityTooSmall))
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
		signingDate := time.Now().UTC()
		fields := buildSignedPostFields(bucket, key, s.awsID, s.awsRegion, signingDate)
		policy, err := encodePostPolicy([]any{}, time.Now().UTC().Add(time.Minute*10), fields, make(map[string]struct{}))
		if err != nil {
			return err
		}

		fields["policy"] = policy
		fields["x-amz-signature"] = signPostPolicy(policy, signingDate.Format("20060102"), s.awsRegion, s.awsSecret)

		objData := []byte("dummy data")
		body, boundary, err := buildPostObjectBody(fields, map[string]string{}, objData)
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
				[]any{"eq", "$x-amz-meta-foo", "bar"},
				[]any{"eq", "$x-amz-meta-baz", "quxx"},
			},
			extraFields: map[string]string{
				"Content-Type":        cType,
				"Cache-Control":       cacheControl,
				"Expires":             expires,
				"Content-Language":    cLanguage,
				"Content-Disposition": cDisposition,
				"Content-Encoding":    cEncoding,
				"x-amz-meta-foo":      "bar",
				"x-amz-meta-baz":      "quxx",
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
