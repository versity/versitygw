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

package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3err"
)

func encodePolicyForTest(t *testing.T, expiration time.Time, conditions []any, rawBase64 bool) string {
	t.Helper()

	policy := map[string]any{
		"expiration": expiration.UTC().Format(time.RFC3339),
		"conditions": conditions,
	}

	b, err := json.Marshal(policy)
	assert.NoError(t, err)

	if rawBase64 {
		return base64.RawStdEncoding.EncodeToString(b)
	}

	return base64.StdEncoding.EncodeToString(b)
}

func encodeRawPolicyJSONForTest(t *testing.T, rawJSON string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(rawJSON))
}

func mustParsePolicyForTest(t *testing.T, encoded string) *POSTPolicy {
	t.Helper()
	p, err := ParsePOSTPolicyBase64(encoded)
	assert.NoError(t, err)
	return p
}

func TestParsePOSTPolicyBase64_Success_AndEvaluate(t *testing.T) {
	encoded := encodePolicyForTest(t, time.Now().Add(15*time.Minute), []any{
		map[string]string{"bucket": "photos"},
		[]any{"starts-with", "$key", "uploads/"},
		[]any{"eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"},
		[]any{"content-length-range", 1, 10},
	}, false)

	p := mustParsePolicyForTest(t, encoded)

	assert.NoError(t, p.Evaluate(PostPolicyEvalInput{
		Bucket:        "photos",
		Key:           "uploads/image.jpg",
		ContentLength: 5,
		Fields: map[string]string{
			"x-amz-algorithm": "AWS4-HMAC-SHA256",
			"file":            "ignored",
			"policy":          encoded,
			"x-amz-signature": "ignored",
			"x-ignore-meta":   "ignored",
		},
	}))
}

func TestParsePOSTPolicyBase64_AcceptsRawBase64(t *testing.T) {
	encoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		map[string]string{"bucket": "photos"},
	}, true)

	_, err := ParsePOSTPolicyBase64(encoded)
	assert.Equal(t, error(nil), err)
}

func TestParsePOSTPolicyBase64_ConcreteParseErrors(t *testing.T) {
	floatRangeEncoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		[]any{"content-length-range", 1.5, 10},
	}, false)

	unknownOpEncoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		[]any{"contains", "$key", "uploads/"},
	}, false)

	badQuotedRangeEncoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		[]any{"content-length-range", "abc", 10},
	}, false)

	tests := []struct {
		name     string
		encoded  string
		expected error
	}{
		{
			name:     "empty policy",
			encoded:  "   ",
			expected: s3err.InvalidPolicyDocument.EmptyPolicy(),
		},
		{
			name:     "invalid base64",
			encoded:  "%%%not-base64%%%",
			expected: s3err.InvalidPolicyDocument.InvalidBase64Encoding(),
		},
		{
			name:     "invalid json",
			encoded:  encodeRawPolicyJSONForTest(t, `{"expiration":`),
			expected: s3err.InvalidPolicyDocument.InvalidJSON(),
		},
		{
			name: "missing expiration",
			encoded: encodeRawPolicyJSONForTest(t, `{
				"conditions":[{"bucket":"photos"}]
			}`),
			expected: s3err.InvalidPolicyDocument.MissingExpiration(),
		},
		{
			name: "missing conditions",
			encoded: encodeRawPolicyJSONForTest(t, `{
				"expiration":"2100-01-01T00:00:00Z"
			}`),
			expected: s3err.InvalidPolicyDocument.MissingConditions(),
		},
		{
			name: "invalid expiration format",
			encoded: encodeRawPolicyJSONForTest(t, `{
				"expiration":"not-a-time",
				"conditions":[{"bucket":"photos"}]
			}`),
			expected: s3err.InvalidPolicyDocument.InvalidExpiration("not-a-time"),
		},
		{
			name: "expired policy",
			encoded: encodePolicyForTest(t, time.Now().Add(-5*time.Minute), []any{
				map[string]string{"bucket": "photos"},
			}, false),
			expected: s3err.InvalidPolicyDocument.PolicyExpired(),
		},
		{
			name:     "unknown operation",
			encoded:  unknownOpEncoded,
			expected: s3err.InvalidPolicyDocument.UnknownConditionOperation("contains"),
		},
		{
			name: "array condition missing op identifier",
			encoded: encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
				[]any{},
			}, false),
			expected: s3err.InvalidPolicyDocument.MissingConditionOperationIdentifier(),
		},
		{
			name: "eq wrong number of args",
			encoded: encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
				[]any{"eq", "$key"},
			}, false),
			expected: s3err.InvalidPolicyDocument.IncorrectConditionArgumentsNumber("eq"),
		},
		{
			name: "content-length-range wrong number of args",
			encoded: encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
				[]any{"content-length-range", 1},
			}, false),
			expected: s3err.InvalidPolicyDocument.IncorrectConditionArgumentsNumber("content-length-range"),
		},
		{
			name: "invalid simple condition value type",
			encoded: encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
				map[string]any{"bucket": 1},
			}, false),
			expected: s3err.InvalidPolicyDocument.InvalidSimpleCondition(),
		},
		{
			name: "simple condition with multiple properties",
			encoded: encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
				map[string]string{"bucket": "photos", "acl": "private"},
			}, false),
			expected: s3err.InvalidPolicyDocument.OnePropSimpleCondition(),
		},
		{
			name: "condition not object or list",
			encoded: encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
				123,
			}, false),
			expected: s3err.InvalidPolicyDocument.InvalidCondition(),
		},
		{
			name:     "content-length-range with float",
			encoded:  floatRangeEncoded,
			expected: s3err.InvalidPolicyDocument.InvalidJSON(),
		},
		{
			name:     "content-length-range with invalid quoted int",
			encoded:  badQuotedRangeEncoded,
			expected: s3err.InvalidPolicyDocument.ConditionFailed(`["content-length-range","abc",10]`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePOSTPolicyBase64(tt.encoded)
			assert.Equal(t, tt.expected, err)
		})
	}
}

func TestPOSTPolicyEvaluate_ConcretePolicyRejections(t *testing.T) {
	encoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		map[string]string{"bucket": "photos"},
		[]any{"starts-with", "$key", "uploads/"},
		[]any{"eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"},
		[]any{"content-length-range", 2, 4},
	}, false)

	p := mustParsePolicyForTest(t, encoded)

	tests := []struct {
		name     string
		input    PostPolicyEvalInput
		expected error
	}{
		{
			name: "extra field",
			input: PostPolicyEvalInput{
				Bucket:        "photos",
				Key:           "uploads/image.jpg",
				ContentLength: 3,
				Fields: map[string]string{
					"x-amz-algorithm": "AWS4-HMAC-SHA256",
					"acl":             "private",
				},
			},
			expected: s3err.InvalidPolicyDocument.ExtraInputField("acl"),
		},
		{
			name: "bucket mismatch",
			input: PostPolicyEvalInput{
				Bucket:        "other-bucket",
				Key:           "uploads/image.jpg",
				ContentLength: 3,
				Fields: map[string]string{
					"x-amz-algorithm": "AWS4-HMAC-SHA256",
				},
			},
			expected: s3err.InvalidPolicyDocument.ConditionFailed(`["eq", "$bucket", "photos"]`),
		},
		{
			name: "key prefix mismatch",
			input: PostPolicyEvalInput{
				Bucket:        "photos",
				Key:           "tmp/image.jpg",
				ContentLength: 3,
				Fields: map[string]string{
					"x-amz-algorithm": "AWS4-HMAC-SHA256",
				},
			},
			expected: s3err.InvalidPolicyDocument.ConditionFailed(`["starts-with","$key","uploads/"]`),
		},
		{
			name: "missing required field",
			input: PostPolicyEvalInput{
				Bucket:        "photos",
				Key:           "uploads/image.jpg",
				ContentLength: 3,
				Fields:        map[string]string{},
			},
			expected: s3err.InvalidPolicyDocument.ConditionFailed(`["eq","$x-amz-algorithm","AWS4-HMAC-SHA256"]`),
		},
		{
			name: "content too large",
			input: PostPolicyEvalInput{
				Bucket:        "photos",
				Key:           "uploads/image.jpg",
				ContentLength: 10,
				Fields: map[string]string{
					"x-amz-algorithm": "AWS4-HMAC-SHA256",
				},
			},
			expected: s3err.GetAPIError(s3err.ErrEntityTooLarge),
		},
		{
			name: "content too small",
			input: PostPolicyEvalInput{
				Bucket:        "photos",
				Key:           "uploads/image.jpg",
				ContentLength: 1,
				Fields: map[string]string{
					"x-amz-algorithm": "AWS4-HMAC-SHA256",
				},
			},
			expected: s3err.GetAPIError(s3err.ErrEntityTooSmall),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Evaluate(tt.input)
			assert.Equal(t, tt.expected, err)
		})
	}
}

func TestPOSTPolicyEvaluate_IgnoresAllowedCoverageFields(t *testing.T) {
	encoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		map[string]string{"bucket": "photos"},
		[]any{"starts-with", "$key", "uploads/"},
	}, false)

	p := mustParsePolicyForTest(t, encoded)

	err := p.Evaluate(PostPolicyEvalInput{
		Bucket:        "photos",
		Key:           "uploads/image.jpg",
		ContentLength: 3,
		Fields: map[string]string{
			"file":            "ignored",
			"policy":          "ignored",
			"x-amz-signature": "ignored",
			"x-ignore-meta":   "ignored",
		},
	})
	assert.Equal(t, error(nil), err)
}

func TestPOSTPolicyEvaluate_ContentTypeStartsWithList_AllEntriesMustMatch(t *testing.T) {
	encoded := encodePolicyForTest(t, time.Now().Add(5*time.Minute), []any{
		map[string]string{"bucket": "photos"},
		[]any{"starts-with", "$key", "uploads/"},
		[]any{"starts-with", "$Content-Type", "image/"},
	}, false)

	p := mustParsePolicyForTest(t, encoded)

	err := p.Evaluate(PostPolicyEvalInput{
		Bucket:        "photos",
		Key:           "uploads/image.jpg",
		ContentLength: 3,
		Fields: map[string]string{
			"content-type": "image/png,text/plain",
		},
	})
	assert.Equal(t, s3err.InvalidPolicyDocument.ConditionFailed(`["starts-with","$Content-Type","image/"]`), err)
}
