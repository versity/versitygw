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

package policy

import (
	"reflect"
	"testing"
)

// evalCondTest is the shared table shape for every TestEvaluateCondition*
// function below. wantErr means "evaluateCondition's ok return should be
// false" (the block's shape or an operator name couldn't be recognized) -
// distinct from want=false, which means the condition was evaluated fine
// but didn't match.
type evalCondTest struct {
	name    string
	raw     string
	ctxVars map[string][]string
	// version is the enclosing document's Version element: a Condition
	// value's ${...} policy variable is only ever substituted
	// when this is exactly Version2012. Left "" (no Version) for every
	// existing case except the ones specifically testing substitution.
	version string
	want    bool
	wantErr bool
}

func runEvalCondTests(t *testing.T, tests []evalCondTest) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, ok := evaluateCondition([]byte(tt.raw), tt.ctxVars, tt.version)
			wantOk := !tt.wantErr
			if ok != wantOk {
				t.Fatalf("evaluateCondition() ok = %v, want %v", ok, wantOk)
			}
			if ok && matched != tt.want {
				t.Errorf("evaluateCondition() matched = %v, want %v", matched, tt.want)
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{name: "empty condition always matches", raw: ``, want: true},
		{
			name:    "StringEquals matches",
			raw:     `{"StringEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"client1"}},
			want:    true,
		},
		{
			name:    "StringEquals mismatch",
			raw:     `{"StringEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"other"}},
			want:    false,
		},
		{
			name:    "StringEquals missing key fails closed",
			raw:     `{"StringEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{},
			want:    false,
		},
		{
			name:    "StringEquals against multivalued context matches any",
			raw:     `{"StringEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"other", "client1"}},
			want:    true,
		},
		{
			name:    "StringEquals against multivalued condition matches any",
			raw:     `{"StringEquals":{"example.com:aud":["client1","client2"]}}`,
			ctxVars: map[string][]string{"example.com:aud": {"client2"}},
			want:    true,
		},
		{
			name:    "StringNotEquals matches when different",
			raw:     `{"StringNotEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"other"}},
			want:    true,
		},
		{
			name:    "StringNotEquals fails when equal",
			raw:     `{"StringNotEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"client1"}},
			want:    false,
		},
		{
			name:    "StringNotEquals matches when key absent",
			raw:     `{"StringNotEquals":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "StringNotEqualsIfExists is accepted and behaves like StringNotEquals",
			raw:     `{"StringNotEqualsIfExists":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"client1"}},
			want:    false,
		},
		{
			name:    "StringLike wildcard matches",
			raw:     `{"StringLike":{"example.com:sub":"user-*"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"user-123"}},
			want:    true,
		},
		{
			name:    "StringLike wildcard mismatch",
			raw:     `{"StringLike":{"example.com:sub":"admin-*"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"user-123"}},
			want:    false,
		},
		{
			name:    "StringLikeIfExists enforces match when key present",
			raw:     `{"StringLikeIfExists":{"example.com:sub":"admin-*"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"user-123"}},
			want:    false,
		},
		{
			name:    "StringLikeIfExists passes when key absent",
			raw:     `{"StringLikeIfExists":{"example.com:sub":"admin-*"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "StringNotLike matches when pattern doesn't match",
			raw:     `{"StringNotLike":{"example.com:sub":"admin-*"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"user-123"}},
			want:    true,
		},
		{
			name:    "StringEqualsIgnoreCase matches regardless of case",
			raw:     `{"StringEqualsIgnoreCase":{"example.com:sub":"Alice"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"alice"}},
			want:    true,
		},
		{
			name:    "StringEqualsIgnoreCase mismatch",
			raw:     `{"StringEqualsIgnoreCase":{"example.com:sub":"alice"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"bob"}},
			want:    false,
		},
		{
			name:    "StringNotEqualsIgnoreCase matches when different regardless of case",
			raw:     `{"StringNotEqualsIgnoreCase":{"example.com:sub":"Alice"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"bob"}},
			want:    true,
		},
		{
			name:    "StringNotEqualsIgnoreCase fails when equal regardless of case",
			raw:     `{"StringNotEqualsIgnoreCase":{"example.com:sub":"Alice"}}`,
			ctxVars: map[string][]string{"example.com:sub": {"alice"}},
			want:    false,
		},
		{
			name:    "StringEqualsIfExists passes when key absent",
			raw:     `{"StringEqualsIfExists":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "StringEqualsIfExists enforces match when key present",
			raw:     `{"StringEqualsIfExists":{"example.com:aud":"client1"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"other"}},
			want:    false,
		},
		{
			name:    "multiple operators must all pass",
			raw:     `{"StringEquals":{"example.com:aud":"client1"},"StringLike":{"example.com:sub":"user-*"}}`,
			ctxVars: map[string][]string{"example.com:aud": {"client1"}, "example.com:sub": {"user-1"}},
			want:    true,
		},
		{
			name:    "unrecognized operator fails closed",
			raw:     `{"FooBarOperator":{"example.com:level":"1"}}`,
			ctxVars: map[string][]string{"example.com:level": {"1"}},
			wantErr: true,
		},
		{
			name:    "malformed condition JSON fails closed",
			raw:     `not json`,
			wantErr: true,
		},
		{
			name:    "malformed condition block shape (operator value not an object) fails closed",
			raw:     `{"StringEquals":"not an object"}`,
			wantErr: true,
		},
		{
			name:    "malformed condition block shape (operator value is an array) fails closed",
			raw:     `{"StringEquals":["not","a","map"]}`,
			wantErr: true,
		},
		{
			// Condition key *names* are case-insensitive in AWS, even
			// though the values they hold remain case-sensitive.
			name:    "condition key name matches case-insensitively",
			raw:     `{"StringEquals":{"AWS:UserName":"alice"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}},
			want:    true,
		},
		{
			name:    "condition key name case-insensitive match still compares values case-sensitively",
			raw:     `{"StringEquals":{"AWS:UserName":"Alice"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}},
			want:    false,
		},
		{
			// A policy variable in a Condition value is substituted from
			// the request context before comparing, the same as a
			// Resource pattern.
			name:    "policy variable in condition value is substituted under version 2012-10-17",
			raw:     `{"StringEquals":{"iam:ResourceTag/owner":"${aws:username}"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}, "iam:ResourceTag/owner": {"alice"}},
			version: Version2012,
			want:    true,
		},
		{
			name:    "policy variable naming an absent key is left literal and so fails to match",
			raw:     `{"StringEquals":{"iam:ResourceTag/owner":"${aws:nonexistent}"}}`,
			ctxVars: map[string][]string{"iam:ResourceTag/owner": {"alice"}},
			version: Version2012,
			want:    false,
		},
		{
			// Without an explicit 2012-10-17 Version, AWS does not expand
			// policy variables at all - the "${aws:username}" text is
			// compared literally and so never matches a real tag value.
			name:    "policy variable is not substituted without version 2012-10-17",
			raw:     `{"StringEquals":{"iam:ResourceTag/owner":"${aws:username}"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}, "iam:ResourceTag/owner": {"alice"}},
			want:    false,
		},
		{
			// AWS never expands policy variables inside Numeric/Date/
			// Bool/Binary/IP/Null operators, even under version 2012-10-17 -
			// a NumericEquals comparing aws:EpochTime against a literal
			// "${aws:EpochTime}" never self-matches.
			name:    "policy variable is not substituted inside NumericEquals even under version 2012-10-17",
			raw:     `{"NumericEquals":{"aws:EpochTime":"${aws:EpochTime}"}}`,
			ctxVars: map[string][]string{"aws:EpochTime": {"1700000000"}},
			version: Version2012,
			want:    false,
		},
	})
}

func TestEvaluateConditionNumeric(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "NumericEquals matches",
			raw:     `{"NumericEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    true,
		},
		{
			name:    "NumericEquals mismatch",
			raw:     `{"NumericEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"6"}},
			want:    false,
		},
		{
			name:    "NumericEquals accepts a bare JSON number condition value",
			raw:     `{"NumericEquals":{"s3:max-keys":5}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    true,
		},
		{
			name:    "NumericEquals unparseable actual operand fails closed, not an error",
			raw:     `{"NumericEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"not-a-number"}},
			want:    false,
		},
		{
			name:    "NumericNotEquals matches when different",
			raw:     `{"NumericNotEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"6"}},
			want:    true,
		},
		{
			name:    "NumericNotEquals fails when equal",
			raw:     `{"NumericNotEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    false,
		},
		{
			name:    "NumericNotEquals matches when key absent",
			raw:     `{"NumericNotEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "NumericLessThan matches",
			raw:     `{"NumericLessThan":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"3"}},
			want:    true,
		},
		{
			name:    "NumericLessThan boundary does not match",
			raw:     `{"NumericLessThan":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    false,
		},
		{
			name:    "NumericLessThanEquals boundary matches",
			raw:     `{"NumericLessThanEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    true,
		},
		{
			name:    "NumericGreaterThan matches",
			raw:     `{"NumericGreaterThan":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"7"}},
			want:    true,
		},
		{
			name:    "NumericGreaterThan boundary does not match",
			raw:     `{"NumericGreaterThan":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    false,
		},
		{
			name:    "NumericGreaterThanEquals boundary matches",
			raw:     `{"NumericGreaterThanEquals":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{"s3:max-keys": {"5"}},
			want:    true,
		},
		{
			name:    "NumericGreaterThanEqualsIfExists passes when key absent",
			raw:     `{"NumericGreaterThanEqualsIfExists":{"s3:max-keys":"5"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
	})
}

func TestEvaluateConditionDate(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "DateEquals matches same instant in RFC3339",
			raw:     `{"DateEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-01-01T00:00:00Z"}},
			want:    true,
		},
		{
			name:    "DateEquals matches across RFC3339 vs epoch-seconds formats",
			raw:     `{"DateEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"1704067200"}},
			want:    true,
		},
		{
			name:    "DateEquals mismatch",
			raw:     `{"DateEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-06-01T00:00:00Z"}},
			want:    false,
		},
		{
			name:    "DateNotEquals matches when different",
			raw:     `{"DateNotEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-06-01T00:00:00Z"}},
			want:    true,
		},
		{
			name:    "DateNotEquals matches when key absent",
			raw:     `{"DateNotEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "DateLessThan matches",
			raw:     `{"DateLessThan":{"aws:CurrentTime":"2024-06-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-01-01T00:00:00Z"}},
			want:    true,
		},
		{
			name:    "DateGreaterThan matches",
			raw:     `{"DateGreaterThan":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-06-01T00:00:00Z"}},
			want:    true,
		},
		{
			name:    "DateGreaterThanEquals boundary matches",
			raw:     `{"DateGreaterThanEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-01-01T00:00:00Z"}},
			want:    true,
		},
		{
			name:    "DateLessThanEquals boundary matches",
			raw:     `{"DateLessThanEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"2024-01-01T00:00:00Z"}},
			want:    true,
		},
		{
			name:    "Date operator unparseable operand fails closed, not an error",
			raw:     `{"DateEquals":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}`,
			ctxVars: map[string][]string{"aws:CurrentTime": {"not-a-date"}},
			want:    false,
		},
	})
}

func TestEvaluateConditionBool(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "Bool matches",
			raw:     `{"Bool":{"example.com:admin":"true"}}`,
			ctxVars: map[string][]string{"example.com:admin": {"true"}},
			want:    true,
		},
		{
			name:    "Bool mismatch",
			raw:     `{"Bool":{"example.com:admin":"true"}}`,
			ctxVars: map[string][]string{"example.com:admin": {"false"}},
			want:    false,
		},
		{
			name:    "Bool absent key fails closed",
			raw:     `{"Bool":{"example.com:admin":"true"}}`,
			ctxVars: map[string][]string{},
			want:    false,
		},
		{
			name:    "BoolIfExists passes when key absent",
			raw:     `{"BoolIfExists":{"example.com:admin":"true"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "Bool garbage value fails closed, not an error",
			raw:     `{"Bool":{"example.com:admin":"true"}}`,
			ctxVars: map[string][]string{"example.com:admin": {"yes"}},
			want:    false,
		},
		{
			name:    "Bool accepts a bare JSON boolean condition value",
			raw:     `{"Bool":{"example.com:admin":true}}`,
			ctxVars: map[string][]string{"example.com:admin": {"true"}},
			want:    true,
		},
	})
}

func TestEvaluateConditionBinary(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "BinaryEquals matches",
			raw:     `{"BinaryEquals":{"example.com:token":"aGVsbG8="}}`,
			ctxVars: map[string][]string{"example.com:token": {"aGVsbG8="}},
			want:    true,
		},
		{
			name:    "BinaryEquals mismatch",
			raw:     `{"BinaryEquals":{"example.com:token":"aGVsbG8="}}`,
			ctxVars: map[string][]string{"example.com:token": {"d29ybGQ="}},
			want:    false,
		},
		{
			name:    "BinaryEquals invalid base64 fails closed, not an error",
			raw:     `{"BinaryEquals":{"example.com:token":"aGVsbG8="}}`,
			ctxVars: map[string][]string{"example.com:token": {"not-valid-base64!!"}},
			want:    false,
		},
	})
}

func TestEvaluateConditionArn(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "ArnLike wildcard matches",
			raw:     `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`,
			ctxVars: map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::123456789012:role/foo"}},
			want:    true,
		},
		{
			name:    "ArnLike cross-account mismatch",
			raw:     `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`,
			ctxVars: map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::999999999999:role/foo"}},
			want:    false,
		},
		{
			name:    "ArnEquals behaves identically to ArnLike (wildcard-aware)",
			raw:     `{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`,
			ctxVars: map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::123456789012:role/foo"}},
			want:    true,
		},
		{
			name:    "ArnNotLike matches a non-matching ARN",
			raw:     `{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`,
			ctxVars: map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::999999999999:role/foo"}},
			want:    true,
		},
		{
			name:    "ArnNotEquals fails when the ARN matches",
			raw:     `{"ArnNotEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`,
			ctxVars: map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::123456789012:role/foo"}},
			want:    false,
		},
		{
			name:    "ArnNotEquals matches when key absent",
			raw:     `{"ArnNotEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
	})
}

func TestEvaluateConditionIP(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "IpAddress CIDR matches",
			raw:     `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
			ctxVars: map[string][]string{"aws:SourceIp": {"10.1.2.3"}},
			want:    true,
		},
		{
			name:    "IpAddress CIDR mismatch",
			raw:     `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
			ctxVars: map[string][]string{"aws:SourceIp": {"203.0.113.5"}},
			want:    false,
		},
		{
			name:    "IpAddress exact address treated as /32",
			raw:     `{"IpAddress":{"aws:SourceIp":"203.0.113.5"}}`,
			ctxVars: map[string][]string{"aws:SourceIp": {"203.0.113.5"}},
			want:    true,
		},
		{
			name:    "NotIpAddress matches an address outside the range",
			raw:     `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
			ctxVars: map[string][]string{"aws:SourceIp": {"203.0.113.5"}},
			want:    true,
		},
		{
			name:    "NotIpAddress fails for an address inside the range",
			raw:     `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
			ctxVars: map[string][]string{"aws:SourceIp": {"10.1.2.3"}},
			want:    false,
		},
		{
			name:    "NotIpAddress matches when key absent",
			raw:     `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
	})
}

func TestEvaluateConditionNull(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    `Null "true" matches when key absent`,
			raw:     `{"Null":{"aws:username":"true"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    `Null "true" fails when key present`,
			raw:     `{"Null":{"aws:username":"true"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}},
			want:    false,
		},
		{
			name:    `Null "false" fails when key absent`,
			raw:     `{"Null":{"aws:username":"false"}}`,
			ctxVars: map[string][]string{},
			want:    false,
		},
		{
			name:    `Null "false" matches when key present`,
			raw:     `{"Null":{"aws:username":"false"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}},
			want:    true,
		},
		{
			name:    "Null garbage value never satisfies",
			raw:     `{"Null":{"aws:username":"maybe"}}`,
			ctxVars: map[string][]string{"aws:username": {"alice"}},
			want:    false,
		},
		{
			name:    "ForAllValues:Null is accepted and behaves like plain Null",
			raw:     `{"ForAllValues:Null":{"aws:username":"true"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "NullIfExists is rejected - Null has no IfExists variant",
			raw:     `{"NullIfExists":{"aws:username":"true"}}`,
			ctxVars: map[string][]string{},
			wantErr: true,
		},
	})
}
func TestEvaluateConditionQualifiers(t *testing.T) {
	runEvalCondTests(t, []evalCondTest{
		{
			name:    "unqualified StringNotEquals denies when any actual value matches (pre-existing behavior, unchanged)",
			raw:     `{"StringNotEquals":{"example.com:groups":"banned"}}`,
			ctxVars: map[string][]string{"example.com:groups": {"admin", "banned"}},
			want:    false,
		},
		{
			name:    "ForAllValues:StringNotEquals denies when any actual value matches",
			raw:     `{"ForAllValues:StringNotEquals":{"example.com:groups":"banned"}}`,
			ctxVars: map[string][]string{"example.com:groups": {"admin", "banned"}},
			want:    false,
		},
		{
			name:    "ForAnyValue:StringNotEquals allows when at least one actual value doesn't match",
			raw:     `{"ForAnyValue:StringNotEquals":{"example.com:groups":"banned"}}`,
			ctxVars: map[string][]string{"example.com:groups": {"admin", "banned"}},
			want:    true,
		},
		{
			name:    "ForAllValues:StringEquals matches when every actual value is in the set",
			raw:     `{"ForAllValues:StringEquals":{"example.com:groups":["admin","banned"]}}`,
			ctxVars: map[string][]string{"example.com:groups": {"admin", "banned"}},
			want:    true,
		},
		{
			name:    "ForAllValues:StringEquals fails when one actual value is outside the set",
			raw:     `{"ForAllValues:StringEquals":{"example.com:groups":["admin","banned"]}}`,
			ctxVars: map[string][]string{"example.com:groups": {"admin", "manager"}},
			want:    false,
		},
		{
			name:    "ForAllValues:StringEquals vacuously matches when the key is entirely absent",
			raw:     `{"ForAllValues:StringEquals":{"example.com:groups":"banned"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "ForAllValues:StringNotEquals vacuously matches when the key is entirely absent",
			raw:     `{"ForAllValues:StringNotEquals":{"example.com:groups":"banned"}}`,
			ctxVars: map[string][]string{},
			want:    true,
		},
		{
			name:    "ForAnyValue:StringEquals matches when at least one actual value is in the set",
			raw:     `{"ForAnyValue:StringEquals":{"example.com:groups":"banned"}}`,
			ctxVars: map[string][]string{"example.com:groups": {"admin", "banned"}},
			want:    true,
		},
	})
}

func TestConditionValuesUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    ConditionValues
		wantErr bool
	}{
		{"string", `"alice"`, ConditionValues{"alice"}, false},
		{"integer number, unquoted", `5`, ConditionValues{"5"}, false},
		{"decimal number preserves literal text", `5.50`, ConditionValues{"5.50"}, false},
		{"bool true", `true`, ConditionValues{"true"}, false},
		{"bool false", `false`, ConditionValues{"false"}, false},
		{"array of strings", `["a","b"]`, ConditionValues{"a", "b"}, false},
		{"array mixing string/number/bool", `["a",5,true]`, ConditionValues{"a", "5", "true"}, false},
		{"null is rejected", `null`, nil, true},
		{"null array element is rejected", `["a",null]`, nil, true},
		{"nested array element is rejected", `[["a"]]`, nil, true},
		{"object element is rejected", `{"a":"b"}`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ConditionValues
			err := got.UnmarshalJSON([]byte(tt.json))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("UnmarshalJSON() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("UnmarshalJSON() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseOperatorName(t *testing.T) {
	tests := []struct {
		name         string
		op           string
		wantOk       bool
		wantBase     string
		wantIfExists bool
		wantQualif   conditionQualifier
	}{
		{name: "StringEquals", op: "StringEquals", wantOk: true, wantBase: "StringEquals"},
		{name: "StringEqualsIfExists", op: "StringEqualsIfExists", wantOk: true, wantBase: "StringEquals", wantIfExists: true},
		{name: "NumericGreaterThanEquals", op: "NumericGreaterThanEquals", wantOk: true, wantBase: "NumericGreaterThanEquals"},
		{name: "DateLessThanIfExists", op: "DateLessThanIfExists", wantOk: true, wantBase: "DateLessThan", wantIfExists: true},
		{name: "Bool", op: "Bool", wantOk: true, wantBase: "Bool"},
		{name: "BoolIfExists", op: "BoolIfExists", wantOk: true, wantBase: "Bool", wantIfExists: true},
		{name: "BinaryEquals", op: "BinaryEquals", wantOk: true, wantBase: "BinaryEquals"},
		{name: "ArnLike", op: "ArnLike", wantOk: true, wantBase: "ArnLike"},
		{name: "IpAddress", op: "IpAddress", wantOk: true, wantBase: "IpAddress"},
		{name: "Null", op: "Null", wantOk: true, wantBase: "Null"},
		{name: "ForAllValues:StringEquals", op: "ForAllValues:StringEquals", wantOk: true, wantBase: "StringEquals", wantQualif: qualifierForAllValues},
		{name: "ForAnyValue:StringNotEqualsIfExists", op: "ForAnyValue:StringNotEqualsIfExists", wantOk: true, wantBase: "StringNotEquals", wantIfExists: true, wantQualif: qualifierForAnyValue},
		{name: "ForAllValues:Null accepted, qualifier is a no-op", op: "ForAllValues:Null", wantOk: true, wantBase: "Null", wantQualif: qualifierForAllValues},
		{name: "NullIfExists rejected", op: "NullIfExists", wantOk: false},
		{name: "unrecognized base", op: "FooBarOperator", wantOk: false},
		{name: "unrecognized qualifier prefix left as part of the name", op: "ForSomeValues:StringEquals", wantOk: false},
		{name: "empty string", op: "", wantOk: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseOperatorName(tt.op)
			if ok != tt.wantOk {
				t.Fatalf("parseOperatorName(%q) ok = %v, want %v", tt.op, ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if got.base != tt.wantBase || got.ifExists != tt.wantIfExists || got.qualifier != tt.wantQualif {
				t.Fatalf("parseOperatorName(%q) = %+v, want {base:%q ifExists:%v qualifier:%v}", tt.op, got, tt.wantBase, tt.wantIfExists, tt.wantQualif)
			}
		})
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{pattern: "user-*", s: "user-123", want: true},
		{pattern: "user-*", s: "admin-123", want: false},
		{pattern: "user-?23", s: "user-123", want: true},
		{pattern: "user-?23", s: "user-1123", want: false},
		{pattern: "*", s: "anything", want: true},
		{pattern: "exact", s: "exact", want: true},
		{pattern: "exact", s: "exacts", want: false},
	}
	for _, tt := range tests {
		if got := globMatch(tt.pattern, tt.s); got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}
