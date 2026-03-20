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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// POSTPolicy is the parsed browser-based upload policy document.
type POSTPolicy struct {
	expiration time.Time
	conditions []postPolicyCondition
}

// PostPolicyEvalInput is all the data required to evaluate the policy.
// Fields should contain already-expanded form values.
type PostPolicyEvalInput struct {
	Bucket        string
	Key           string
	ContentLength int64
	Fields        map[string]string
}

// postPolicyCondition is the internal contract shared by all supported
// POST policy condition forms.
type postPolicyCondition interface {
	validate() error
	match(PostPolicyEvalInput) error
	coveredField() string
}

// rawPolicy mirrors the JSON structure of an incoming POST policy document.
type rawPolicy struct {
	Expiration string            `json:"expiration"`
	Conditions []json.RawMessage `json:"conditions"`
}

// ParsePOSTPolicyBase64 decodes and validates a base64-encoded POST policy.
func ParsePOSTPolicyBase64(encoded string) (*POSTPolicy, error) {
	raw, err := decodeBase64Policy(encoded)
	if err != nil {
		return nil, err
	}

	var rp rawPolicy
	err = json.Unmarshal(raw, &rp)
	if err != nil {
		debuglogger.Logf("invalid POST policy JSON: %v", err)
		return nil, s3err.InvalidPolicyDocument.InvalidJSON()
	}

	if strings.TrimSpace(rp.Expiration) == "" {
		debuglogger.Logf("POST policy is missing expiration")
		return nil, s3err.InvalidPolicyDocument.MissingExpiration()
	}
	if len(rp.Conditions) == 0 {
		debuglogger.Logf("POST policy is missing conditions")
		return nil, s3err.InvalidPolicyDocument.MissingConditions()
	}

	exp, err := parseExpiration(rp.Expiration)
	if err != nil {
		return nil, err
	}

	conds := make([]postPolicyCondition, 0, len(rp.Conditions))
	for _, rawCond := range rp.Conditions {
		parsed, err := parseCondition(rawCond)
		if err != nil {
			return nil, err
		}
		conds = append(conds, parsed)
	}

	p := &POSTPolicy{
		expiration: exp,
		conditions: conds,
	}

	err = p.validate()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// validate checks the parsed policy for structural correctness.
func (p *POSTPolicy) validate() error {
	now := time.Now().UTC()
	if p.expiration.Before(now) {
		debuglogger.Logf("POST policy expired at %s", p.expiration.Format(time.RFC3339))
		return s3err.InvalidPolicyDocument.PolicyExpired()
	}

	for _, cond := range p.conditions {
		if err := cond.validate(); err != nil {
			return err
		}
	}

	return nil
}

// Evaluate returns nil if the input satisfies the policy.
// Otherwise it returns a deny reason.
func (p *POSTPolicy) Evaluate(in PostPolicyEvalInput) error {
	// Every submitted form field must be present in conditions, except:
	// x-amz-signature, file, policy, and x-ignore-*.
	for field := range in.Fields {
		if isIgnoredCoverageField(field) {
			continue
		}
		if !p.hasConditionForField(field) {
			debuglogger.Logf("POST policy does not cover input field: %s", field)
			return s3err.InvalidPolicyDocument.ExtraInputField(field)
		}
	}

	for _, cond := range p.conditions {
		if err := cond.match(in); err != nil {
			return err
		}
	}

	return nil
}

// exactCondition represents either an object-form condition or an "eq" array
// condition that requires a field to match a single value exactly.
type exactCondition struct {
	field        string
	value        string
	rawCondition []byte
}

// condition returns the policy expression used in condition failure messages.
func (c exactCondition) condition() string {
	if len(c.rawCondition) == 0 {
		// the key/value condition case
		return fmt.Sprintf(`["eq", "$%s", "%s"]`, c.field, c.value)
	}

	return string(c.rawCondition)
}

// validate ensures the exact-match condition references a field.
func (c exactCondition) validate() error {
	if strings.TrimSpace(c.field) == "" {
		debuglogger.Logf("empty field in POST policy 'eq' condition")
		return s3err.InvalidPolicyDocument.ConditionFailed(c.condition())
	}

	return nil
}

// match checks whether the resolved field value matches the expected value.
func (c exactCondition) match(in PostPolicyEvalInput) error {
	got, ok := lookupField(in, c.field)
	if !ok {
		debuglogger.Logf("missing POST policy field %q for condition %s", c.field, c.condition())
		return s3err.InvalidPolicyDocument.ConditionFailed(c.condition())
	}
	if got != c.value {
		debuglogger.Logf("POST policy exact match failed for field %q: got %q want %q", c.field, got, c.value)
		return s3err.InvalidPolicyDocument.ConditionFailed(c.condition())
	}

	return nil
}

// coveredField reports which form field this condition authorizes.
func (c exactCondition) coveredField() string { return c.field }

// startsWithCondition represents a policy rule that constrains a field by
// prefix rather than by exact equality.
type startsWithCondition struct {
	field        string
	prefix       string
	rawCondition []byte
}

// condition returns the original policy expression for failure reporting.
func (c startsWithCondition) condition() string {
	return string(c.rawCondition)
}

// validate ensures the starts-with condition references a field.
func (c startsWithCondition) validate() error {
	if strings.TrimSpace(c.field) == "" {
		debuglogger.Logf("empty field in POST policy 'starts-with' condition")
		return s3err.InvalidPolicyDocument.ConditionFailed(c.condition())
	}

	return nil
}

// match checks whether the resolved field value satisfies the required prefix.
func (c startsWithCondition) match(in PostPolicyEvalInput) error {
	got, ok := lookupField(in, c.field)
	if !ok {
		debuglogger.Logf("missing POST policy field %q for condition %s", c.field, c.condition())
		return s3err.InvalidPolicyDocument.ConditionFailed(c.condition())
	}
	if !startsWithMatch(c.field, got, c.prefix) {
		debuglogger.Logf("POST policy starts-with failed for field %q: got %q prefix %q", c.field, got, c.prefix)
		return s3err.InvalidPolicyDocument.ConditionFailed(c.condition())
	}
	return nil
}

// coveredField reports which form field this condition authorizes.
func (c startsWithCondition) coveredField() string { return c.field }

// contentLengthRangeCondition enforces the allowed size range of the uploaded
// object body.
type contentLengthRangeCondition struct {
	min int64
	max int64
}

// validate accepts any parsed range and leaves size enforcement to match.
func (c contentLengthRangeCondition) validate() error {
	return nil
}

// match rejects uploads whose content length falls outside the allowed range.
func (c contentLengthRangeCondition) match(in PostPolicyEvalInput) error {
	if in.ContentLength > c.max {
		debuglogger.Logf("POST policy content length %d exceeds max %d", in.ContentLength, c.max)
		return s3err.GetAPIError(s3err.ErrEntityTooLarge)
	}
	if in.ContentLength < c.min {
		debuglogger.Logf("POST policy content length %d is smaller than min %d", in.ContentLength, c.min)
		return s3err.GetAPIError(s3err.ErrEntityTooSmall)
	}

	return nil
}

// Content length constraints apply to the uploaded body as a whole rather than
// to a named form field, so they do not participate in field coverage checks.
func (c contentLengthRangeCondition) coveredField() string { return "" }

// hasConditionForField reports whether the policy covers the supplied form
// field name.
func (p *POSTPolicy) hasConditionForField(field string) bool {
	for _, cond := range p.conditions {
		if cond.coveredField() == field {
			return true
		}
	}

	return false
}

// lookupField resolves policy field references against the canonical request
// state and submitted form fields.
func lookupField(in PostPolicyEvalInput, field string) (string, bool) {
	// bucket and key are validated from the resolved request state
	switch field {
	case "bucket":
		return in.Bucket, true
	case "key":
		return in.Key, true
	}

	if in.Fields == nil {
		return "", false
	}

	v, ok := in.Fields[field]
	return v, ok
}

// isIgnoredCoverageField reports whether a submitted field is exempt from the
// POST policy's field coverage requirement.
func isIgnoredCoverageField(field string) bool {
	return field == "file" ||
		field == "policy" ||
		field == "x-amz-signature" ||
		strings.HasPrefix(field, "x-ignore-")
}

// startsWithMatch applies AWS's starts-with matching rules for POST policy
// evaluation.
func startsWithMatch(field, value, prefix string) bool {
	// AWS special-case:
	// For starts-with on Content-Type, a comma-separated value is interpreted
	// as a list and every entry must satisfy the prefix.
	if field == "content-type" && strings.Contains(value, ",") {
		parts := strings.SplitSeq(value, ",")
		for part := range parts {
			if !strings.HasPrefix(strings.TrimSpace(part), prefix) {
				return false
			}
		}
		return true
	}
	return strings.HasPrefix(value, prefix)
}

// decodeBase64Policy accepts both padded and raw standard base64 encodings for
// POST policy documents.
func decodeBase64Policy(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		debuglogger.Logf("empty POST policy")
		return nil, s3err.InvalidPolicyDocument.EmptyPolicy()
	}

	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}

	debuglogger.Logf("invalid POST policy base64 encoding")
	return nil, s3err.InvalidPolicyDocument.InvalidBase64Encoding()
}

// parseExpiration parses the policy expiration timestamp and normalizes it to
// UTC.
func parseExpiration(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	debuglogger.Logf("invalid POST policy expiration: %s", s)
	return time.Time{}, s3err.InvalidPolicyDocument.InvalidExpiration(s)
}

// parseCondition converts one raw JSON condition into its internal validation
// and matching form.
func parseCondition(raw json.RawMessage) (postPolicyCondition, error) {
	// Object form: {"content-type":"application/xml"}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil && obj != nil {
		if len(obj) != 1 {
			debuglogger.Logf("POST policy simple condition must have exactly one property: %s", string(raw))
			return nil, s3err.InvalidPolicyDocument.OnePropSimpleCondition()
		}

		for field, value := range obj {
			s, ok := value.(string)
			if !ok {
				debuglogger.Logf("POST policy simple condition value must be string: %s", string(raw))
				return nil, s3err.InvalidPolicyDocument.InvalidSimpleCondition()
			}

			return exactCondition{
				field: strings.ToLower(field),
				value: s,
			}, nil
		}
	}

	// Array form:
	// ["eq", "$acl", "public-read"]
	// ["starts-with", "$key", "user/eric/"]
	// ["content-length-range", 1, 10485760]
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		debuglogger.Logf("invalid POST policy condition: %s", string(raw))
		return nil, s3err.InvalidPolicyDocument.InvalidCondition()
	}
	if len(arr) == 0 {
		debuglogger.Logf("POST policy condition missing operation identifier")
		return nil, s3err.InvalidPolicyDocument.MissingConditionOperationIdentifier()
	}

	var op string
	if err := json.Unmarshal(arr[0], &op); err != nil {
		debuglogger.Logf("invalid POST policy condition operation: %s", string(raw))
		return nil, s3err.InvalidPolicyDocument.InvalidJSON()
	}

	switch op {
	case "eq", "starts-with":
		if len(arr) != 3 {
			debuglogger.Logf("POST policy %s condition has wrong number of arguments: %s", op, string(raw))
			return nil, s3err.InvalidPolicyDocument.IncorrectConditionArgumentsNumber(op)
		}

		var fieldRef string
		if err := json.Unmarshal(arr[1], &fieldRef); err != nil {
			debuglogger.Logf("invalid POST policy field reference: %s", string(raw))
			return nil, s3err.InvalidPolicyDocument.InvalidJSON()
		}
		value, err := rawScalarToString(arr[2])
		if err != nil {
			debuglogger.Logf("invalid POST policy scalar value: %s", string(raw))
			return nil, s3err.InvalidPolicyDocument.InvalidJSON()
		}

		if !strings.HasPrefix(fieldRef, "$") || len(fieldRef) == 1 {
			debuglogger.Logf("invalid POST policy field reference format: %s", fieldRef)
			return nil, s3err.InvalidPolicyDocument.ConditionFailed(string(raw))
		}

		// Normalize field names so condition checks line up with the parsed form
		// map regardless of how they were written in the policy document.
		field := strings.ToLower(fieldRef[1:])
		if op == "eq" {
			return exactCondition{field: field, value: value, rawCondition: raw}, nil
		}

		return startsWithCondition{field: field, prefix: value, rawCondition: raw}, nil
	case "content-length-range":
		if len(arr) != 3 {
			debuglogger.Logf("POST policy %s condition has wrong number of arguments: %s", op, string(raw))
			return nil, s3err.InvalidPolicyDocument.IncorrectConditionArgumentsNumber(op)
		}

		min, err := parseJSONInt64(arr[1], raw)
		if err != nil {
			return nil, err
		}
		max, err := parseJSONInt64(arr[2], raw)
		if err != nil {
			return nil, err
		}

		return contentLengthRangeCondition{min: min, max: max}, nil
	default:
		debuglogger.Logf("unknown POST policy operation: %s", op)
		return nil, s3err.InvalidPolicyDocument.UnknownConditionOperation(op)
	}
}

// parseJSONInt64 parses an integer condition operand from either a JSON number
// or a quoted decimal string.
func parseJSONInt64(raw json.RawMessage, rawCondition json.RawMessage) (int64, error) {
	// try parsing as JSON number
	var num json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	if err := dec.Decode(&num); err == nil {
		// Ensure it's a valid int64 (reject floats, exponents, overflow)
		if v, err := num.Int64(); err == nil {
			return v, nil
		}
		debuglogger.Logf("invalid POST policy integer value: %s", string(raw))
		return 0, s3err.InvalidPolicyDocument.InvalidJSON()
	}

	// AWS also accepts quoted integers here.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			debuglogger.Logf("invalid POST policy quoted integer: %s", s)
			return 0, s3err.InvalidPolicyDocument.ConditionFailed(string(rawCondition))
		}
		return v, nil
	}

	debuglogger.Logf("invalid POST policy integer JSON: %s", string(raw))
	return 0, s3err.InvalidPolicyDocument.InvalidJSON()
}

// rawScalarToString converts a JSON scalar that is valid in policy conditions
// into its string representation.
func rawScalarToString(raw json.RawMessage) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}

	switch x := v.(type) {
	case string:
		return x, nil
	case json.Number:
		return x.String(), nil
	default:
		return "", errors.New("unsupported type")
	}
}
