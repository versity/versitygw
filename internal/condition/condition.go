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

// Package condition implements AWS IAM's policy Condition grammar and
// evaluation semantics: the operator registry (StringEquals, IpAddress,
// DateGreaterThan, ...), the ForAllValues/ForAnyValue/IfExists modifiers,
// and ${...} policy-variable substitution. It has no knowledge of any
// particular policy type (identity, trust, or resource-based) — callers
// supply a statement's raw Condition block, a request's context-key values,
// and the enclosing document's Version, and get back whether the condition
// holds. This lets both iamapi/policy (IAM identity/trust policies) and
// auth (S3 bucket policies) share one implementation and one AWS-verified
// behavior, rather than maintaining two.
package condition

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/versity/versitygw/debuglogger"
)

// Values decodes the value(s) of a single Condition operator/key pair.
// Unlike Action/Resource's string-only representation, a Condition value may
// also be a bare JSON number or boolean rather than a string, so e.g. "5.50"
// round-trips as "5.50", not "5.5". A JSON null value or a non-scalar
// (object/array) element is rejected.
type Values []string

func (c *Values) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			return err
		}
		values := make([]string, len(raws))
		for i, r := range raws {
			s, ok := decodeConditionScalar(r)
			if !ok {
				return fmt.Errorf("policy: invalid condition value %s", r)
			}
			values[i] = s
		}
		*c = values
		return nil
	}

	s, ok := decodeConditionScalar(trimmed)
	if !ok {
		return fmt.Errorf("policy: invalid condition value %s", trimmed)
	}
	*c = Values{s}
	return nil
}

// decodeConditionScalar decodes a single JSON scalar (string, number, or
// bool) to its string form, rejecting null and any non-scalar (object,
// array) value.
func decodeConditionScalar(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", false
		}
		return s, true
	}
	switch string(trimmed) {
	case "true", "false":
		return string(trimmed), true
	case "null":
		return "", false
	}
	var num json.Number
	if err := json.Unmarshal(trimmed, &num); err != nil {
		return "", false
	}
	return num.String(), true
}

// Block is a statement's Condition object, decoded to operator name -> key
// -> value(s).
type Block map[string]map[string]Values

// Qualifier is IAM's multivalued-context-key set operator, given as a
// "ForAllValues:"/"ForAnyValue:" prefix on a condition operator name.
type Qualifier int

const (
	QualifierNone Qualifier = iota
	QualifierForAllValues
	QualifierForAnyValue
)

// conditionComparator is a single (policy value, request value) match test
// for one condition operator family, e.g. string equality or a numeric
// comparison. It never itself accounts for absence, IfExists, negation, or
// multivalued aggregation - those are handled by evaluateConditionKey and
// aggregate around it.
type conditionComparator func(expected, actual string) bool

// conditionOperatorDef is a recognized condition operator's evaluation
// behavior: negate distinguishes a Not-family operator (StringNotEquals,
// ArnNotEquals, ...) from its positive counterpart - both share the same
// comparator, since "not equal" is just the equality test used differently
// (see aggregate), not a different comparison.
type conditionOperatorDef struct {
	compare conditionComparator
	negate  bool
}

// conditionRegistry is every condition operator base name this package
// recognizes, except "Null" (handled separately by evaluateNull - it has no
// value comparator at all, only a presence check). Populated below from
// AWS's documented condition operator reference.
var conditionRegistry = map[string]conditionOperatorDef{
	"StringEquals":              {compare: stringExact},
	"StringNotEquals":           {compare: stringExact, negate: true},
	"StringEqualsIgnoreCase":    {compare: stringFold},
	"StringNotEqualsIgnoreCase": {compare: stringFold, negate: true},
	"StringLike":                {compare: stringLike},
	"StringNotLike":             {compare: stringLike, negate: true},

	"NumericEquals":            {compare: numericCompare(func(a, e float64) bool { return a == e })},
	"NumericNotEquals":         {compare: numericCompare(func(a, e float64) bool { return a == e }), negate: true},
	"NumericLessThan":          {compare: numericCompare(func(a, e float64) bool { return a < e })},
	"NumericLessThanEquals":    {compare: numericCompare(func(a, e float64) bool { return a <= e })},
	"NumericGreaterThan":       {compare: numericCompare(func(a, e float64) bool { return a > e })},
	"NumericGreaterThanEquals": {compare: numericCompare(func(a, e float64) bool { return a >= e })},

	"DateEquals":            {compare: dateCompare(func(a, e time.Time) bool { return a.Equal(e) })},
	"DateNotEquals":         {compare: dateCompare(func(a, e time.Time) bool { return a.Equal(e) }), negate: true},
	"DateLessThan":          {compare: dateCompare(func(a, e time.Time) bool { return a.Before(e) })},
	"DateLessThanEquals":    {compare: dateCompare(func(a, e time.Time) bool { return !a.After(e) })},
	"DateGreaterThan":       {compare: dateCompare(func(a, e time.Time) bool { return a.After(e) })},
	"DateGreaterThanEquals": {compare: dateCompare(func(a, e time.Time) bool { return !a.Before(e) })},

	"Bool": {compare: boolMatch},

	// BinaryEquals is a plain string comparison, not a base64-decode-then-
	// compare: AWS's own IAM condition-operator reference documents the
	// request context value as itself the base64 text (the same string
	// that appears in the policy on a match), never the decoded raw bytes
	// - live-verified via iam:SimulateCustomPolicy, which also rejects a
	// non-base64 binary-typed context value outright. Do not "fix" this to
	// decode either side.
	"BinaryEquals": {compare: stringExact},

	// ArnEquals and ArnLike behave identically in real AWS (both wildcard
	// -aware), and are matched here with the same whole-string GlobMatch
	// already used for Action/Resource - do not "fix" ArnEquals to a strict
	// == later, that would diverge from AWS behavior.
	"ArnEquals":    {compare: stringLike},
	"ArnLike":      {compare: stringLike},
	"ArnNotEquals": {compare: stringLike, negate: true},
	"ArnNotLike":   {compare: stringLike, negate: true},

	"IpAddress":    {compare: ipMatch},
	"NotIpAddress": {compare: ipMatch, negate: true},
}

func stringExact(expected, actual string) bool { return expected == actual }
func stringFold(expected, actual string) bool  { return strings.EqualFold(expected, actual) }
func stringLike(expected, actual string) bool  { return GlobMatch(expected, actual) }

// numericCompare builds a comparator from a (actual, expected float64) ->
// bool test, matching AWS's direction convention (the request's value is
// compared against the policy's value). Either operand failing to parse as
// a number fails the comparison rather than erroring
func numericCompare(op func(actual, expected float64) bool) conditionComparator {
	return func(expected, actual string) bool {
		e, eerr := strconv.ParseFloat(expected, 64)
		a, aerr := strconv.ParseFloat(actual, 64)
		return eerr == nil && aerr == nil && op(a, e)
	}
}

// dateCompare builds a comparator from a (actual, expected time.Time) ->
// bool test, same direction convention as numericCompare.
func dateCompare(op func(actual, expected time.Time) bool) conditionComparator {
	return func(expected, actual string) bool {
		e, eok := parseConditionDate(expected)
		a, aok := parseConditionDate(actual)
		return eok && aok && op(a, e)
	}
}

// parseConditionDate parses a Date condition operand in either form AWS
// accepts: an RFC 3339 date-time, or Unix epoch seconds (optionally
// fractional).
func parseConditionDate(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), true
	}
	return time.Time{}, false
}

func boolMatch(expected, actual string) bool {
	e, eerr := strconv.ParseBool(expected)
	a, aerr := strconv.ParseBool(actual)
	return eerr == nil && aerr == nil && e == a
}

// normalizeIPOrCIDR appends a full-length prefix ("/32" or "/128") to s when
// it names a bare address rather than a CIDR range, so a single address and
// its equivalent /32 or /128 range are always handled the same way.
func normalizeIPOrCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return s + "/32"
	}
	return s + "/128"
}

// ParseIPOrCIDR reports whether s is a valid IP address or CIDR range, for
// write-time validation of an IP-semantic condition key's value (e.g. AWS
// rejects PutBucketPolicy for a non-IP aws:SourceIp value with "Invalid IP
// address in Conditions", independent of which operator wraps it).
func ParseIPOrCIDR(s string) bool {
	_, _, err := net.ParseCIDR(normalizeIPOrCIDR(s))
	return err == nil
}

// ipMatch reports whether actual (an address) falls within cidr (a CIDR
// range, or an exact address treated as a /32 or /128), matching IAM's
// IpAddress/NotIpAddress condition operators. An unparseable operand on
// either side never matches (fails closed) rather than erroring.
func ipMatch(cidr, actual string) bool {
	_, network, err := net.ParseCIDR(normalizeIPOrCIDR(cidr))
	if err != nil {
		return false
	}
	ip := net.ParseIP(actual)
	return ip != nil && network.Contains(ip)
}

// ParsedOperator is a condition operator name decomposed into its set
// qualifier, base operator, and IfExists flag.
type ParsedOperator struct {
	Qualifier Qualifier
	Base      string
	IfExists  bool
}

// ParseOperatorName decomposes name (e.g. "ForAllValues:StringNotEqualsIfExists")
// into a ParsedOperator, reporting ok=false if the base operator (after
// stripping a recognized qualifier prefix and IfExists suffix) isn't one
// conditionRegistry recognizes, or is "Null" (Null has no IfExists variant -
// "NullIfExists" is rejected here since after suffix-stripping "Null" isn't
// itself in conditionRegistry). A bare "Null", optionally qualifier-prefixed, is accepted
func ParseOperatorName(name string) (ParsedOperator, bool) {
	op := name
	qualifier := QualifierNone
	switch {
	case strings.HasPrefix(op, "ForAllValues:"):
		qualifier = QualifierForAllValues
		op = strings.TrimPrefix(op, "ForAllValues:")
	case strings.HasPrefix(op, "ForAnyValue:"):
		qualifier = QualifierForAnyValue
		op = strings.TrimPrefix(op, "ForAnyValue:")
	}

	if op == "Null" {
		return ParsedOperator{Qualifier: qualifier, Base: "Null"}, true
	}

	base := strings.TrimSuffix(op, "IfExists")
	ifExists := base != op
	if _, ok := conditionRegistry[base]; !ok {
		return ParsedOperator{}, false
	}
	return ParsedOperator{Qualifier: qualifier, Base: base, IfExists: ifExists}, true
}

// Parse decodes raw (a statement's Condition block) into a Block, validating
// only its JSON shape and that every operator name is one ParseOperatorName
// recognizes - not condition key names, which are meaningful only to a
// specific policy type (IAM identity policies accept arbitrary custom/tag
// keys; S3 bucket policies validate against AWS's fixed key catalogue) and
// so are the caller's responsibility. An absent, null, or empty raw decodes
// to a nil Block with no error, matching Evaluate's "always matches"
// contract for a statement with no Condition at all.
func Parse(raw json.RawMessage) (Block, error) {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	var block Block
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, err
	}
	for operator := range block {
		if _, ok := ParseOperatorName(operator); !ok {
			return nil, fmt.Errorf("policy: unrecognized condition operator %q", operator)
		}
	}
	return block, nil
}

// ShapeValid reports whether raw (a statement's Condition block) satisfies
// Parse without error - write-time validation of the condition grammar
// alone (operator names), with no opinion on condition keys.
func ShapeValid(raw json.RawMessage) bool {
	_, err := Parse(raw)
	return err == nil
}

// conditionVariableOperators is the subset of conditionRegistry that AWS
// documents as supporting ${...} policy-variable substitution in a
// Condition value: the String family and the Arn family (both ultimately
// whole-string comparisons). AWS's policy-variable documentation
// specifically excludes Numeric, Date, Boolean, Binary, IP address, and
// Null operators - a variable placed there is never substituted, regardless
// of document version.
var conditionVariableOperators = map[string]bool{
	"StringEquals":              true,
	"StringNotEquals":           true,
	"StringEqualsIgnoreCase":    true,
	"StringNotEqualsIgnoreCase": true,
	"StringLike":                true,
	"StringNotLike":             true,
	"ArnEquals":                 true,
	"ArnLike":                   true,
	"ArnNotEquals":              true,
	"ArnNotLike":                true,
}

// Evaluate evaluates a policy statement's Condition block against ctxVars -
// context-key values keyed however the caller's policy type documents them
// (e.g. "aws:<GlobalKey>" for IAM identity/S3 bucket policies,
// "<provider-url>:<claim>" for trust-policy evaluation). An absent or empty
// Condition always matches. version is the enclosing document's Version
// element: a ${...} policy variable in a Condition value is only ever
// substituted when version is exactly "2012-10-17" AND the operator is one
// of conditionVariableOperators - AWS requires the 2012-10-17 policy version
// to use variables at all, and never expands them for
// Numeric/Date/Bool/Binary/IP/Null operators even then. A variable that
// doesn't qualify is left as literal text, the same fallback used for an
// absent/multivalued context key - so it simply won't match a real
// condition value, rather than silently expanding into something AWS itself
// wouldn't.
//
// matched reports whether the condition holds; ok reports whether it could
// be evaluated at all. ok is false only for a Condition block Parse would
// already reject - i.e. only for a document stored before write-time
// validation existed, or containing a future operator this package doesn't
// yet recognize. Callers MUST treat ok=false as "cannot rule out a hidden
// Deny" and deny the whole evaluation, never as a non-match.
func Evaluate(raw json.RawMessage, ctxVars map[string][]string, version string) (matched bool, ok bool) {
	block, err := Parse(raw)
	if err != nil {
		debuglogger.Logf("policy condition block failed to parse: %v", err)
		return false, false
	}

	for operator, kvs := range block {
		op, _ := ParseOperatorName(operator) // Parse already validated every operator name
		for key, expected := range kvs {
			actual, present := lookupContextValues(ctxVars, key)
			if version == version2012 && conditionVariableOperators[op.Base] {
				expected = substituteConditionValues(expected, ctxVars)
			}
			if !evaluateConditionKey(op, expected, actual, present) {
				return false, true
			}
		}
	}
	return true, true
}

// version2012 is AWS's "2012-10-17" policy-document version string, the
// only one that enables ${...} policy-variable substitution. Duplicated
// here (rather than imported) since this package has no dependency on any
// specific policy type's Version constants.
const version2012 = "2012-10-17"

// lookupContextValues retrieves ctxVars[key], matching key
// case-insensitively: AWS documents condition (and policy-variable) key
// *names* as case-insensitive - "aws:SourceIp" and "AWS:SOURCEIP" name the
// same key - even though the values held under that key remain
// case-sensitive. An exact match is tried first so the common case doesn't
// pay for a map scan.
func lookupContextValues(ctxVars map[string][]string, key string) ([]string, bool) {
	if v, ok := ctxVars[key]; ok {
		return v, true
	}
	for k, v := range ctxVars {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// policyVariablePattern matches a single "${...}" policy-variable
// placeholder, e.g. "${aws:username}".
var policyVariablePattern = regexp.MustCompile(`\$\{([A-Za-z0-9_:.\-]+)\}`)

// SubstitutePolicyVariables replaces every ${key} placeholder in s with the
// single value ctxVars holds for key, looked up the same case-insensitive
// way as a Condition key. AWS only allows a single-valued context key to be
// used as a policy variable; a placeholder naming an absent or multivalued
// key is left as literal text, same as any other substring - so it simply
// won't match a real resource ARN or condition value, rather than being
// silently dropped and turning a Deny that relies on it into a no-op.
func SubstitutePolicyVariables(s string, ctxVars map[string][]string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return policyVariablePattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-1]
		values, ok := lookupContextValues(ctxVars, key)
		if !ok || len(values) != 1 {
			return match
		}
		return values[0]
	})
}

// substituteConditionValues applies SubstitutePolicyVariables to every
// element of values, so e.g. a Condition of
// {"StringEquals":{"iam:ResourceTag/owner":"${aws:username}"}} compares
// against the requester's own username rather than the literal text.
func substituteConditionValues(values Values, ctxVars map[string][]string) Values {
	out := make(Values, len(values))
	for i, v := range values {
		out[i] = SubstitutePolicyVariables(v, ctxVars)
	}
	return out
}

// evaluateConditionKey evaluates one operator/key pair of an already
// -parsed Condition block against actual (ctxVars[key]) and present
// (whether key was in ctxVars at all).
func evaluateConditionKey(op ParsedOperator, expected Values, actual []string, present bool) bool {
	if op.Base == "Null" {
		return evaluateNull(expected, present)
	}
	entry := conditionRegistry[op.Base] // guaranteed present - ParseOperatorName already validated op.Base

	if op.Qualifier == QualifierForAllValues && !present {
		return true
	}
	if entry.negate {
		if !present {
			return true
		}
		return aggregate(op.Qualifier, true, expected, actual, entry.compare)
	}
	if !present {
		return op.IfExists
	}
	return aggregate(op.Qualifier, false, expected, actual, entry.compare)
}

// evaluateNull implements the Null condition operator: true if expected
// (normally exactly one of "true"/"false", case-insensitive) says the key
// must be absent ("true") and it is, or must be present ("false") and it
// is. A value that's neither "true" nor "false" never satisfies the
// condition (fails closed)
func evaluateNull(expected Values, present bool) bool {
	for _, e := range expected {
		switch {
		case strings.EqualFold(e, "true"):
			if !present {
				return true
			}
		case strings.EqualFold(e, "false"):
			if present {
				return true
			}
		}
	}
	return false
}

// aggregate reports whether expected/actual satisfy a condition-key match
// under qualifier's multivalued-context-key semantics. negate selects the
// Not-operator family, sharing the same per-pair comparator as its positive
// counterpart (see conditionRegistry).
func aggregate(qualifier Qualifier, negate bool, expected Values, actual []string, cmp conditionComparator) bool {
	matchesAny := func(a string) bool {
		for _, e := range expected {
			if cmp(e, a) {
				return true
			}
		}
		return false
	}

	useForAll := qualifier == QualifierForAllValues || (qualifier == QualifierNone && negate)
	if useForAll {
		for _, a := range actual {
			if ok := matchesAny(a); ok == negate {
				return false
			}
		}
		return true // vacuously true over an empty/absent actual
	}
	for _, a := range actual {
		if ok := matchesAny(a); ok != negate {
			return true
		}
	}
	return false // vacuously false over an empty/absent actual
}

// GlobMatch implements the small wildcard grammar IAM Action/Resource/Arn
// patterns use: '*' matches any run of characters (including none), '?'
// matches exactly one character, everything else matches literally.
func GlobMatch(pattern, s string) bool {
	var pi, si, star, match int
	star = -1
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			match = si
			pi++
		case star != -1:
			pi = star + 1
			match++
			si = match
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
