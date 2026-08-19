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
	"bytes"
	"encoding/json"
	"fmt"
)

// Recognized values for a policy document's Version element.
const (
	Version2008 = "2008-10-17"
	Version2012 = "2012-10-17"
)

// Document is a parsed AWS IAM policy document.
type Document struct {
	Version   string
	Statement []Statement
}

// Statement is a single element of a policy document's Statement list.
type Statement struct {
	Sid          string
	Effect       string
	Action       StringOrSlice
	NotAction    StringOrSlice
	Resource     StringOrSlice
	NotResource  StringOrSlice
	Principal    json.RawMessage
	NotPrincipal json.RawMessage
	Condition    json.RawMessage
}

// UnmarshalJSON accepts Statement as either a single JSON object or an
// array of objects, matching the AWS IAM policy grammar. A missing or
// JSON-null Statement leaves Document.Statement nil rather than erroring
// here — Validate reports that as a grammar error so all "empty document"
// shapes produce the same message.
func (d *Document) UnmarshalJSON(data []byte) error {
	// A duplicate key anywhere in the document (top-level Version/Statement,
	// a statement's Effect/Action, a Principal key, a nested Condition
	// operator or context key, ...) is ambiguous: Go's json package silently
	// keeps the last occurrence, but real AWS's policy simulator rejects
	// e.g. a duplicated "Effect":"Deny","Effect":"Allow" outright as
	// InvalidInput rather than picking one. Reject the whole document
	// up front, structurally, rather than special-casing every field.
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}

	var raw struct {
		Version   string
		Statement json.RawMessage
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.Version = raw.Version

	if len(raw.Statement) == 0 || string(bytes.TrimSpace(raw.Statement)) == "null" {
		return nil
	}

	var stmts []Statement
	if err := unmarshalStrict(raw.Statement, &stmts); err == nil {
		d.Statement = stmts
		return nil
	}

	var single Statement
	if err := unmarshalStrict(raw.Statement, &single); err != nil {
		return err
	}
	d.Statement = []Statement{single}
	return nil
}

// rejectDuplicateJSONKeys reports an error if any JSON object anywhere in
// raw — at any nesting depth: the top-level document, an individual
// statement, its Principal, or a Condition block's operator/key maps —
// contains the same key twice. The standard decoder accepts this silently
// and keeps the last occurrence, which can turn e.g. a written
// "Effect":"Deny","Effect":"Allow" (rejected by AWS's own policy simulator
// as InvalidInput) into a working Allow instead of a rejected document
func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return checkDuplicateJSONKeys(dec, tok)
}

// checkDuplicateJSONKeys recursively walks the value tok (already read from
// dec) for duplicate object keys, consuming the rest of that value's tokens
// from dec — including its closing delimiter, for an object or array — before
// returning.
func checkDuplicateJSONKeys(dec *json.Decoder, tok json.Token) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar (string/number/bool/null): nothing nested to check
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key := keyTok.(string)
			if _, dup := seen[key]; dup {
				return fmt.Errorf("policy: duplicate key %q", key)
			}
			seen[key] = struct{}{}

			valTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := checkDuplicateJSONKeys(dec, valTok); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume '}'
		return err
	case '[':
		for dec.More() {
			valTok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := checkDuplicateJSONKeys(dec, valTok); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume ']'
		return err
	}
	return nil
}

// unmarshalStrict decodes data into v, rejecting any object field that
// doesn't correspond to one of v's exported struct fields - unlike plain
// json.Unmarshal, which silently ignores unrecognized fields. Used for
// Statement specifically, so e.g. a "Conditon" typo is rejected as a
// malformed policy document rather than silently producing an unconditional Allow/Deny
// Statement's field set (Sid/Effect/Action/NotAction/Resource/NotResource/
// Principal/NotPrincipal/Condition) is AWS's complete statement grammar, so
// nothing legitimate is rejected by this.
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// StringOrSlice decodes a JSON value that may be either a single string or
// an array of strings, matching the AWS IAM policy grammar for Action,
// NotAction, Resource, and NotResource. A JSON-null value decodes to a nil
// StringOrSlice, identical to the key being absent.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	if string(bytes.TrimSpace(data)) == "null" {
		*s = nil
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = StringOrSlice{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*s = StringOrSlice(multi)
	return nil
}
