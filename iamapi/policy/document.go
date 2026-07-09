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
}

// UnmarshalJSON accepts Statement as either a single JSON object or an
// array of objects, matching the AWS IAM policy grammar. A missing or
// JSON-null Statement leaves Document.Statement nil rather than erroring
// here — Validate reports that as a grammar error so all "empty document"
// shapes produce the same message.
func (d *Document) UnmarshalJSON(data []byte) error {
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
	if err := json.Unmarshal(raw.Statement, &stmts); err == nil {
		d.Statement = stmts
		return nil
	}

	var single Statement
	if err := json.Unmarshal(raw.Statement, &single); err != nil {
		return err
	}
	d.Statement = []Statement{single}
	return nil
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
