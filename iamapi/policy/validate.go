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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/versity/versitygw/iamapi/iamerr"
)

// MaxDocumentLength is IAM's parameter-level maximum length for a
// PolicyDocument value.
const MaxDocumentLength = 131072

// vendorPattern is the inferred grammar for the service prefix of a policy
// action/resource (the text before the first ':', e.g. "s3", "iam",
// "elasticloadbalancing"). AWS does not publish this pattern; alphanumeric
// + hyphen matches every real service prefix and was verified to reject an
// empty or space-containing prefix the same way live IAM does.
var vendorPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// validPartition is the only ARN partition name supported byt the gateway: real
// IAM also accepts "aws-cn", "aws-us-gov", and the "aws-iso*" partitions,
// but this deployment only ever runs in the standard "aws" partition, so a
// resource ARN whose partition field is anything else is rejected
const validPartition = "aws"

var (
	errSyntax              = iamerr.MalformedPolicyDocument("Syntax errors in policy.")
	errMissingActions      = iamerr.MalformedPolicyDocument("Policy statement must contain actions.")
	errMissingResources    = iamerr.MalformedPolicyDocument("Policy statement must contain resources.")
	errPrincipalNotAllowed = iamerr.MalformedPolicyDocument("Policy document should not specify a principal.")
	errDuplicateSid        = iamerr.MalformedPolicyDocument("Statement IDs (SID) in a single policy must be unique.")
	errMissingVendorPrefix = iamerr.MalformedPolicyDocument("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")
	errLegacyParsing       = iamerr.MalformedPolicyDocument("The policy failed legacy parsing")
)

// Validate checks raw against IAM's parameter-level constraints for a
// PolicyDocument value: a maximum length of 131072 and the allowed
// character set (tab/LF/CR plus printable Latin-1, U+0020-U+00FF, with at
// least one such character present — so an empty value is rejected here
// too, as a charset violation).
func Validate(field, raw string) error {
	if len(raw) > MaxDocumentLength {
		return iamerr.ValueTooLong(field, MaxDocumentLength)
	}
	if !isValidDocumentCharset(raw) {
		return iamerr.InvalidCharset(field)
	}
	return nil
}

func isValidDocumentCharset(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch r {
		case '\t', '\n', '\r':
			continue
		}
		if r < 0x20 || r > 0xFF {
			return false
		}
	}
	return true
}

// Parse parses raw as an IAM policy document and checks it against IAM
// policy grammar
func Parse(raw string) error {
	var doc Document
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return errSyntax
	}
	return doc.Validate()
}

// Validate checks d against IAM policy document grammar: a valid Version if
// present, a non-empty Statement (single object or array), document-wide
// unique Sids, and per statement, the rules enforced by Statement.Validate.
func (d Document) Validate() error {
	if d.Version != "" && d.Version != Version2008 && d.Version != Version2012 {
		return errSyntax
	}
	if len(d.Statement) == 0 {
		return errSyntax
	}

	seenSids := make(map[string]struct{}, len(d.Statement))
	for _, stmt := range d.Statement {
		if err := stmt.Validate(); err != nil {
			return err
		}
		if stmt.Sid != "" {
			if _, ok := seenSids[stmt.Sid]; ok {
				return errDuplicateSid
			}
			seenSids[stmt.Sid] = struct{}{}
		}
	}

	return nil
}

// Validate checks s against IAM policy statement grammar: a valid Effect,
// no Principal/NotPrincipal, an Action or NotAction (not both) with
// vendor-prefixed values, and a Resource or NotResource (not both) with
// ARN-shaped values. Condition is not modeled or validated.
func (s Statement) Validate() error {
	switch s.Effect {
	case "Allow", "Deny":
	default:
		return errSyntax
	}

	if len(s.Principal) > 0 || len(s.NotPrincipal) > 0 {
		return errPrincipalNotAllowed
	}

	if len(s.Action) > 0 && len(s.NotAction) > 0 {
		return errSyntax
	}
	if len(s.Action) == 0 && len(s.NotAction) == 0 {
		return errMissingActions
	}
	for _, action := range s.Action {
		if err := validateActionVendor(action); err != nil {
			return err
		}
	}
	for _, action := range s.NotAction {
		if err := validateActionVendor(action); err != nil {
			return err
		}
	}

	if len(s.Resource) > 0 && len(s.NotResource) > 0 {
		return errSyntax
	}
	if len(s.Resource) == 0 && len(s.NotResource) == 0 {
		return errMissingResources
	}
	for _, resource := range s.Resource {
		if err := validateResourceARN(resource); err != nil {
			return err
		}
	}
	for _, resource := range s.NotResource {
		if err := validateResourceARN(resource); err != nil {
			return err
		}
	}

	return nil
}

// validateActionVendor checks that action is either the bare wildcard "*"
// or has a syntactically valid "vendor:name" shape. The action name after
// the colon is not checked against any known service/action list — real
// IAM accepts unrecognized service/action names at this stage too.
func validateActionVendor(action string) error {
	if action == "*" {
		return nil
	}
	before, _, ok := strings.Cut(action, ":")
	if !ok {
		return errMissingVendorPrefix
	}
	vendor := before
	if !vendorPattern.MatchString(vendor) {
		return iamerr.MalformedPolicyDocument(fmt.Sprintf("Vendor %s is not valid", vendor))
	}
	return nil
}

// validateResourceARN checks a single Resource/NotResource entry against
// IAM's ARN grammar: either the bare wildcard "*", or
// "arn:partition:service:region:account:resource". The service, region,
// account, and resource fields are not further validated — only the
// partition is checked, matching what real IAM enforces at this stage
func validateResourceARN(resource string) error {
	if resource == "*" {
		return nil
	}
	if !strings.Contains(resource, ":") {
		return iamerr.MalformedPolicyDocument(fmt.Sprintf("Resource %s must be in ARN format or \"*\".", resource))
	}

	if strings.HasPrefix(resource, "arn:") {
		fields := strings.SplitN(resource[len("arn:"):], ":", 5)
		if len(fields) < 5 {
			return errLegacyParsing
		}
		partition := fields[0]
		if partition != validPartition {
			return iamerr.MalformedPolicyDocument(fmt.Sprintf("Partition %q is not valid for resource %q.", partition, resource))
		}
		return nil
	}

	tokens := strings.SplitN(resource, ":", 6)
	field := func(i int) string {
		if i < len(tokens) {
			return tokens[i]
		}
		return "*"
	}
	partition := field(1)
	reconstructed := fmt.Sprintf("arn:%s:%s:%s:%s:%s", partition, field(2), field(3), field(4), field(5))
	return iamerr.MalformedPolicyDocument(fmt.Sprintf("Partition %q is not valid for resource %q.", partition, reconstructed))
}
