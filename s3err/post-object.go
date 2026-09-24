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

package s3err

import (
	"fmt"
	"net/http"
	"strings"
)

// argCredential is the canonical spelling of the POST form credential field.
// S3 echoes the form field names back in <ArgumentName> canonicalized, not as
// they are spelled in the submitted form.
const argCredential = "X-Amz-Credential"

// canonicalPOSTFormFields maps the POST form authentication field names to the
// spelling S3 reports them with. Fields that are not part of the signing
// protocol, such as "key", are reported as submitted.
var canonicalPOSTFormFields = map[string]string{
	"x-amz-algorithm":      "X-Amz-Algorithm",
	"x-amz-credential":     argCredential,
	"x-amz-date":           "X-Amz-Date",
	"x-amz-signature":      "X-Amz-Signature",
	"x-amz-security-token": "X-Amz-Security-Token",
}

// canonicalPOSTFormField returns the spelling S3 reports field with, leaving
// fields outside the signing protocol untouched.
func canonicalPOSTFormField(field string) string {
	if canonical, ok := canonicalPOSTFormFields[strings.ToLower(field)]; ok {
		return canonical
	}

	return field
}

// Factory for building s3 object POST authentication errors.
func invalidPOSTObjectAuthErr(argName, argValue, format string, args ...any) InvalidArgumentError {
	return InvalidArgumentError{
		ArgumentName:  argName,
		ArgumentValue: argValue,
		Description:   fmt.Sprintf(format, args...),
	}
}

type invalidPostAuthErr struct{}

func (invalidPostAuthErr) InvalidDateFormat(creds, date string) S3Error {
	return invalidPOSTObjectAuthErr(
		argCredential,
		creds,
		"incorrect date format %q. This date in the credential must be in the format \"yyyyMMdd\".",
		date,
	)
}

func (invalidPostAuthErr) MalformedCredential(creds string) S3Error {
	return invalidPOSTObjectAuthErr(
		argCredential,
		creds,
		"the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
	)
}

func (invalidPostAuthErr) IncorrectTerminal(creds, terminal string) S3Error {
	return invalidPOSTObjectAuthErr(
		argCredential,
		creds,
		"incorrect terminal %q. This endpoint uses \"aws4_request\".",
		terminal,
	)
}

func (invalidPostAuthErr) IncorrectRegion(creds, expected, actual string) S3Error {
	err := invalidPOSTObjectAuthErr(
		argCredential,
		creds,
		"the region '%s' is wrong; expecting '%s'",
		actual,
		expected,
	)
	err.Region = expected

	return err
}

func (invalidPostAuthErr) IncorrectService(creds, service string) S3Error {
	return invalidPOSTObjectAuthErr(
		argCredential,
		creds,
		"incorrect service %q. This endpoint belongs to \"s3\".",
		service,
	)
}

func (invalidPostAuthErr) MissingField(field string) S3Error {
	name := canonicalPOSTFormField(field)

	return invalidPOSTObjectAuthErr(
		name,
		"",
		"Bucket POST must contain a field named '%s'.  If it is specified, please check the order of the fields.",
		name,
	)
}

var PostAuth invalidPostAuthErr

// Factory for building s3 object POST authentication errors.
func invalidPolicyDocumentErr(format string, args ...any) APIError {
	return APIError{
		Code:           "InvalidPolicyDocument",
		Description:    fmt.Sprintf(format, args...),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func invalidAccordingToPolicyErr(format string, args ...any) APIError {
	return APIError{
		Code:           "AccessDenied",
		Description:    fmt.Sprintf(format, args...),
		HTTPStatusCode: http.StatusForbidden,
	}
}

type invalidPolicyDocument struct{}

func (invalidPolicyDocument) EmptyPolicy() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Expecting '{' but found End-of-Input")
}

func (invalidPolicyDocument) InvalidBase64Encoding() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: invalid Base64 encoding.")
}

func (invalidPolicyDocument) InvalidJSON() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid JSON.")
}

func (invalidPolicyDocument) UnexpectedField(field string) S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Unexpected: %q", field)
}

func (invalidPolicyDocument) MissingExpiration() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Policy missing expiration.")
}

func (invalidPolicyDocument) InvalidExpiration(exp string) S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid 'expiration' value: '%s'", exp)
}

func (invalidPolicyDocument) InvalidConditions() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid 'conditions' value: must be a List.")
}

func (invalidPolicyDocument) InvalidCondition() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid condition test: must be a List or Object.")
}

func (invalidPolicyDocument) MissingConditionOperationIdentifier() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Condition: missing operation identifier.")
}

func (invalidPolicyDocument) UnknownConditionOperation(op string) S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Condition: unknown operation '%s'.", op)
}

func (invalidPolicyDocument) IncorrectConditionArgumentsNumber(op string) S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid %s: wrong number of arguments.", op)
}

func (invalidPolicyDocument) MissingConditions() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Policy missing conditions.")
}

func (invalidPolicyDocument) OnePropSimpleCondition() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Simple-Condition: Simple-Conditions must have exactly one property specified.")
}

func (invalidPolicyDocument) InvalidSimpleCondition() S3Error {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Simple-Condition: value must be a string.")
}

func (invalidPolicyDocument) ConditionFailed(condition string) S3Error {
	return invalidAccordingToPolicyErr("Invalid according to Policy: Policy Condition failed: %s", condition)
}

func (invalidPolicyDocument) ExtraInputField(field string) S3Error {
	return invalidAccordingToPolicyErr("Invalid according to Policy: Extra input fields: %s", field)
}

func (invalidPolicyDocument) PolicyExpired() S3Error {
	return invalidAccordingToPolicyErr("Invalid according to Policy: Policy expired.")
}

var InvalidPolicyDocument invalidPolicyDocument
