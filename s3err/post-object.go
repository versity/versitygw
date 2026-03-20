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
)

// Factory for building s3 object POST authentication errors.
func invalidPOSTObjectAuthErr(format string, args ...any) APIError {
	return APIError{
		Code:           "InvalidArgument",
		Description:    fmt.Sprintf(format, args...),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

type invalidPostAuthErr struct{}

func (invalidPostAuthErr) InvalidDateFormat(s string) APIError {
	return invalidPOSTObjectAuthErr(
		"incorrect date format %q. This date in the credential must be in the format \"yyyyMMdd\".",
		s,
	)
}

func (invalidPostAuthErr) MalformedCredential() APIError {
	return invalidPOSTObjectAuthErr(
		"the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
	)
}

func (invalidPostAuthErr) IncorrectTerminal(s string) APIError {
	return invalidPOSTObjectAuthErr("incorrect terminal %q. This endpoint uses \"aws4_request\".", s)
}

func (invalidPostAuthErr) IncorrectRegion(expected, actual string) APIError {
	return invalidPOSTObjectAuthErr("the region %q is wrong; expecting %q", actual, expected)
}

func (invalidPostAuthErr) IncorrectService(s string) APIError {
	return invalidPOSTObjectAuthErr("incorrect service %q. This endpoint belongs to \"s3\".", s)
}

func (invalidPostAuthErr) MissingField(field string) APIError {
	return invalidPOSTObjectAuthErr("Bucket POST must contain a field named '%s'.  If it is specified, please check the order of the fields.", field)
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

func (invalidPolicyDocument) EmptyPolicy() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Expecting '{' but found End-of-Input")
}

func (invalidPolicyDocument) InvalidBase64Encoding() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: invalid Base64 encoding.")
}

func (invalidPolicyDocument) InvalidJSON() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid JSON.")
}

func (invalidPolicyDocument) MissingExpiration() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Policy missing expiration.")
}

func (invalidPolicyDocument) InvalidExpiration(exp string) APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid 'expiration' value: '%s'", exp)
}

func (invalidPolicyDocument) InvalidConditions() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid 'conditions' value: must be a List.")
}

func (invalidPolicyDocument) InvalidCondition() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid condition test: must be a List or Object.")
}

func (invalidPolicyDocument) MissingConditionOperationIdentifier() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Condition: missing operation identifier.")
}

func (invalidPolicyDocument) UnknownConditionOperation(op string) APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Condition: unknown operation '%s'.", op)
}

func (invalidPolicyDocument) IncorrectConditionArgumentsNumber(op string) APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid %s: wrong number of arguments.", op)
}

func (invalidPolicyDocument) MissingConditions() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Policy missing conditions.")
}

func (invalidPolicyDocument) OnePropSimpleCondition() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Simple-Condition: Simple-Conditions must have exactly one property specified.")
}

func (invalidPolicyDocument) InvalidSimpleCondition() APIError {
	return invalidPolicyDocumentErr("Invalid Policy: Invalid Simple-Condition: value must be a string.")
}

func (invalidPolicyDocument) ConditionFailed(condition string) APIError {
	return invalidAccordingToPolicyErr("Invalid according to Policy: Policy Condition failed: %s", condition)
}

func (invalidPolicyDocument) ExtraInputField(field string) APIError {
	return invalidAccordingToPolicyErr("Invalid according to Policy: Extra input fields: %s", field)
}

func (invalidPolicyDocument) PolicyExpired() APIError {
	return invalidAccordingToPolicyErr("Invalid according to Policy: Policy expired.")
}

var InvalidPolicyDocument invalidPolicyDocument
