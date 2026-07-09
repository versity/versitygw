// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamerr

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	Namespace         = "https://iam.amazonaws.com/doc/2010-05-08/"
	AWSFaultNamespace = "http://webservices.amazon.com/AWSFault/2005-15-09"
)

type ErrorType string

const (
	TypeSender   ErrorType = "Sender"
	TypeReceiver ErrorType = "Receiver"
)

type ErrorCode int

const (
	ErrInternalFailure ErrorCode = iota

	ErrSignatureDoesNotMatch
	ErrMissingAuthenticationToken
	ErrIncompleteSignature
	ErrUnsupportedSignatureVersion
	ErrMissingAuthorizationComponents
	ErrIncorrectService
	ErrInvalidCredentialDate
	ErrInvalidTerminal
	ErrUnsupportedQueryAlgorithm
	ErrInvalidRegion
	ErrMissingHostSignedHeader
	ErrInvalidClientTokenID
	ErrInvalidContentLength
	ErrThrottling
	ErrTooManyTags
	ErrInvalidPathPrefix
	ErrDuplicateTagKeys
	ErrInvalidAccessKeyIDChars
	ErrDeleteConflict
	ErrDeleteConflictPolicies
)

type APIError interface {
	error
	StatusCode() int
	XMLBody(requestID string) []byte
}

type Error struct {
	Type           ErrorType
	Code           string
	Message        string
	HTTPStatusCode int
	XMLNamespace   string
}

func (e Error) Error() string {
	return e.Code + ": " + e.Message
}

func (e Error) StatusCode() int {
	return e.HTTPStatusCode
}

func (e Error) XMLBody(requestID string) []byte {
	namespace := e.XMLNamespace
	if namespace == "" {
		namespace = Namespace
	}

	body, err := xml.Marshal(struct {
		XMLName   xml.Name
		Error     errorXML
		RequestID string `xml:"RequestId"`
	}{
		XMLName: xml.Name{Space: namespace, Local: "ErrorResponse"},
		Error: errorXML{
			Type:    e.Type,
			Code:    e.Code,
			Message: e.Message,
		},
		RequestID: requestID,
	})
	if err != nil {
		return nil
	}

	return append([]byte(xml.Header), body...)
}

type errorXML struct {
	Type    ErrorType
	Code    string
	Message string
}

var errorCodeResponse = map[ErrorCode]Error{
	ErrInternalFailure: {
		Type:           TypeReceiver,
		Code:           "InternalFailure",
		Message:        "The request processing has failed because of an unknown error, exception or failure.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrInvalidContentLength: {
		Type:           TypeSender,
		Code:           "InvalidRequest",
		Message:        "Content-Length must be a valid integer.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrThrottling: {
		Type:           TypeSender,
		Code:           "Throttling",
		Message:        "Rate exceeded.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingAuthenticationToken: {
		Type:           TypeSender,
		Code:           "MissingAuthenticationToken",
		Message:        "Request is missing Authentication Token",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrUnsupportedQueryAlgorithm: {
		Type:           TypeSender,
		Code:           "MissingAuthenticationToken",
		Message:        "Missing Authentication Token",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidClientTokenID: {
		Type:           TypeSender,
		Code:           "InvalidClientTokenId",
		Message:        "The security token included in the request is invalid.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrIncompleteSignature: {
		Type:           TypeSender,
		Code:           "IncompleteSignature",
		Message:        "The request signature does not conform to AWS standards.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedSignatureVersion: {
		Type:           TypeSender,
		Code:           "IncompleteSignature",
		Message:        "AWS Signature Version 2 is not supported.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingAuthorizationComponents: {
		Type:           TypeSender,
		Code:           "IncompleteSignature",
		Message:        "Authorization header requires Credential, SignedHeaders, and Signature.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSignatureDoesNotMatch: {
		Type:           TypeSender,
		Code:           "SignatureDoesNotMatch",
		Message:        "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrIncorrectService: {
		Type:           TypeSender,
		Code:           "SignatureDoesNotMatch",
		Message:        "Credential should be scoped to correct service: 'iam'.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCredentialDate: {
		Type:           TypeSender,
		Code:           "SignatureDoesNotMatch",
		Message:        "Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTerminal: {
		Type:           TypeSender,
		Code:           "SignatureDoesNotMatch",
		Message:        "Credential should be scoped with a valid terminator: 'aws4_request'.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidRegion: {
		Type:           TypeSender,
		Code:           "SignatureDoesNotMatch",
		Message:        "Credential should be scoped to a valid region. ",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrMissingHostSignedHeader: {
		Type:           TypeSender,
		Code:           "SignatureDoesNotMatch",
		Message:        "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidPathPrefix: {
		Type:           TypeSender,
		Code:           "ValidationError",
		Message:        "The specified value for pathPrefix is invalid. It must begin with the / character and contain only alphanumeric characters and/or / characters.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrTooManyTags: {
		Type:           TypeSender,
		Code:           "ValidationError",
		Message:        "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrDuplicateTagKeys: {
		Type:           TypeSender,
		Code:           "InvalidInput",
		Message:        "Duplicate tag keys found. Please note that Tag keys are case insensitive.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidAccessKeyIDChars: {
		Type:           TypeSender,
		Code:           "ValidationError",
		Message:        "The specified value for accessKeyId is invalid. It must contain only alphanumeric characters.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrDeleteConflict: {
		Type:           TypeSender,
		Code:           "DeleteConflict",
		Message:        "Cannot delete entity, must delete access keys first.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrDeleteConflictPolicies: {
		Type:           TypeSender,
		Code:           "DeleteConflict",
		Message:        "Cannot delete entity, must delete policies first.",
		HTTPStatusCode: http.StatusConflict,
	},
}

func GetAPIError(code ErrorCode) Error {
	if err, ok := errorCodeResponse[code]; ok {
		return err
	}

	return errorCodeResponse[ErrInternalFailure]
}

func InvalidAction(action, version string) Error {
	err := newSenderError("InvalidAction", fmt.Sprintf("Could not find operation %s for version %s", action, version), http.StatusBadRequest)
	err.XMLNamespace = AWSFaultNamespace
	return err
}

func MissingParameter(parameter string) Error {
	return newSenderError("MissingParameter", fmt.Sprintf("The request must contain the parameter %s.", parameter), http.StatusBadRequest)
}

func IncompleteSignatureMalformedComponent(component string) Error {
	err := GetAPIError(ErrIncompleteSignature)
	err.Message = fmt.Sprintf("Authorization component %q is malformed.", component)
	return err
}

func IncompleteSignatureMalformedCredential(credential string) Error {
	return newSenderError(
		"IncompleteSignature",
		fmt.Sprintf("Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got '%s'", credential),
		http.StatusBadRequest,
	)
}

func IncompleteSignatureMissingAuthorizationComponent(component, authorization string) Error {
	err := GetAPIError(ErrIncompleteSignature)
	err.Message = fmt.Sprintf("Authorization header requires '%s' parameter. (Hashed with SHA-256 and encoded with Base64) Authorization=%s",
		component,
		hashAuthorization(authorization))
	return err
}

func IncompleteSignatureMissingQueryParameter(parameter string) Error {
	err := GetAPIError(ErrIncompleteSignature)
	err.Message = fmt.Sprintf("AWS query-string parameters must include '%s'. Re-examine the query-string parameters.", parameter)
	return err
}

func IncompleteSignatureMissingDate(authorization string) Error {
	return newSenderError(
		"IncompleteSignature",
		fmt.Sprintf("Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. (Hashed with SHA-256 and encoded with Base64) Authorization=%s", hashAuthorization(authorization)),
		http.StatusBadRequest,
	)
}

func IncompleteSignatureInvalidXAmzDate(date string) Error {
	return newSenderError(
		"IncompleteSignature",
		fmt.Sprintf("Date must be in ISO-8601 'basic format'. Got '%s'. See http://en.wikipedia.org/wiki/ISO_8601", date),
		http.StatusBadRequest,
	)
}

func IncompleteSignatureHeadersNotSigned(headers []string) Error {
	err := GetAPIError(ErrIncompleteSignature)
	err.Message = fmt.Sprintf("The request signature does not conform to AWS standards. Header(s) not signed: %s.", strings.Join(headers, ", "))
	return err
}

func SignatureDoesNotMatchNotYetCurrent(requestTime, serverTime time.Time, allowedSkew time.Duration) Error {
	err := GetAPIError(ErrSignatureDoesNotMatch)
	err.Message = fmt.Sprintf("Signature not yet current: %s is still later than %s (%s + %d min.)",
		requestTime.UTC().Format("20060102T150405Z"),
		serverTime.UTC().Add(allowedSkew).Format("20060102T150405Z"),
		serverTime.UTC().Format("20060102T150405Z"),
		allowedSkew/time.Minute)
	return err
}

func SignatureDoesNotMatchExpired(requestTime, serverTime time.Time, allowedSkew time.Duration) Error {
	err := GetAPIError(ErrSignatureDoesNotMatch)
	err.Message = fmt.Sprintf("Signature expired: %s is now earlier than %s (%s - %d min.)",
		requestTime.UTC().Format("20060102T150405Z"),
		serverTime.UTC().Add(-allowedSkew).Format("20060102T150405Z"),
		serverTime.UTC().Format("20060102T150405Z"),
		allowedSkew/time.Minute)
	return err
}

func EntityAlreadyExistsUser(userName string) Error {
	return newSenderError("EntityAlreadyExists", fmt.Sprintf("User with name %s already exists.", userName), http.StatusConflict)
}

func NoSuchEntityUser(userName string) Error {
	return newSenderError("NoSuchEntity", fmt.Sprintf("The user with name %s cannot be found.", userName), http.StatusNotFound)
}

func NoSuchEntityAccessKey(accessKeyID string) Error {
	return newSenderError("NoSuchEntity", fmt.Sprintf("The Access Key with id %s cannot be found", accessKeyID), http.StatusNotFound)
}

func AccessKeysLimitExceeded(maxKeys int) Error {
	return newSenderError("LimitExceeded", fmt.Sprintf("Cannot exceed quota for AccessKeysPerUser: %d", maxKeys), http.StatusConflict)
}

func ValidationError(message string) Error {
	return newSenderError("ValidationError", message, http.StatusBadRequest)
}

func InvalidInput(message string) Error {
	return newSenderError("InvalidInput", message, http.StatusBadRequest)
}

func InvalidUserName(field string) Error {
	return ValidationError(fmt.Sprintf("The specified value for %s is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", field))
}

func UserNameTooLong(field string, maxLength int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", field, maxLength))
}

func InvalidPath(field string) Error {
	return ValidationError(fmt.Sprintf("The specified value for %s is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters.", field))
}

func PathTooLong(field string, maxLength int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", field, maxLength))
}

func InvalidMaxItems(value string) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value '%s' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000", value))
}

func AccessKeyIDTooShort(minLength int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at 'accessKeyId' failed to satisfy constraint: Member must have length greater than or equal to %d", minLength))
}

func AccessKeyIDTooLong(maxLength int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at 'accessKeyId' failed to satisfy constraint: Member must have length less than or equal to %d", maxLength))
}

func InvalidAccessKeyStatus(value string) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value '%s' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]", value))
}

func TagKeyTooLong(index int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at 'tags.%d.member.key' failed to satisfy constraint: Member must have length less than or equal to 128", index))
}

func InvalidTagKey(index int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at 'tags.%d.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+", index))
}

func TagValueTooLong(index int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at 'tags.%d.member.value' failed to satisfy constraint: Member must have length less than or equal to 256", index))
}

func InvalidTagValue(index int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at 'tags.%d.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*", index))
}

func MissingValue(field string) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must not be null", field))
}

func ValueTooLong(field string, maxLength int) Error {
	return ValidationError(fmt.Sprintf("1 validation error detected: Value at '%s' failed to satisfy constraint: Member must have length less than or equal to %d", field, maxLength))
}

func InvalidCharset(field string) Error {
	return ValidationError(fmt.Sprintf("The specified value for %s is invalid. It must contain only printable ASCII characters.", field))
}

func MalformedPolicyDocument(message string) Error {
	return newSenderError("MalformedPolicyDocument", message, http.StatusBadRequest)
}

func NoSuchEntityUserPolicy(userName, policyName string) Error {
	return newSenderError("NoSuchEntity", fmt.Sprintf("The user policy with name %s cannot be found.", policyName), http.StatusNotFound)
}

func InlinePolicyQuotaExceeded(entityKind, entityName string, maxBytes int) Error {
	return newSenderError("LimitExceeded", fmt.Sprintf("Maximum policy size of %d bytes exceeded for %s %s", maxBytes, entityKind, entityName), http.StatusConflict)
}

func newSenderError(code, message string, statusCode int) Error {
	return Error{
		Type:           TypeSender,
		Code:           code,
		Message:        message,
		HTTPStatusCode: statusCode,
	}
}

func hashAuthorization(authorization string) string {
	hash := sha256.Sum256([]byte(authorization))
	return base64.StdEncoding.EncodeToString(hash[:])
}
