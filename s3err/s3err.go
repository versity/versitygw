// Copyright 2023 Versity Software
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
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// APIError structure
type APIError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

// APIErrorResponse - error response format
type APIErrorResponse struct {
	XMLName    xml.Name `xml:"Error" json:"-"`
	Code       string
	Message    string
	Key        string `xml:"Key,omitempty" json:"Key,omitempty"`
	BucketName string `xml:"BucketName,omitempty" json:"BucketName,omitempty"`
	Resource   string
	Region     string `xml:"Region,omitempty" json:"Region,omitempty"`
	RequestID  string `xml:"RequestId" json:"RequestId"`
	HostID     string `xml:"HostId" json:"HostId"`
}

func (A APIError) Error() string {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	e := xml.NewEncoder(&bytesBuffer)
	_ = e.Encode(A)
	return bytesBuffer.String()
}

// ErrorCode type of error status.
type ErrorCode int

// Error codes, see full list at http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
const (
	ErrNone ErrorCode = iota
	ErrAccessDenied
	ErrAnonymousRequest
	ErrAnonymousCreateMp
	ErrAnonymousCopyObject
	ErrAnonymousPutBucketOwnership
	ErrAnonymousGetBucketOwnership
	ErrAnonymousResponseHeaders
	ErrMethodNotAllowed
	ErrBucketNotEmpty
	ErrVersionedBucketNotEmpty
	ErrBucketAlreadyExists
	ErrBucketAlreadyOwnedByYou
	ErrNoSuchBucket
	ErrNoSuchKey
	ErrNoSuchUpload
	ErrInvalidBucketName
	ErrInvalidDigest
	ErrBadDigest
	ErrInvalidMaxKeys
	ErrInvalidMaxBuckets
	ErrInvalidMaxUploads
	ErrInvalidMaxParts
	ErrInvalidPartNumberMarker
	ErrInvalidObjectAttributes
	ErrInvalidPart
	ErrInvalidPartNumber
	ErrInvalidPartOrder
	ErrInvalidCompleteMpPartNumber
	ErrInternalError
	ErrNonEmptyRequestBody
	ErrIncompleteBody
	ErrInvalidCopyDest
	ErrInvalidCopySourceRange
	ErrInvalidCopySourceBucket
	ErrInvalidCopySourceObject
	ErrInvalidCopySourceEncoding
	ErrInvalidTagKey
	ErrInvalidTagValue
	ErrDuplicateTagKey
	ErrBucketTaggingLimited
	ErrObjectTaggingLimited
	ErrCannotParseHTTPRequest
	ErrInvalidURLEncodedTagging
	ErrInvalidAuthHeader
	ErrUnsupportedAuthorizationType
	ErrMalformedPOSTRequest
	ErrPOSTFileRequired
	ErrPostPolicyConditionInvalidFormat
	ErrEntityTooSmall
	ErrEntityTooLarge
	ErrMissingFields
	ErrMissingCredTag
	ErrMalformedXML
	ErrMalformedCredentialDate
	ErrMissingSignHeadersTag
	ErrMissingSignTag
	ErrUnsignedHeaders
	ErrExpiredPresignRequest
	ErrSignatureDoesNotMatch
	ErrContentSHA256Mismatch
	ErrInvalidSHA256Paylod
	ErrInvalidSHA256PayloadUsage
	ErrUnsupportedAnonymousSignedStreaming
	ErrMissingContentLength
	ErrContentLengthMismatch
	ErrInvalidAccessKeyID
	ErrRequestNotReadyYet
	ErrMissingDateHeader
	ErrGetUploadsWithKey
	ErrVersionsWithKey
	ErrCopySourceNotAllowed
	ErrInvalidRequest
	ErrAuthNotSetup
	ErrNotImplemented
	ErrPreconditionFailed
	ErrInvalidObjectState
	ErrInvalidRange
	ErrInvalidURI
	ErrObjectLockConfigurationNotFound
	ErrNoSuchObjectLockConfiguration
	ErrInvalidBucketObjectLockConfiguration
	ErrObjectLockConfigurationNotAllowed
	ErrObjectLocked
	ErrPastObjectLockRetainDate
	ErrObjectLockInvalidRetentionPeriod
	ErrInvalidLegalHoldStatus
	ErrInvalidObjectLockMode
	ErrNoSuchBucketPolicy
	ErrBucketTaggingNotFound
	ErrObjectLockInvalidHeaders
	ErrObjectAttributesInvalidHeader
	ErrRequestTimeTooSkewed
	ErrInvalidBucketAclWithObjectOwnership
	ErrBothCannedAndHeaderGrants
	ErrOwnershipControlsNotFound
	ErrAclNotSupported
	ErrMalformedACL
	ErrUnexpectedContent
	ErrMissingSecurityHeader
	ErrInvalidMetadataDirective
	ErrInvalidTaggingDirective
	ErrKeyTooLong
	ErrInvalidVersionId
	ErrNoSuchVersion
	ErrSuspendedVersioningNotAllowed
	ErrMissingRequestBody
	ErrMultipleChecksumHeaders
	ErrChecksumSDKAlgoMismatch
	ErrChecksumRequired
	ErrMissingContentSha256
	ErrInvalidChecksumAlgorithm
	ErrInvalidChecksumPart
	ErrChecksumTypeWithAlgo
	ErrInvalidChecksumHeader
	ErrTrailerHeaderNotSupported
	ErrBadRequest
	ErrMissingUploadId
	ErrNoSuchCORSConfiguration
	ErrCORSForbidden
	ErrMissingCORSOrigin
	ErrCORSIsNotEnabled
	ErrNotModified
	ErrInvalidLocationConstraint
	ErrInvalidArgument
	ErrMalformedTrailer
	ErrInvalidChunkSize

	// Non-AWS errors
	ErrExistingObjectIsDirectory
	ErrObjectParentIsFile
	ErrDirectoryObjectContainsData
	ErrDirectoryNotEmpty
	ErrQuotaExceeded
	ErrVersioningNotConfigured

	// Admin api errors
	ErrAdminAccessDenied
	ErrAdminUserNotFound
	ErrAdminUserExists
	ErrAdminInvalidUserRole
	ErrAdminMissingUserAcess
	ErrAdminMethodNotSupported
)

var errorCodeResponse = map[ErrorCode]APIError{
	ErrAccessDenied: {
		Code:           "AccessDenied",
		Description:    "Access Denied.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAnonymousRequest: {
		Code:           "AccessDenied",
		Description:    "Anonymous users cannot invoke this API. Please authenticate.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAnonymousCreateMp: {
		Code:           "AccessDenied",
		Description:    "Anonymous users cannot initiate multipart uploads. Please authenticate.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAnonymousCopyObject: {
		Code:           "AccessDenied",
		Description:    "Anonymous users cannot copy objects. Please authenticate.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAnonymousPutBucketOwnership: {
		Code:           "AccessDenied",
		Description:    "s3:PutBucketOwnershipControls does not support Anonymous requests!",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAnonymousGetBucketOwnership: {
		Code:           "AccessDenied",
		Description:    "s3:GetBucketOwnershipControls does not support Anonymous requests!",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAnonymousResponseHeaders: {
		Code:           "InvalidRequest",
		Description:    "Request specific response headers cannot be used for anonymous GET requests.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMethodNotAllowed: {
		Code:           "MethodNotAllowed",
		Description:    "The specified method is not allowed against this resource.",
		HTTPStatusCode: http.StatusMethodNotAllowed,
	},
	ErrBucketNotEmpty: {
		Code:           "BucketNotEmpty",
		Description:    "The bucket you tried to delete is not empty.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrVersionedBucketNotEmpty: {
		Code:           "BucketNotEmpty",
		Description:    "The bucket you tried to delete is not empty. You must delete all versions in the bucket.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrBucketAlreadyExists: {
		Code:           "BucketAlreadyExists",
		Description:    "The requested bucket name is not available. The bucket name can not be an existing collection, and the bucket namespace is shared by all users of the system. Please select a different name and try again.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrBucketAlreadyOwnedByYou: {
		Code:           "BucketAlreadyOwnedByYou",
		Description:    "Your previous request to create the named bucket succeeded and you already own it.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrInvalidBucketName: {
		Code:           "InvalidBucketName",
		Description:    "The specified bucket is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidDigest: {
		Code:           "InvalidDigest",
		Description:    "The Content-Md5 you specified is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBadDigest: {
		Code:           "BadDigest",
		Description:    "The Content-MD5 you specified did not match what we received.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxBuckets: {
		Code:           "InvalidArgument",
		Description:    "Argument max-buckets must be an integer between 1 and 10000.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxUploads: {
		Code:           "InvalidArgument",
		Description:    "Argument max-uploads must be an integer between 0 and 2147483647.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxKeys: {
		Code:           "InvalidArgument",
		Description:    "Argument maxKeys must be an integer between 0 and 2147483647.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxParts: {
		Code:           "InvalidArgument",
		Description:    "Argument max-parts must be an integer between 0 and 2147483647.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartNumberMarker: {
		Code:           "InvalidArgument",
		Description:    "Argument part-number-marker must be an integer between 0 and 2147483647",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidObjectAttributes: {
		Code:           "InvalidArgument",
		Description:    "Invalid attribute name specified.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchBucket: {
		Code:           "NoSuchBucket",
		Description:    "The specified bucket does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchKey: {
		Code:           "NoSuchKey",
		Description:    "The specified key does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchUpload: {
		Code:           "NoSuchUpload",
		Description:    "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrInternalError: {
		Code:           "InternalError",
		Description:    "We encountered an internal error, please try again.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrNonEmptyRequestBody: {
		Code:           "InvalidRequest",
		Description:    "The request included a body. Requests of this type must not include a non-empty body.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrIncompleteBody: {
		Code:           "IncompleteBody",
		Description:    "The request body terminated unexpectedly",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPart: {
		Code:           "InvalidPart",
		Description:    "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartNumber: {
		Code:           "InvalidArgument",
		Description:    "Part number must be an integer between 1 and 10000, inclusive.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartOrder: {
		Code:           "InvalidPartOrder",
		Description:    "The list of parts was not in ascending order. Parts must be ordered by part number.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCompleteMpPartNumber: {
		Code:           "InvalidArgument",
		Description:    "PartNumber must be >= 1",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopyDest: {
		Code:           "InvalidRequest",
		Description:    "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopySourceRange: {
		Code:           "InvalidArgument",
		Description:    "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopySourceBucket: {
		Code:           "InvalidArgument",
		Description:    "Invalid copy source bucket name",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopySourceObject: {
		Code:           "InvalidArgument",
		Description:    "Invalid copy source object key",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopySourceEncoding: {
		Code:           "InvalidArgument",
		Description:    "Invalid copy source encoding",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTagKey: {
		Code:           "InvalidTag",
		Description:    "The TagKey you have provided is invalid",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTagValue: {
		Code:           "InvalidTag",
		Description:    "The TagValue you have provided is invalid",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrDuplicateTagKey: {
		Code:           "InvalidTag",
		Description:    "Cannot provide multiple Tags with the same key",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBucketTaggingLimited: {
		Code:           "BadRequest",
		Description:    "Bucket tag count cannot be greater than 50",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrObjectTaggingLimited: {
		Code:           "BadRequest",
		Description:    "Object tags cannot be greater than 10",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrCannotParseHTTPRequest: {
		Code:           "BadRequest",
		Description:    "An error occurred when parsing the HTTP request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidURLEncodedTagging: {
		Code:           "InvalidArgument",
		Description:    "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedXML: {
		Code:           "MalformedXML",
		Description:    "The XML you provided was not well-formed or did not validate against our published schema.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidAuthHeader: {
		Code:           "InvalidArgument",
		Description:    "Authorization header is invalid -- one and only one ' ' (space) required.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedAuthorizationType: {
		Code:           "InvalidArgument",
		Description:    "Unsupported Authorization Type",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedPOSTRequest: {
		Code:           "MalformedPOSTRequest",
		Description:    "The body of your POST request is not well-formed multipart/form-data.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrPOSTFileRequired: {
		Code:           "InvalidArgument",
		Description:    "POST requires exactly one file upload per request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrPostPolicyConditionInvalidFormat: {
		Code:           "PostPolicyInvalidKeyName",
		Description:    "Invalid according to Policy: Policy Condition failed.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrEntityTooSmall: {
		Code:           "EntityTooSmall",
		Description:    "Your proposed upload is smaller than the minimum allowed object size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEntityTooLarge: {
		Code:           "EntityTooLarge",
		Description:    "Your proposed upload exceeds the maximum allowed object size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingFields: {
		Code:           "MissingFields",
		Description:    "Missing fields in request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingCredTag: {
		Code:           "InvalidRequest",
		Description:    "Missing Credential field for this request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSignHeadersTag: {
		Code:           "InvalidArgument",
		Description:    "Signature header missing SignedHeaders field.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSignTag: {
		Code:           "AccessDenied",
		Description:    "Signature header missing Signature field.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsignedHeaders: {
		Code:           "AccessDenied",
		Description:    "There were headers present in the request which were not signed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrExpiredPresignRequest: {
		Code:           "AccessDenied",
		Description:    "Request has expired.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidAccessKeyID: {
		Code:           "InvalidAccessKeyId",
		Description:    "The AWS Access Key Id you provided does not exist in our records.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrRequestNotReadyYet: {
		Code:           "AccessDenied",
		Description:    "Request is not valid yet.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrSignatureDoesNotMatch: {
		Code:           "SignatureDoesNotMatch",
		Description:    "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrContentSHA256Mismatch: {
		Code:           "XAmzContentSHA256Mismatch",
		Description:    "The provided 'x-amz-content-sha256' header does not match what was computed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidSHA256Paylod: {
		Code:           "InvalidArgument",
		Description:    "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER or a valid sha256 value.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidSHA256PayloadUsage: {
		Code:           "InvalidRequest",
		Description:    "The value of x-amz-content-sha256 header is invalid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedAnonymousSignedStreaming: {
		Code:           "InvalidRequest",
		Description:    "Anonymous requests don't support this x-amz-content-sha256 value. Please use UNSIGNED-PAYLOAD or STREAMING-UNSIGNED-PAYLOAD-TRAILER.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingContentLength: {
		Code:           "MissingContentLength",
		Description:    "You must provide the Content-Length HTTP header.",
		HTTPStatusCode: http.StatusLengthRequired,
	},
	ErrContentLengthMismatch: {
		Code:           "IncompleteBody",
		Description:    "You did not provide the number of bytes specified by the Content-Length HTTP header",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingDateHeader: {
		Code:           "AccessDenied",
		Description:    "AWS authentication requires a valid Date or x-amz-date header.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrGetUploadsWithKey: {
		Code:           "InvalidRequest",
		Description:    "Key is not expected for the GET method ?uploads subresource",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrVersionsWithKey: {
		Code:           "InvalidRequest",
		Description:    "There is no such thing as the ?versions sub-resource for a key",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrCopySourceNotAllowed: {
		Code:           "InvalidArgument",
		Description:    "You can only specify a copy source header for copy requests.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidRequest: {
		Code:           "InvalidRequest",
		Description:    "Invalid Request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAuthNotSetup: {
		Code:           "InvalidRequest",
		Description:    "Signed request requires setting up SeaweedFS S3 authentication.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNotImplemented: {
		Code:           "NotImplemented",
		Description:    "A header you provided implies functionality that is not implemented.",
		HTTPStatusCode: http.StatusNotImplemented,
	},
	ErrPreconditionFailed: {
		Code:           "PreconditionFailed",
		Description:    "At least one of the pre-conditions you specified did not hold.",
		HTTPStatusCode: http.StatusPreconditionFailed,
	},
	ErrInvalidObjectState: {
		Code:           "InvalidObjectState",
		Description:    "The operation is not valid for the current state of the object.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidRange: {
		Code:           "InvalidRange",
		Description:    "The requested range is not satisfiable",
		HTTPStatusCode: http.StatusRequestedRangeNotSatisfiable,
	},
	ErrInvalidURI: {
		Code:           "InvalidURI",
		Description:    "The specified URI couldn't be parsed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrObjectLockConfigurationNotFound: {
		Code:           "ObjectLockConfigurationNotFoundError",
		Description:    "Object Lock configuration does not exist for this bucket.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchObjectLockConfiguration: {
		Code:           "NoSuchObjectLockConfiguration",
		Description:    "The specified object does not have a ObjectLock configuration.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidBucketObjectLockConfiguration: {
		Code:           "InvalidRequest",
		Description:    "Bucket is missing Object Lock Configuration.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrObjectLockConfigurationNotAllowed: {
		Code:           "InvalidBucketState",
		Description:    "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrObjectLocked: {
		Code:           "AccessDenied",
		Description:    "Access Denied because object protected by object lock.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrPastObjectLockRetainDate: {
		Code:           "InvalidRequest",
		Description:    "the retain until date must be in the future.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrObjectLockInvalidRetentionPeriod: {
		Code:           "InvalidRetentionPeriod",
		Description:    "the retention days/years must be positive integer.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidLegalHoldStatus: {
		Code:           "InvalidArgument",
		Description:    "Legal Hold must be either of 'ON' or 'OFF'",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidObjectLockMode: {
		Code:           "InvalidArgument",
		Description:    "Unknown wormMode directive.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchBucketPolicy: {
		Code:           "NoSuchBucketPolicy",
		Description:    "The bucket policy does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrBucketTaggingNotFound: {
		Code:           "NoSuchTagSet",
		Description:    "The TagSet does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrObjectLockInvalidHeaders: {
		Code:           "InvalidRequest",
		Description:    "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrObjectAttributesInvalidHeader: {
		Code:           "InvalidRequest",
		Description:    "The x-amz-object-attributes header specifying the attributes to be retrieved is either missing or empty",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrRequestTimeTooSkewed: {
		Code:           "RequestTimeTooSkewed",
		Description:    "The difference between the request time and the current time is too large.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidBucketAclWithObjectOwnership: {
		Code:           "InvalidBucketAclWithObjectOwnership",
		Description:    "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBothCannedAndHeaderGrants: {
		Code:           "InvalidRequest",
		Description:    "Specifying both Canned ACLs and Header Grants is not allowed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrOwnershipControlsNotFound: {
		Code:           "OwnershipControlsNotFoundError",
		Description:    "The bucket ownership controls were not found.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrAclNotSupported: {
		Code:           "AccessControlListNotSupported",
		Description:    "The bucket does not allow ACLs.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedACL: {
		Code:           "MalformedACLError",
		Description:    "The XML you provided was not well-formed or did not validate against our published schema.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnexpectedContent: {
		Code:           "UnexpectedContent",
		Description:    "This request does not support content.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSecurityHeader: {
		Code:           "MissingSecurityHeader",
		Description:    "Your request was missing a required header.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrInvalidMetadataDirective: {
		Code:           "InvalidArgument",
		Description:    "Unknown metadata directive.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTaggingDirective: {
		Code:           "InvalidArgument",
		Description:    "Unknown tagging directive.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidVersionId: {
		Code:           "InvalidArgument",
		Description:    "Invalid version id specified",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrKeyTooLong: {
		Code:           "KeyTooLongError",
		Description:    "Your key is too long.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchVersion: {
		Code:           "NoSuchVersion",
		Description:    "The specified version does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrSuspendedVersioningNotAllowed: {
		Code:           "InvalidBucketState",
		Description:    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingRequestBody: {
		Code:           "MissingRequestBodyError",
		Description:    "Request Body is empty",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrChecksumSDKAlgoMismatch: {
		Code:           "InvalidRequest",
		Description:    "x-amz-sdk-checksum-algorithm specified, but no corresponding x-amz-checksum-* or x-amz-trailer headers were found.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrChecksumRequired: {
		Code:           "InvalidRequest",
		Description:    "Missing required header for this request: Content-MD5 OR x-amz-checksum-*",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingContentSha256: {
		Code:           "InvalidRequest",
		Description:    "Missing required header for this request: x-amz-content-sha256",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMultipleChecksumHeaders: {
		Code:           "InvalidRequest",
		Description:    "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidChecksumAlgorithm: {
		Code:           "InvalidRequest",
		Description:    "Checksum algorithm provided is unsupported. Please try again with any of the valid types: [CRC32, CRC32C, SHA1, SHA256]",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidChecksumPart: {
		Code:           "InvalidArgument",
		Description:    "Invalid Base64 or multiple checksums present in request",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrChecksumTypeWithAlgo: {
		Code:           "InvalidRequest",
		Description:    "The x-amz-checksum-type header can only be used with the x-amz-checksum-algorithm header.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidChecksumHeader: {
		Code:           "InvalidRequest",
		Description:    "The algorithm type you specified in x-amz-checksum- header is invalid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrTrailerHeaderNotSupported: {
		Code:           "InvalidRequest",
		Description:    "The value specified in the x-amz-trailer header is not supported",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBadRequest: {
		Code:           "400",
		Description:    "Bad Request",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingUploadId: {
		Code:           "InvalidArgument",
		Description:    "This operation does not accept partNumber without uploadId",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchCORSConfiguration: {
		Code:           "NoSuchCORSConfiguration",
		Description:    "The CORS configuration does not exist",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrCORSForbidden: {
		Code:           "AccessForbidden",
		Description:    "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrMissingCORSOrigin: {
		Code:           "BadRequest",
		Description:    "Insufficient information. Origin request header needed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrCORSIsNotEnabled: {
		Code:           "AccessForbidden",
		Description:    "CORSResponse: CORS is not enabled for this bucket.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrNotModified: {
		Code:           "NotModified",
		Description:    "Not Modified",
		HTTPStatusCode: http.StatusNotModified,
	},
	ErrInvalidLocationConstraint: {
		Code:           "InvalidLocationConstraint",
		Description:    "The specified location-constraint is not valid",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidArgument: {
		Code:           "InvalidArgument",
		Description:    "",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedTrailer: {
		Code:           "MalformedTrailerError",
		Description:    "The request contained trailing data that was not well-formed or did not conform to our published schema.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidChunkSize: {
		Code:           "InvalidChunkSizeError",
		Description:    "Only the last chunk is allowed to have a size less than 8192 bytes",
		HTTPStatusCode: http.StatusBadRequest,
	},

	// non aws errors
	ErrExistingObjectIsDirectory: {
		Code:           "ExistingObjectIsDirectory",
		Description:    "Existing Object is a directory.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrObjectParentIsFile: {
		Code:           "ObjectParentIsFile",
		Description:    "Object parent already exists as a file.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrDirectoryObjectContainsData: {
		Code:           "DirectoryObjectContainsData",
		Description:    "Directory object contains data payload.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrDirectoryNotEmpty: {
		Code:           "ErrDirectoryNotEmpty",
		Description:    "Directory object not empty.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrQuotaExceeded: {
		Code:           "QuotaExceeded",
		Description:    "Your request was denied due to quota exceeded.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrVersioningNotConfigured: {
		Code:           "VersioningNotConfigured",
		Description:    "Versioning has not been configured for the gateway.",
		HTTPStatusCode: http.StatusNotImplemented,
	},

	// Admin api errors
	ErrAdminAccessDenied: {
		Code:           "XAdminAccessDenied",
		Description:    "Only admin users have access to this resource.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAdminUserNotFound: {
		Code:           "XAdminUserNotFound",
		Description:    "No user exists with the provided access key ID.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrAdminUserExists: {
		Code:           "XAdminUserExists",
		Description:    "A user with the provided access key ID already exists.",
		HTTPStatusCode: http.StatusConflict,
	},
	ErrAdminInvalidUserRole: {
		Code:           "XAdminInvalidArgument",
		Description:    "User role has to be one of the following: 'user', 'admin', 'userplus'.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminMissingUserAcess: {
		Code:           "XAdminInvalidArgument",
		Description:    "User access key ID is missing.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrAdminMethodNotSupported: {
		Code:           "XAdminMethodNotSupported",
		Description:    "The method is not supported in single root user mode.",
		HTTPStatusCode: http.StatusNotImplemented,
	},
}

// GetAPIError provides API Error for input API error code.
func GetAPIError(code ErrorCode) APIError {
	return errorCodeResponse[code]
}

// getErrorResponse gets in standard error and resource value and
// provides a encodable populated response values
func GetAPIErrorResponse(err APIError, resource, requestID, hostID string) []byte {
	return encodeResponse(APIErrorResponse{
		Code:       err.Code,
		Message:    err.Description,
		BucketName: "",
		Key:        "",
		Resource:   resource,
		Region:     "",
		RequestID:  requestID,
		HostID:     hostID,
	})
}

// Encodes the response headers into XML format.
func encodeResponse(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	e := xml.NewEncoder(&bytesBuffer)
	e.Encode(response)
	return bytesBuffer.Bytes()
}

// Returns invalid checksum error with the provided header in the error description
func GetInvalidChecksumHeaderErr(header string) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("Value for %v header is invalid.", header),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetInvalidTrailingChecksumHeaderErr(header string) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("Value for %v trailing header is invalid.", header),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// Returns checksum type mismatch APIError
func GetChecksumTypeMismatchErr(expected, actual types.ChecksumAlgorithm) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("Checksum Type mismatch occurred, expected checksum Type: %v, actual checksum Type: %v", expected, actual),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// Returns incorrect checksum APIError
func GetChecksumBadDigestErr(algo types.ChecksumAlgorithm) APIError {
	return APIError{
		Code:           "BadDigest",
		Description:    fmt.Sprintf("The %v you specified did not match the calculated checksum.", algo),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// Returns checksum type mismatch error with checksum algorithm
func GetChecksumSchemaMismatchErr(algo types.ChecksumAlgorithm, t types.ChecksumType) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("The %v checksum type cannot be used with the %v checksum algorithm.", strings.ToUpper(string(t)), strings.ToLower(string(algo))),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// Returns checksum type mismatch error for multipart uploads
func GetChecksumTypeMismatchOnMpErr(t types.ChecksumType) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("The upload was created using the %v checksum mode. The complete request must use the same checksum mode.", t),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetIncorrectMpObjectSizeErr(expected, actual int64) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("The provided 'x-amz-mp-object-size' header value %v does not match what was computed: %v", expected, actual),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetNegatvieMpObjectSizeErr(val int64) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("Value for x-amz-mp-object-size header is less than zero: '%v'", val),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetInvalidMpObjectSizeErr(val string) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("Value for x-amz-mp-object-size header is invalid: '%s'", val),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func CreateExceedingRangeErr(objSize int64) APIError {
	return APIError{
		Code:           "InvalidArgument",
		Description:    fmt.Sprintf("Range specified is not valid for source object of size: %d", objSize),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetInvalidCORSHeaderErr(header string) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf(`AllowedHeader "%s" contains invalid character.`, header),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetInvalidCORSRequestHeaderErr(header string) APIError {
	return APIError{
		Code:           "BadRequest",
		Description:    fmt.Sprintf(`Access-Control-Request-Headers "%s" contains invalid character.`, header),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetUnsopportedCORSMethodErr(method string) APIError {
	return APIError{
		Code:           "InvalidRequest",
		Description:    fmt.Sprintf("Found unsupported HTTP method in CORS config. Unsupported method is %s", method),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetInvalidCORSMethodErr(method string) APIError {
	return APIError{
		Code:           "BadRequest",
		Description:    fmt.Sprintf("Invalid Access-Control-Request-Method: %s", method),
		HTTPStatusCode: http.StatusBadRequest,
	}
}
