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
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
)

type InvalidArgErrorCode int

const (
	InvalidArgMaxBuckets InvalidArgErrorCode = iota
	InvalidArgNegativeMaxKeys
	InvalidArgObjectAttributes
	InvalidArgPartNumber
	InvalidArgCompleteMpPartNumber
	InvalidArgCopySourceRange
	InvalidArgCopySourceBucket
	InvalidArgCopySourceObject
	InvalidArgCopySourceEncoding
	InvalidArgURLEncodedTagging
	InvalidArgAuthHeader
	InvalidArgAuthorizationType
	InvalidArgPOSTFileRequired
	InvalidArgSHA256Payload
	InvalidArgCopySource
	InvalidArgRetainUntilDate
	InvalidArgPastObjectLockRetainDate
	InvalidArgObjectLockRetentionDays
	InvalidArgObjectLockRetentionYears
	InvalidArgMissingObjectLockRetainDate
	InvalidArgMissingObjectLockMode
	InvalidArgLegalHoldStatus
	InvalidArgObjectLockMode
	InvalidArgMetadataDirective
	InvalidArgTaggingDirective
	InvalidArgVersionId
	InvalidArgChecksumPart
	InvalidArgMissingUploadId
	InvalidArgUploadIdMarker
	InvalidArgCannedAcl
	InvalidArgOnlyAws4HmacSha256
	InvalidArgDateHeader
	InvalidArgIndexDocumentSuffix
	InvalidArgErrorDocumentKey
)

var invalidArgErrResponses = map[InvalidArgErrorCode]InvalidArgumentError{
	InvalidArgMaxBuckets: {
		Description:  "Argument max-buckets must be an integer between 1 and 10000.",
		ArgumentName: "max-buckets",
	},
	InvalidArgNegativeMaxKeys: {
		Description:  "max-keys cannot be negative",
		ArgumentName: "maxKeys",
	},
	InvalidArgObjectAttributes: {
		Description:  "Invalid attribute name specified.",
		ArgumentName: "x-amz-object-attributes",
	},
	InvalidArgPartNumber: {
		Description:  "Part number must be an integer between 1 and 10000, inclusive.",
		ArgumentName: "partNumber",
	},
	InvalidArgCompleteMpPartNumber: {
		Description:  "PartNumber must be >= 1",
		ArgumentName: "PartNumber",
	},
	InvalidArgCopySourceRange: {
		Description:  "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
		ArgumentName: "x-amz-copy-source-range",
	},
	InvalidArgCopySourceBucket: {
		Description:  "Invalid copy source bucket name",
		ArgumentName: "x-amz-copy-source",
	},
	InvalidArgCopySourceObject: {
		Description:  "Invalid copy source object key",
		ArgumentName: "x-amz-copy-source",
	},
	InvalidArgCopySourceEncoding: {
		Description:  "Invalid copy source encoding",
		ArgumentName: "x-amz-copy-source",
	},
	InvalidArgURLEncodedTagging: {
		Description:  "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.",
		ArgumentName: "x-amz-tagging",
	},
	InvalidArgAuthHeader: {
		Description:  "Authorization header is invalid -- one and only one ' ' (space) required.",
		ArgumentName: "Authorization",
	},
	InvalidArgAuthorizationType: {
		Description:  "Unsupported Authorization Type",
		ArgumentName: "Authorization",
	},
	InvalidArgPOSTFileRequired: {
		Description:  "POST requires exactly one file upload per request.",
		ArgumentName: "file",
	},
	InvalidArgSHA256Payload: {
		Description:  "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER or a valid sha256 value.",
		ArgumentName: "x-amz-content-sha256",
	},
	InvalidArgCopySource: {
		Description:  "You can only specify a copy source header for copy requests.",
		ArgumentName: "x-amz-copy-source",
	},
	InvalidArgRetainUntilDate: {
		Description:  "The retain until date must be provided in ISO 8601 format",
		ArgumentName: "x-amz-object-lock-retain-until-date",
	},
	InvalidArgPastObjectLockRetainDate: {
		Description:  "The retain until date must be in the future!",
		ArgumentName: "x-amz-object-lock-retain-until-date",
	},
	InvalidArgMissingObjectLockRetainDate: {
		Description:  "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied.",
		ArgumentName: "x-amz-object-lock-retain-until-date",
	},
	InvalidArgMissingObjectLockMode: {
		Description:  "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied.",
		ArgumentName: "x-amz-object-lock-mode",
	},
	InvalidArgObjectLockRetentionDays: {
		Description:  "Default retention period must be a positive integer value.",
		ArgumentName: "Days",
	},
	InvalidArgObjectLockRetentionYears: {
		Description:  "Default retention period must be a positive integer value.",
		ArgumentName: "Years",
	},
	InvalidArgLegalHoldStatus: {
		Description:  "Legal Hold must be either of 'ON' or 'OFF'",
		ArgumentName: "x-amz-object-lock-legal-hold",
	},
	InvalidArgObjectLockMode: {
		Description:  "Unknown wormMode directive.",
		ArgumentName: "x-amz-object-lock-mode",
	},
	InvalidArgMetadataDirective: {
		Description:  "Unknown metadata directive.",
		ArgumentName: "x-amz-metadata-directive",
	},
	InvalidArgTaggingDirective: {
		Description:  "Unknown tagging directive.",
		ArgumentName: "x-amz-tagging-directive",
	},
	InvalidArgVersionId: {
		Description:  "Invalid version id specified",
		ArgumentName: "versionId",
	},
	InvalidArgChecksumPart: {
		Description:  "Invalid Base64 or multiple checksums present in request",
		ArgumentName: "Checksum",
	},
	InvalidArgMissingUploadId: {
		Description:  "This operation does not accept partNumber without uploadId",
		ArgumentName: "partNumber",
	},
	InvalidArgUploadIdMarker: {
		Description:  "Invalid uploadId marker",
		ArgumentName: "upload-id-marker",
	},
	InvalidArgCannedAcl: {
		Description:  "",
		ArgumentName: "x-amz-acl",
	},
	InvalidArgOnlyAws4HmacSha256: {
		Description:  "Only AWS4-HMAC-SHA256 is supported",
		ArgumentName: "X-Amz-Algorithm",
	},
	InvalidArgDateHeader: {
		Description:  "X-Amz-Date must be formated via ISO8601 Long format",
		ArgumentName: "X-Amz-Date",
	},
	InvalidArgIndexDocumentSuffix: {
		Description:  "The IndexDocument Suffix is not well formed",
		ArgumentName: "IndexDocument",
	},
	InvalidArgErrorDocumentKey: {
		Description:  "The ErrorDocument Key is not well formed",
		ArgumentName: "ErrorDocument",
	},
}

// InvalidArgumentError is returned when a request argument is invalid.
// Produces <ArgumentName> and <ArgumentValue> fields in the XML response.
type InvalidArgumentError struct {
	Description   string
	ArgumentName  string
	ArgumentValue string
}

func (e InvalidArgumentError) BaseError() APIError {
	return APIError{
		Code:           "InvalidArgument",
		Description:    e.Description,
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// InvalidArgumentError http status code is always 400
func (e InvalidArgumentError) StatusCode() int { return http.StatusBadRequest }

func (e InvalidArgumentError) Error() string {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	enc := xml.NewEncoder(&bytesBuffer)
	_ = enc.Encode(e)
	return bytesBuffer.String()
}

func (e InvalidArgumentError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName       xml.Name `xml:"Error"`
		Code          string
		Message       string
		ArgumentName  string `xml:"ArgumentName,omitempty"`
		ArgumentValue string `xml:"ArgumentValue,omitempty"`
		RequestId     string `xml:"RequestId,omitempty"`
		HostId        string `xml:"HostId,omitempty"`
	}{
		Code:          "InvalidArgument",
		Message:       e.Description,
		ArgumentName:  e.ArgumentName,
		ArgumentValue: e.ArgumentValue,
		RequestId:     requestID,
		HostId:        hostID,
	})
}

func (e InvalidArgumentError) HTMLBody(requestID, hostID string) []byte {
	return e.BaseError().encodeHTMLResponse(requestID, hostID,
		ErrorField{Name: "ArgumentName", Value: e.ArgumentName},
		ErrorField{Name: "ArgumentValue", Value: e.ArgumentValue},
	)
}

func GetInvalidArgumentErr(code InvalidArgErrorCode, value string) InvalidArgumentError {
	err := invalidArgErrResponses[code]
	err.ArgumentValue = value
	return err
}

func GetInvalidArgMaxLimiter(name, value string) InvalidArgumentError {
	return InvalidArgumentError{
		ArgumentName:  name,
		ArgumentValue: value,
		Description:   fmt.Sprintf("Provided %s not an integer or within integer range", value),
	}
}

func GetInvalidArgNegativeMaxLimiter(name, value string) InvalidArgumentError {
	return InvalidArgumentError{
		ArgumentName:  name,
		ArgumentValue: value,
		Description:   fmt.Sprintf("Argument %s must be an integer between 0 and 2147483647", value),
	}
}

func GetInvalidArgExceedingRange(size int64) InvalidArgumentError {
	return InvalidArgumentError{
		ArgumentName:  "x-amz-copy-source-range",
		ArgumentValue: fmt.Sprint(size),
		Description:   fmt.Sprintf("Range specified is not valid for source object of size: %d", size),
	}
}

func GetInvalidArgObjectOwnership(value string) InvalidArgumentError {
	return InvalidArgumentError{
		ArgumentName: "x-amz-object-ownership",
		// no ArgumentValue is returned for this error
		Description: fmt.Sprintf("Invalid x-amz-object-ownership header: %s", value),
	}
}
