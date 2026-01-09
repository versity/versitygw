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

package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	bucketNameRegexp   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+[a-z0-9]$`)
	bucketNameIpRegexp = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
)

var strictBucketNameValidation atomic.Bool

func init() {
	strictBucketNameValidation.Store(true)
}

func SetBucketNameValidationStrict(strict bool) {
	strictBucketNameValidation.Store(strict)
}

func GetUserMetaData(headers *fasthttp.RequestHeader) (metadata map[string]string) {
	metadata = make(map[string]string)
	headers.DisableNormalizing()
	for key, value := range headers.AllInOrder() {
		hKey := string(key)
		if strings.HasPrefix(strings.ToLower(hKey), "x-amz-meta-") {
			trimmedKey := strings.ToLower(hKey[11:])
			headerValue := string(value)
			metadata[trimmedKey] = headerValue
		}
	}
	headers.EnableNormalizing()

	return
}

func createHttpRequestFromCtx(ctx *fiber.Ctx, signedHdrs []string, contentLength int64, streamBody bool) (*http.Request, error) {
	req := ctx.Request()
	var body io.Reader
	if streamBody {
		body = req.BodyStream()
	} else {
		body = bytes.NewReader(req.Body())
	}

	uri := ctx.OriginalURL()

	httpReq, err := http.NewRequest(string(req.Header.Method()), uri, body)
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	// Set the request headers
	for key, value := range req.Header.All() {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) {
			httpReq.Header.Add(keyStr, string(value))
		}
	}

	// make sure all headers in the signed headers are present
	for _, header := range signedHdrs {
		if httpReq.Header.Get(header) == "" {
			httpReq.Header.Set(header, "")
		}
	}

	// Check if Content-Length in signed headers
	// If content length is non 0, then the header will be included
	if !includeHeader("Content-Length", signedHdrs) {
		httpReq.ContentLength = 0
	} else {
		httpReq.ContentLength = contentLength
	}

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}

var (
	signedQueryArgs = map[string]bool{
		"X-Amz-Algorithm":     true,
		"X-Amz-Credential":    true,
		"X-Amz-Date":          true,
		"X-Amz-SignedHeaders": true,
		"X-Amz-Signature":     true,
	}
)

func createPresignedHttpRequestFromCtx(ctx *fiber.Ctx, signedHdrs []string, contentLength int64, streamBody bool) (*http.Request, error) {
	req := ctx.Request()
	var body io.Reader
	if streamBody {
		body = req.BodyStream()
	} else {
		body = bytes.NewReader(req.Body())
	}

	uri, _, _ := strings.Cut(ctx.OriginalURL(), "?")
	isFirst := true

	for key, value := range ctx.Request().URI().QueryArgs().All() {
		_, ok := signedQueryArgs[string(key)]
		if !ok {
			escapeValue := url.QueryEscape(string(value))
			if isFirst {
				uri += fmt.Sprintf("?%s=%s", key, escapeValue)
				isFirst = false
			} else {
				uri += fmt.Sprintf("&%s=%s", key, escapeValue)
			}
		}
	}

	httpReq, err := http.NewRequest(string(req.Header.Method()), uri, body)
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}
	// Set the request headers
	for key, value := range req.Header.All() {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) {
			httpReq.Header.Add(keyStr, string(value))
		}
	}

	// Check if Content-Length in signed headers
	// If content length is non 0, then the header will be included
	if !includeHeader("Content-Length", signedHdrs) {
		httpReq.ContentLength = 0
	} else {
		httpReq.ContentLength = contentLength
	}

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}

func SetMetaHeaders(ctx *fiber.Ctx, meta map[string]string) {
	ctx.Response().Header.DisableNormalizing()
	for key, val := range meta {
		ctx.Response().Header.Set(fmt.Sprintf("x-amz-meta-%s", key), val)
	}
	ctx.Response().Header.EnableNormalizing()
}

func ParseUint(str string) (int32, error) {
	if str == "" {
		return 1000, nil
	}
	num, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		debuglogger.Logf("invalid intager provided: %v\n", err)
		return 1000, fmt.Errorf("invalid int: %w", err)
	}
	if num < 0 {
		debuglogger.Logf("negative intager provided: %v\n", num)
		return 1000, fmt.Errorf("negative uint: %v", num)
	}
	if num > 1000 {
		num = 1000
	}
	return int32(num), nil
}

type CustomHeader struct {
	Key   string
	Value string
}

func SetResponseHeaders(ctx *fiber.Ctx, headers []CustomHeader) {
	for _, header := range headers {
		ctx.Set(header.Key, header.Value)
	}
}

// Streams the response body by chunks
func StreamResponseBody(ctx *fiber.Ctx, rdr io.ReadCloser, bodysize int) {
	// SetBodyStream will call Close() on the reader when the stream is done
	// since rdr is a ReadCloser
	ctx.Context().SetBodyStream(rdr, bodysize)
}

func IsValidBucketName(bucket string) bool {
	if !strictBucketNameValidation.Load() {
		return true
	}

	if len(bucket) < 3 || len(bucket) > 63 {
		debuglogger.Logf("bucket name length should be in 3-63 range, got: %v\n", len(bucket))
		return false
	}
	// Checks to contain only digits, lowercase letters, dot, hyphen.
	// Checks to start and end with only digits and lowercase letters.
	if !bucketNameRegexp.MatchString(bucket) {
		debuglogger.Logf("invalid bucket name: %v\n", bucket)
		return false
	}
	// Checks not to be a valid IP address
	if bucketNameIpRegexp.MatchString(bucket) {
		debuglogger.Logf("bucket name is an ip address: %v\n", bucket)
		return false
	}
	return true
}

func includeHeader(hdr string, signedHdrs []string) bool {
	for _, shdr := range signedHdrs {
		if strings.EqualFold(hdr, shdr) {
			return true
		}
	}
	return false
}

// expiration time window
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html#RESTAuthenticationTimeStamp
const timeExpirationSec = 15 * 60

func ValidateDate(date time.Time) error {
	now := time.Now().UTC()
	diff := date.Unix() - now.Unix()

	// Checks the dates difference to be within allotted window
	if diff > timeExpirationSec || diff < -timeExpirationSec {
		return s3err.GetAPIError(s3err.ErrRequestTimeTooSkewed)
	}

	return nil
}

func ParseDeleteObjects(objs []types.ObjectIdentifier) (result []string) {
	for _, obj := range objs {
		result = append(result, *obj.Key)
	}

	return
}

func FilterObjectAttributes(attrs map[s3response.ObjectAttributes]struct{}, output s3response.GetObjectAttributesResponse) s3response.GetObjectAttributesResponse {
	// These properties shouldn't appear in the final response body
	output.LastModified = nil
	output.VersionId = nil
	output.DeleteMarker = nil

	if _, ok := attrs[s3response.ObjectAttributesEtag]; !ok {
		output.ETag = nil
	}
	if _, ok := attrs[s3response.ObjectAttributesObjectParts]; !ok {
		output.ObjectParts = nil
	}
	if _, ok := attrs[s3response.ObjectAttributesObjectSize]; !ok {
		output.ObjectSize = nil
	}
	if _, ok := attrs[s3response.ObjectAttributesStorageClass]; !ok {
		output.StorageClass = ""
	}
	if _, ok := attrs[s3response.ObjectAttributesChecksum]; !ok {
		output.Checksum = nil
	}

	return output
}

func ParseObjectAttributes(ctx *fiber.Ctx) (map[s3response.ObjectAttributes]struct{}, error) {
	attrs := map[s3response.ObjectAttributes]struct{}{}
	var err error
	for key, value := range ctx.Request().Header.All() {
		if string(key) == "X-Amz-Object-Attributes" {
			if len(value) == 0 {
				break
			}
			oattrs := strings.Split(string(value), ",")
			for _, a := range oattrs {
				attr := s3response.ObjectAttributes(a)
				if !attr.IsValid() {
					debuglogger.Logf("invalid object attribute: %v\n", attr)
					err = s3err.GetAPIError(s3err.ErrInvalidObjectAttributes)
					break
				}
				attrs[attr] = struct{}{}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	if len(attrs) == 0 {
		debuglogger.Logf("empty get object attributes")
		return nil, s3err.GetAPIError(s3err.ErrObjectAttributesInvalidHeader)
	}

	return attrs, nil
}

type objLockCfg struct {
	RetainUntilDate time.Time
	ObjectLockMode  types.ObjectLockMode
	LegalHoldStatus types.ObjectLockLegalHoldStatus
}

func ParsObjectLockHdrs(ctx *fiber.Ctx) (*objLockCfg, error) {
	legalHoldHdr := ctx.Get("X-Amz-Object-Lock-Legal-Hold")
	objLockModeHdr := ctx.Get("X-Amz-Object-Lock-Mode")
	objLockDate := ctx.Get("X-Amz-Object-Lock-Retain-Until-Date")

	if (objLockDate != "" && objLockModeHdr == "") || (objLockDate == "" && objLockModeHdr != "") {
		debuglogger.Logf("one of 2 required params is missing: (lock date): %v, (lock mode): %v\n", objLockDate, objLockModeHdr)
		return nil, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)
	}

	var retainUntilDate time.Time
	if objLockDate != "" {
		rDate, err := time.Parse(time.RFC3339, objLockDate)
		if err != nil {
			debuglogger.Logf("failed to parse retain until date: %v\n", err)
			return nil, s3err.GetAPIError(s3err.ErrInvalidRetainUntilDate)
		}
		if rDate.Before(time.Now()) {
			debuglogger.Logf("expired retain until date: %v\n", rDate.Format(time.RFC3339))
			return nil, s3err.GetAPIError(s3err.ErrPastObjectLockRetainDate)
		}
		retainUntilDate = rDate
	}

	objLockMode := types.ObjectLockMode(objLockModeHdr)

	if objLockMode != "" &&
		objLockMode != types.ObjectLockModeCompliance &&
		objLockMode != types.ObjectLockModeGovernance {
		debuglogger.Logf("invalid object lock mode: %v\n", objLockMode)
		return nil, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode)
	}

	legalHold := types.ObjectLockLegalHoldStatus(legalHoldHdr)

	if legalHold != "" && legalHold != types.ObjectLockLegalHoldStatusOff && legalHold != types.ObjectLockLegalHoldStatusOn {
		debuglogger.Logf("invalid object lock legal hold status: %v\n", legalHold)
		return nil, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus)
	}

	return &objLockCfg{
		RetainUntilDate: retainUntilDate,
		ObjectLockMode:  objLockMode,
		LegalHoldStatus: legalHold,
	}, nil
}

func IsValidOwnership(val types.ObjectOwnership) bool {
	switch val {
	case types.ObjectOwnershipBucketOwnerEnforced:
		return true
	case types.ObjectOwnershipBucketOwnerPreferred:
		return true
	case types.ObjectOwnershipObjectWriter:
		return true
	default:
		debuglogger.Logf("invalid object ownership: %v\n", val)
		return false
	}
}

type ChecksumValues map[types.ChecksumAlgorithm]string

// Headers concatinates checksum algorithm by prefixing each
// with 'x-amz-checksum-'
// e.g.
// "x-amz-checksum-crc64nvme, x-amz-checksum-sha1"
func (cv ChecksumValues) Headers() string {
	result := ""
	isFirst := false

	for key := range cv {
		if !isFirst {
			result += ", "
		}
		result += fmt.Sprintf("x-amz-checksum-%v", strings.ToLower(string(key)))
	}
	return result
}

// ParseCalculatedChecksumHeaders parses and validates x-amz-checksum-x header keys
// e.g x-amz-checksum-crc32, x-amz-checksum-sha256 ...
func ParseCalculatedChecksumHeaders(ctx *fiber.Ctx) (ChecksumValues, error) {
	checksums := ChecksumValues{}

	var hdrErr error
	// Parse and validate checksum headers
	for key, value := range ctx.Request().Header.All() {
		// only check the headers with 'X-Amz-Checksum-' prefix
		if !strings.HasPrefix(string(key), "X-Amz-Checksum-") {
			continue
		}
		//  "X-Amz-Checksum-Type" and "X-Amz-Checksum-Algorithm" aren't considered
		// as invalid values, even if the s3 action doesn't expect these headers
		switch string(key) {
		case "X-Amz-Checksum-Type", "X-Amz-Checksum-Algorithm":
			continue
		}

		algo := types.ChecksumAlgorithm(strings.ToUpper(strings.TrimPrefix(string(key), "X-Amz-Checksum-")))
		err := IsChecksumAlgorithmValid(algo)
		if err != nil {
			debuglogger.Logf("invalid checksum header: %s\n", key)
			hdrErr = s3err.GetAPIError(s3err.ErrInvalidChecksumHeader)
			break
		}

		checksums[algo] = string(value)
	}

	if hdrErr != nil {
		return checksums, hdrErr
	}

	if len(checksums) > 1 {
		debuglogger.Logf("multiple checksum headers provided: %v\n", checksums.Headers())
		return checksums, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)
	}

	return checksums, nil
}

// ParseCompleteMpChecksumHeaders parses and validates
// the 'CompleteMultipartUpload' x-amz-checksum-x headers
// by supporting both 'checksum' and 'checksum-<part_length>' formats
func ParseCompleteMpChecksumHeaders(ctx *fiber.Ctx) (ChecksumValues, error) {
	// first parse/validate 'x-amz-checksum-x' headers
	checksums, err := ParseCalculatedChecksumHeaders(ctx)
	if err != nil {
		return checksums, err
	}

	for al, val := range checksums {
		algo := strings.ToLower(string(al))
		if al != types.ChecksumAlgorithmCrc64nvme {
			chParts := strings.Split(val, "-")
			if len(chParts) > 2 {
				debuglogger.Logf("invalid checksum header: x-amz-checksum-%s: %s", algo, val)
				return checksums, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", algo))
			}
			if len(chParts) == 2 {
				_, err := strconv.ParseInt(chParts[1], 10, 32)
				if err != nil {
					debuglogger.Logf("invalid checksum header: x-amz-checksum-%s: %s", algo, val)
					return checksums, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", algo))
				}
				val = chParts[0]
			}
		}
		if !IsValidChecksum(val, al) {
			return checksums, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", algo))
		}
	}

	return checksums, nil
}

// ParseChecksumHeadersAndSdkAlgo parses/validates 'x-amz-sdk-checksum-algorithm' and
// 'x-amz-checksum-x' precalculated request headers
func ParseChecksumHeadersAndSdkAlgo(ctx *fiber.Ctx) (types.ChecksumAlgorithm, ChecksumValues, error) {
	sdkAlgorithm := types.ChecksumAlgorithm(strings.ToUpper(ctx.Get("X-Amz-Sdk-Checksum-Algorithm")))
	err := IsChecksumAlgorithmValid(sdkAlgorithm)
	if err != nil {
		debuglogger.Logf("invalid checksum algorithm: %v\n", sdkAlgorithm)
		return "", nil, err
	}

	checksums, err := ParseCalculatedChecksumHeaders(ctx)
	if err != nil {
		return sdkAlgorithm, checksums, err
	}

	trailer := strings.ToUpper(ctx.Get("X-Amz-Trailer"))

	if len(checksums) != 0 && trailer != "" {
		// both x-amz-trailer and one of x-amz-checksum-* is not allowed
		debuglogger.Logf("x-amz-checksum-* header is used with x-amz-trailer: trailer: %s", trailer)
		return sdkAlgorithm, checksums, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)
	}

	trailerAlgo := strings.TrimPrefix(trailer, "X-AMZ-CHECKSUM-")

	if sdkAlgorithm != "" {
		if len(checksums) == 0 && trailerAlgo == "" {
			// in case x-amz-sdk-algorithm is specified, but no corresponging
			// x-amz-checksum-* or x-amz-trailer is sent
			debuglogger.Logf("'x-amz-sdk-checksum-algorithm : %s' is used without corresponding x-amz-checksum-* header", sdkAlgorithm)
			return sdkAlgorithm, checksums, s3err.GetAPIError(s3err.ErrChecksumSDKAlgoMismatch)
		}

		if trailerAlgo != "" && string(sdkAlgorithm) != trailerAlgo {
			// x-amz-sdk-checksum-algorithm and x-amz-trailer should match
			debuglogger.Logf("x-amz-sdk-checksum-algorithm: (%s) and x-amz-trailer: (%s) doesn't match", sdkAlgorithm, trailerAlgo)
			return sdkAlgorithm, checksums, s3err.GetInvalidChecksumHeaderErr("x-amz-sdk-checksum-algorithm")
		}
	}

	if trailerAlgo != "" {
		sdkAlgorithm = types.ChecksumAlgorithm(trailerAlgo)
	}

	for al, val := range checksums {
		if !IsValidChecksum(val, al) {
			return sdkAlgorithm, checksums, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", strings.ToLower(string(al))))
		}

		// If any other checksum value is provided,
		// rather than x-amz-sdk-checksum-algorithm
		if sdkAlgorithm != "" && sdkAlgorithm != al {
			return sdkAlgorithm, checksums, s3err.GetInvalidChecksumHeaderErr("x-amz-sdk-checksum-algorithm")
		}
		sdkAlgorithm = al
	}

	return sdkAlgorithm, checksums, nil
}

var checksumLengths = map[types.ChecksumAlgorithm]int{
	types.ChecksumAlgorithmCrc32:     4,
	types.ChecksumAlgorithmCrc32c:    4,
	types.ChecksumAlgorithmCrc64nvme: 8,
	types.ChecksumAlgorithmSha1:      20,
	types.ChecksumAlgorithmSha256:    32,
}

func IsValidChecksum(checksum string, algorithm types.ChecksumAlgorithm) bool {
	decoded, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil {
		debuglogger.Logf("failed to parse checksum base64: %v\n", err)
		return false
	}

	expectedLength, exists := checksumLengths[algorithm]
	if !exists {
		debuglogger.Logf("unknown checksum algorithm: %v\n", algorithm)
		return false
	}

	isValid := len(decoded) == expectedLength
	if !isValid {
		debuglogger.Logf("decoded checksum length: (expected): %v, (got): %v\n", expectedLength, len(decoded))
	}

	return isValid
}

func IsChecksumAlgorithmValid(alg types.ChecksumAlgorithm) error {
	alg = types.ChecksumAlgorithm(strings.ToUpper(string(alg)))
	if alg != "" &&
		alg != types.ChecksumAlgorithmCrc32 &&
		alg != types.ChecksumAlgorithmCrc32c &&
		alg != types.ChecksumAlgorithmSha1 &&
		alg != types.ChecksumAlgorithmSha256 &&
		alg != types.ChecksumAlgorithmCrc64nvme {
		debuglogger.Logf("invalid checksum algorithm: %v\n", alg)
		return s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)
	}

	return nil
}

// Validates the provided checksum type
func IsChecksumTypeValid(t types.ChecksumType) error {
	if t != "" &&
		t != types.ChecksumTypeComposite &&
		t != types.ChecksumTypeFullObject {
		debuglogger.Logf("invalid checksum type: %v\n", t)
		return s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-type")
	}
	return nil
}

type checksumTypeSchema map[types.ChecksumType]struct{}
type checksumSchema map[types.ChecksumAlgorithm]checksumTypeSchema

// A table defining the checksum algorithm/type support
var checksumMap checksumSchema = checksumSchema{
	types.ChecksumAlgorithmCrc32: checksumTypeSchema{
		types.ChecksumTypeComposite:  struct{}{},
		types.ChecksumTypeFullObject: struct{}{},
		"":                           struct{}{},
	},
	types.ChecksumAlgorithmCrc32c: checksumTypeSchema{
		types.ChecksumTypeComposite:  struct{}{},
		types.ChecksumTypeFullObject: struct{}{},
		"":                           struct{}{},
	},
	types.ChecksumAlgorithmSha1: checksumTypeSchema{
		types.ChecksumTypeComposite: struct{}{},
		"":                          struct{}{},
	},
	types.ChecksumAlgorithmSha256: checksumTypeSchema{
		types.ChecksumTypeComposite: struct{}{},
		"":                          struct{}{},
	},
	types.ChecksumAlgorithmCrc64nvme: checksumTypeSchema{
		types.ChecksumTypeFullObject: struct{}{},
		"":                           struct{}{},
	},
	// Both could be empty
	"": checksumTypeSchema{
		"": struct{}{},
	},
}

// Checks if checksum type and algorithm are supported together
func checkChecksumTypeAndAlgo(algo types.ChecksumAlgorithm, t types.ChecksumType) error {
	typeSchema := checksumMap[algo]
	_, ok := typeSchema[t]
	if !ok {
		debuglogger.Logf("checksum type and algorithm mismatch: (type): %v, (algorithm): %v\n", t, algo)
		return s3err.GetChecksumSchemaMismatchErr(algo, t)
	}

	return nil
}

// Parses and validates the x-amz-checksum-algorithm and x-amz-checksum-type headers
func ParseCreateMpChecksumHeaders(ctx *fiber.Ctx) (types.ChecksumAlgorithm, types.ChecksumType, error) {
	algo := types.ChecksumAlgorithm(strings.ToUpper(ctx.Get("x-amz-checksum-algorithm")))
	if err := IsChecksumAlgorithmValid(algo); err != nil {
		return "", "", err
	}

	chType := types.ChecksumType(strings.ToUpper(ctx.Get("x-amz-checksum-type")))
	if err := IsChecksumTypeValid(chType); err != nil {
		return "", "", err
	}

	// Verify if checksum algorithm is provided, if
	// checksum type is specified
	if chType != "" && algo == "" {
		debuglogger.Logf("checksum type can only be used with checksum algorithm: (type): %v\n", chType)
		return algo, chType, s3err.GetAPIError(s3err.ErrChecksumTypeWithAlgo)
	}

	// Verify if the checksum type is supported for
	// the provided checksum algorithm
	if err := checkChecksumTypeAndAlgo(algo, chType); err != nil {
		return algo, chType, err
	}

	// x-amz-checksum-type defaults to COMPOSITE
	// if x-amz-checksum-algorithm is set except
	// for the CRC64NVME algorithm: it defaults to FULL_OBJECT
	if algo != "" && chType == "" {
		if algo == types.ChecksumAlgorithmCrc64nvme {
			chType = types.ChecksumTypeFullObject
		} else {
			chType = types.ChecksumTypeComposite
		}
	}

	return algo, chType, nil
}

// TagLimit specifies the allowed tag count in a tag set
type TagLimit int

const (
	// Tag limit for bucket tagging
	TagLimitBucket TagLimit = 50
	// Tag limit for object tagging
	TagLimitObject TagLimit = 10
)

// The tag key/value validation pattern comes from
// AWS S3 docs
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Tag.html
var tagRule = regexp.MustCompile(`^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$`)

// Parses and validates tagging
func ParseTagging(data []byte, limit TagLimit) (map[string]string, error) {
	var tagging s3response.TaggingInput
	err := xml.Unmarshal(data, &tagging)
	if err != nil {
		debuglogger.Logf("invalid taggging: %s", data)
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	tLen := len(tagging.TagSet.Tags)
	if tLen > int(limit) {
		switch limit {
		case TagLimitObject:
			debuglogger.Logf("bucket tagging length exceeds %v: %v", limit, tLen)
			return nil, s3err.GetAPIError(s3err.ErrObjectTaggingLimited)
		case TagLimitBucket:
			debuglogger.Logf("object tagging length exceeds %v: %v", limit, tLen)
			return nil, s3err.GetAPIError(s3err.ErrBucketTaggingLimited)
		}
	}

	tagSet := make(map[string]string, tLen)

	for _, tag := range tagging.TagSet.Tags {
		// validate tag key length
		if len(tag.Key) == 0 || len(tag.Key) > 128 {
			debuglogger.Logf("tag key should 0 < tag.Key <= 128, key: %v", tag.Key)
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)
		}

		// validate tag key string chars
		if !tagRule.MatchString(tag.Key) {
			debuglogger.Logf("invalid tag key: %s", tag.Key)
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)
		}

		// validate tag value length
		if len(tag.Value) > 256 {
			debuglogger.Logf("invalid long tag value: (length): %v, (value): %v", len(tag.Value), tag.Value)
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)
		}

		// validate tag value string chars
		if !tagRule.MatchString(tag.Value) {
			debuglogger.Logf("invalid tag value: %s", tag.Value)
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)
		}

		// make sure there are no duplicate keys
		_, ok := tagSet[tag.Key]
		if ok {
			debuglogger.Logf("duplicate tag key: %v", tag.Key)
			return nil, s3err.GetAPIError(s3err.ErrDuplicateTagKey)
		}

		tagSet[tag.Key] = tag.Value
	}

	return tagSet, nil
}

// Returns the provided string pointer
func GetStringPtr(str string) *string {
	if str == "" {
		return nil
	}

	return &str
}

// Converts any type to a string pointer
func ConvertToStringPtr[T any](val T) *string {
	str := fmt.Sprint(val)
	if str == "" {
		return nil
	}
	return &str
}

// Converst any pointer to a string pointer
func ConvertPtrToStringPtr[T any](val *T) *string {
	if val == nil {
		return nil
	}
	str := fmt.Sprint(*val)
	return &str
}

// Formats the date with the given formatting and returns a string pointer
func FormatDatePtrToString(date *time.Time, format string) *string {
	if date == nil {
		return nil
	}
	if date.IsZero() {
		return nil
	}

	formatted := date.UTC().Format(format)
	return &formatted
}

// GetInt64 returns the value of int64 pointer
func GetInt64(n *int64) int64 {
	if n == nil {
		return 0
	}

	return *n
}

// ValidateCopySource parses and validates the copy-source
func ValidateCopySource(copysource string) error {
	var err error
	copysource, err = url.QueryUnescape(copysource)
	if err != nil {
		debuglogger.Logf("invalid copy source encoding: %s", copysource)
		return s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding)
	}

	bucket, rest, _ := strings.Cut(copysource, "/")
	if !IsValidBucketName(bucket) {
		debuglogger.Logf("invalid copy source bucket: %s", bucket)
		return s3err.GetAPIError(s3err.ErrInvalidCopySourceBucket)
	}

	// cut till the versionId as it's the only query param
	// that is recognized in copy source
	object, versionId, _ := strings.Cut(rest, "?versionId=")

	// objects containing '../', '...../' ... are considered valid in AWS
	// but for the security purposes these should be considered as invalid
	// in the gateway
	if !IsObjectNameValid(object) {
		debuglogger.Logf("invalid copy source object: %s", object)
		return s3err.GetAPIError(s3err.ErrInvalidCopySourceObject)
	}

	// validate the versionId
	err = ValidateVersionId(versionId)
	if err != nil {
		return err
	}

	return nil
}

// GetQueryParam returns a pointer to the query parameter value if it exists
func GetQueryParam(ctx *fiber.Ctx, key string) *string {
	value := ctx.Query(key)
	if value == "" {
		return nil
	}
	return &value
}

// ApplyOverride returns the override value if it exists and status is 200, otherwise returns original
func ApplyOverride(original, override *string) *string {
	if override != nil {
		return override
	}
	return original
}

// ValidateVersionId check if the input versionId is 'ulid' compatible
func ValidateVersionId(versionId string) error {
	if versionId == "" || versionId == "null" {
		return nil
	}
	_, err := ulid.Parse(versionId)
	if err != nil {
		debuglogger.Logf("invalid versionId: %s", versionId)
		return s3err.GetAPIError(s3err.ErrInvalidVersionId)
	}

	return nil
}

// GenerateObjectLocation generates the object location path-styled or host-styled
// depending on the gateway configuration
func GenerateObjectLocation(ctx *fiber.Ctx, virtualDomain, bucket, object string) string {
	scheme := ctx.Protocol()
	host := ctx.Hostname()

	// escape the object name
	obj := url.PathEscape(object)

	if virtualDomain != "" && strings.Contains(host, virtualDomain) {
		// the host already contains the bucket name
		return fmt.Sprintf("%s://%s/%s", scheme, host, obj)
	}

	return fmt.Sprintf(
		"%s://%s/%s/%s",
		scheme,
		host,
		bucket,
		obj,
	)
}
