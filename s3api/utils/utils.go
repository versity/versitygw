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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/encoding/httpbinding"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	bucketNameRegexp   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+[a-z0-9]$`)
	bucketNameIpRegexp = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
)

const (
	upperhex = "0123456789ABCDEF"
)

func GetUserMetaData(headers *fasthttp.RequestHeader) (metadata map[string]string) {
	metadata = make(map[string]string)
	headers.DisableNormalizing()
	headers.VisitAllInOrder(func(key, value []byte) {
		hKey := string(key)
		if strings.HasPrefix(strings.ToLower(hKey), "x-amz-meta-") {
			trimmedKey := hKey[11:]
			headerValue := string(value)
			metadata[trimmedKey] = headerValue
		}
	})
	headers.EnableNormalizing()

	return
}

func createHttpRequestFromCtx(ctx *fiber.Ctx, signedHdrs []string, contentLength int64) (*http.Request, error) {
	req := ctx.Request()
	var body io.Reader
	if IsBigDataAction(ctx) {
		body = req.BodyStream()
	} else {
		body = bytes.NewReader(req.Body())
	}

	escapedURI := escapeOriginalURI(ctx)

	httpReq, err := http.NewRequest(string(req.Header.Method()), escapedURI, body)
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	// Set the request headers
	req.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

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

func createPresignedHttpRequestFromCtx(ctx *fiber.Ctx, signedHdrs []string, contentLength int64) (*http.Request, error) {
	req := ctx.Request()
	var body io.Reader
	if IsBigDataAction(ctx) {
		body = req.BodyStream()
	} else {
		body = bytes.NewReader(req.Body())
	}

	uri := string(ctx.Request().URI().Path())
	uri = httpbinding.EscapePath(uri, false)
	isFirst := true

	ctx.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
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
	})

	httpReq, err := http.NewRequest(string(req.Header.Method()), uri, body)
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}
	// Set the request headers
	req.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

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
		ctx.Response().Header.Set(fmt.Sprintf("X-Amz-Meta-%s", key), val)
	}
	ctx.Response().Header.EnableNormalizing()
}

func ParseUint(str string, debug bool) (int32, error) {
	if str == "" {
		return 1000, nil
	}
	num, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		if debug {
			debuglogger.Logf("invalid intager provided: %v\n", err)
		}
		return 1000, fmt.Errorf("invalid int: %w", err)
	}
	if num < 0 {
		if debug {
			debuglogger.Logf("negative intager provided: %v\n", num)
		}
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

func IsValidBucketName(bucket string, debug bool) bool {
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

func IsBigDataAction(ctx *fiber.Ctx) bool {
	if ctx.Method() == http.MethodPut && len(strings.Split(ctx.Path(), "/")) >= 3 {
		if !ctx.Request().URI().QueryArgs().Has("tagging") && ctx.Get("X-Amz-Copy-Source") == "" && !ctx.Request().URI().QueryArgs().Has("acl") {
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

func ParseObjectAttributes(ctx *fiber.Ctx, debug bool) (map[s3response.ObjectAttributes]struct{}, error) {
	attrs := map[s3response.ObjectAttributes]struct{}{}
	var err error
	ctx.Request().Header.VisitAll(func(key, value []byte) {
		if string(key) == "X-Amz-Object-Attributes" {
			if len(value) == 0 {
				return
			}
			oattrs := strings.Split(string(value), ",")
			for _, a := range oattrs {
				attr := s3response.ObjectAttributes(a)
				if !attr.IsValid() {
					if debug {
						debuglogger.Logf("invalid object attribute: %v\n", attr)
					}
					err = s3err.GetAPIError(s3err.ErrInvalidObjectAttributes)
					break
				}
				attrs[attr] = struct{}{}
			}
		}
	})

	if err != nil {
		return nil, err
	}

	if len(attrs) == 0 {
		if debug {
			debuglogger.Logf("empty get object attributes")
		}
		return nil, s3err.GetAPIError(s3err.ErrObjectAttributesInvalidHeader)
	}

	return attrs, nil
}

type objLockCfg struct {
	RetainUntilDate time.Time
	ObjectLockMode  types.ObjectLockMode
	LegalHoldStatus types.ObjectLockLegalHoldStatus
}

func ParsObjectLockHdrs(ctx *fiber.Ctx, debug bool) (*objLockCfg, error) {
	legalHoldHdr := ctx.Get("X-Amz-Object-Lock-Legal-Hold")
	objLockModeHdr := ctx.Get("X-Amz-Object-Lock-Mode")
	objLockDate := ctx.Get("X-Amz-Object-Lock-Retain-Until-Date")

	if (objLockDate != "" && objLockModeHdr == "") || (objLockDate == "" && objLockModeHdr != "") {
		if debug {
			debuglogger.Logf("one of 2 required params is missing: (lock date): %v, (lock mode): %v\n", objLockDate, objLockModeHdr)
		}
		return nil, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)
	}

	var retainUntilDate time.Time
	if objLockDate != "" {
		rDate, err := time.Parse(time.RFC3339, objLockDate)
		if err != nil {
			if debug {
				debuglogger.Logf("failed to parse retain until date: %v\n", err)
			}
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		if rDate.Before(time.Now()) {
			if debug {
				debuglogger.Logf("expired retain until date: %v\n", rDate.Format(time.RFC3339))
			}
			return nil, s3err.GetAPIError(s3err.ErrPastObjectLockRetainDate)
		}
		retainUntilDate = rDate
	}

	objLockMode := types.ObjectLockMode(objLockModeHdr)

	if objLockMode != "" &&
		objLockMode != types.ObjectLockModeCompliance &&
		objLockMode != types.ObjectLockModeGovernance {
		if debug {
			debuglogger.Logf("invalid object lock mode: %v\n", objLockMode)
		}
		return nil, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode)
	}

	legalHold := types.ObjectLockLegalHoldStatus(legalHoldHdr)

	if legalHold != "" && legalHold != types.ObjectLockLegalHoldStatusOff && legalHold != types.ObjectLockLegalHoldStatusOn {
		if debug {
			debuglogger.Logf("invalid object lock legal hold status: %v\n", legalHold)
		}
		return nil, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus)
	}

	return &objLockCfg{
		RetainUntilDate: retainUntilDate,
		ObjectLockMode:  objLockMode,
		LegalHoldStatus: legalHold,
	}, nil
}

func IsValidOwnership(val types.ObjectOwnership, debug bool) bool {
	switch val {
	case types.ObjectOwnershipBucketOwnerEnforced:
		return true
	case types.ObjectOwnershipBucketOwnerPreferred:
		return true
	case types.ObjectOwnershipObjectWriter:
		return true
	default:
		if debug {
			debuglogger.Logf("invalid object ownership: %v\n", val)
		}
		return false
	}
}

func escapeOriginalURI(ctx *fiber.Ctx) string {
	path := ctx.Path()

	// Escape the URI original path
	escapedURI := escapePath(path)

	// Add the URI query params
	query := string(ctx.Request().URI().QueryArgs().QueryString())
	if query != "" {
		escapedURI = escapedURI + "?" + query
	}

	return escapedURI
}

// Escapes the path string
// Most of the parts copied from std url
func escapePath(s string) string {
	hexCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			hexCount++
		}
	}

	if hexCount == 0 {
		return s
	}

	var buf [64]byte
	var t []byte

	required := len(s) + 2*hexCount
	if required <= len(buf) {
		t = buf[:required]
	} else {
		t = make([]byte, required)
	}

	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = upperhex[c>>4]
			t[j+2] = upperhex[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}

	return string(t)
}

// Checks if the character needs to be escaped
func shouldEscape(c byte) bool {
	if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
		return false
	}

	switch c {
	case '-', '_', '.', '~', '/':
		return false
	}

	return true
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

func ParseChecksumHeaders(ctx *fiber.Ctx, debug bool) (types.ChecksumAlgorithm, ChecksumValues, error) {
	sdkAlgorithm := types.ChecksumAlgorithm(strings.ToUpper(ctx.Get("X-Amz-Sdk-Checksum-Algorithm")))

	err := IsChecksumAlgorithmValid(sdkAlgorithm, debug)
	if err != nil {
		if debug {
			debuglogger.Logf("invalid checksum algorithm: %v\n", sdkAlgorithm)
		}
		return "", nil, err
	}

	checksums := ChecksumValues{}

	var hdrErr error
	// Parse and validate checksum headers
	ctx.Request().Header.VisitAll(func(key, value []byte) {
		// Skip `X-Amz-Checksum-Type` as it's a special header
		if hdrErr != nil || !strings.HasPrefix(string(key), "X-Amz-Checksum-") || string(key) == "X-Amz-Checksum-Type" {
			return
		}

		algo := types.ChecksumAlgorithm(strings.ToUpper(strings.TrimPrefix(string(key), "X-Amz-Checksum-")))
		err := IsChecksumAlgorithmValid(algo, debug)
		if err != nil {
			if debug {
				debuglogger.Logf("invalid checksum header: %s\n", key)
			}
			hdrErr = s3err.GetAPIError(s3err.ErrInvalidChecksumHeader)
			return
		}

		checksums[algo] = string(value)
	})

	if hdrErr != nil {
		return sdkAlgorithm, nil, hdrErr
	}

	if len(checksums) > 1 {
		if debug {
			debuglogger.Logf("multiple checksum headers provided: %v\n", checksums.Headers())
		}
		return sdkAlgorithm, checksums, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)
	}

	for al, val := range checksums {
		if !IsValidChecksum(val, al, debug) {
			return sdkAlgorithm, checksums, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", strings.ToLower(string(al))))
		}
		// If any other checksum value is provided,
		// rather than x-amz-sdk-checksum-algorithm
		if sdkAlgorithm != "" && sdkAlgorithm != al {
			return sdkAlgorithm, checksums, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)
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

func IsValidChecksum(checksum string, algorithm types.ChecksumAlgorithm, debug bool) bool {
	decoded, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil {
		if debug {
			debuglogger.Logf("failed to parse checksum base64: %v\n", err)
		}
		return false
	}

	expectedLength, exists := checksumLengths[algorithm]
	if !exists {
		if debug {
			debuglogger.Logf("unknown checksum algorithm: %v\n", algorithm)
		}
		return false
	}

	isValid := len(decoded) == expectedLength
	if !isValid && debug {
		debuglogger.Logf("decoded checksum length: (expected): %v, (got): %v\n", expectedLength, len(decoded))
	}

	return isValid
}

func IsChecksumAlgorithmValid(alg types.ChecksumAlgorithm, debug bool) error {
	alg = types.ChecksumAlgorithm(strings.ToUpper(string(alg)))
	if alg != "" &&
		alg != types.ChecksumAlgorithmCrc32 &&
		alg != types.ChecksumAlgorithmCrc32c &&
		alg != types.ChecksumAlgorithmSha1 &&
		alg != types.ChecksumAlgorithmSha256 &&
		alg != types.ChecksumAlgorithmCrc64nvme {
		if debug {
			debuglogger.Logf("invalid checksum algorithm: %v\n", alg)
		}
		return s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)
	}

	return nil
}

// Validates the provided checksum type
func IsChecksumTypeValid(t types.ChecksumType, debug bool) error {
	if t != "" &&
		t != types.ChecksumTypeComposite &&
		t != types.ChecksumTypeFullObject {
		if debug {
			debuglogger.Logf("invalid checksum type: %v\n", t)
		}
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
func checkChecksumTypeAndAlgo(algo types.ChecksumAlgorithm, t types.ChecksumType, debug bool) error {
	typeSchema := checksumMap[algo]
	_, ok := typeSchema[t]
	if !ok {
		if debug {
			debuglogger.Logf("checksum type and algorithm mismatch: (type): %v, (algorithm): %v\n", t, algo)
		}
		return s3err.GetChecksumSchemaMismatchErr(algo, t)
	}

	return nil
}

// Parses and validates the x-amz-checksum-algorithm and x-amz-checksum-type headers
func ParseCreateMpChecksumHeaders(ctx *fiber.Ctx, debug bool) (types.ChecksumAlgorithm, types.ChecksumType, error) {
	algo := types.ChecksumAlgorithm(ctx.Get("x-amz-checksum-algorithm"))
	if err := IsChecksumAlgorithmValid(algo, debug); err != nil {
		return "", "", err
	}

	chType := types.ChecksumType(ctx.Get("x-amz-checksum-type"))
	if err := IsChecksumTypeValid(chType, debug); err != nil {
		return "", "", err
	}

	// Verify if checksum algorithm is provided, if
	// checksum type is specified
	if chType != "" && algo == "" {
		if debug {
			debuglogger.Logf("checksum type can only be used with checksum algorithm: (type): %v\n", chType)
		}
		return algo, chType, s3err.GetAPIError(s3err.ErrChecksumTypeWithAlgo)
	}

	// Verify if the checksum type is supported for
	// the provided checksum algorithm
	if err := checkChecksumTypeAndAlgo(algo, chType, debug); err != nil {
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
