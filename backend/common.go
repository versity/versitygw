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

package backend

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const (
	// this is the media type for directories in AWS and Nextcloud
	DirContentType     = "application/x-directory"
	DefaultContentType = "binary/octet-stream"

	// this is the minimum allowed size for mp parts
	MinPartSize = 5 * 1024 * 1024
)

func IsValidBucketName(name string) bool { return true }

type ByBucketName []s3response.ListAllMyBucketsEntry

func (d ByBucketName) Len() int           { return len(d) }
func (d ByBucketName) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d ByBucketName) Less(i, j int) bool { return d[i].Name < d[j].Name }

type ByObjectName []types.Object

func (d ByObjectName) Len() int           { return len(d) }
func (d ByObjectName) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d ByObjectName) Less(i, j int) bool { return *d[i].Key < *d[j].Key }

func GetPtrFromString(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

func GetStringFromPtr(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func GetTimePtr(t time.Time) *time.Time {
	return &t
}

func TrimEtag(etag *string) *string {
	if etag == nil {
		return nil
	}

	return GetPtrFromString(strings.Trim(*etag, "\""))
}

var (
	errInvalidRange           = s3err.GetAPIError(s3err.ErrInvalidRange)
	errInvalidCopySourceRange = s3err.GetAPIError(s3err.ErrInvalidCopySourceRange)
	errPreconditionFailed     = s3err.GetAPIError(s3err.ErrPreconditionFailed)
	errNotModified            = s3err.GetAPIError(s3err.ErrNotModified)
)

// ParseObjectRange parses input range header and returns startoffset, length, isValid
// and error. If no endoffset specified, then length is set to the object size
// for invalid inputs, it returns no error, but isValid=false
// `InvalidRange` error is returnd, only if startoffset is greater than the object size
func ParseObjectRange(size int64, acceptRange string) (int64, int64, bool, error) {
	// Return full object (invalid range, no error) if header empty
	if acceptRange == "" {
		return 0, size, false, nil
	}

	rangeKv := strings.Split(acceptRange, "=")
	if len(rangeKv) != 2 {
		return 0, size, false, nil
	}
	if rangeKv[0] != "bytes" { // unsupported unit -> ignore
		return 0, size, false, nil
	}

	bRange := strings.Split(rangeKv[1], "-")
	if len(bRange) != 2 { // malformed / multi-range
		return 0, size, false, nil
	}

	// Parse start; empty start indicates a suffix-byte-range-spec (e.g. bytes=-100)
	startOffset, err := strconv.ParseInt(bRange[0], 10, strconv.IntSize)
	if startOffset > int64(math.MaxInt) || startOffset < int64(math.MinInt) {
		return 0, size, false, errInvalidRange
	}
	if err != nil && bRange[0] != "" { // invalid numeric start (non-empty) -> ignore range
		return 0, size, false, nil
	}

	// If end part missing (e.g. bytes=100-)
	if bRange[1] == "" {
		if bRange[0] == "" { // bytes=- (meaningless) -> ignore
			return 0, size, false, nil
		}
		// start beyond or at size is unsatisfiable -> error (RequestedRangeNotSatisfiable)
		if startOffset >= size {
			return 0, 0, false, errInvalidRange
		}
		// bytes=100- => from start to end
		return startOffset, size - startOffset, true, nil
	}

	endOffset, err := strconv.ParseInt(bRange[1], 10, strconv.IntSize)
	if endOffset > int64(math.MaxInt) {
		return 0, size, false, errInvalidRange
	}
	if err != nil { // invalid numeric end -> ignore range
		return 0, size, false, nil
	}

	// Suffix range handling (bRange[0] == "")
	if bRange[0] == "" {
		// Disallow -0 (always unsatisfiable)
		if endOffset == 0 {
			return 0, 0, false, errInvalidRange
		}
		// For zero-sized objects any positive suffix is treated as invalid (ignored, no error)
		if size == 0 {
			return 0, size, false, nil
		}
		// Clamp to object size (request more bytes than exist -> entire object)
		endOffset = min(endOffset, size)
		return size - endOffset, endOffset, true, nil
	}

	// Normal range (start-end)
	if startOffset > endOffset { // start > end -> ignore
		return 0, size, false, nil
	}
	// Start beyond or at end of object -> error
	if startOffset >= size {
		return 0, 0, false, errInvalidRange
	}
	// Adjust end beyond object size (trim)
	if endOffset >= size {
		endOffset = size - 1
	}
	return startOffset, endOffset - startOffset + 1, true, nil
}

// ParseCopySourceRange parses input range header and returns startoffset, length
// and error. If no endoffset specified, then length is set to the object size
func ParseCopySourceRange(size int64, acceptRange string) (int64, int64, error) {
	if acceptRange == "" {
		return 0, size, nil
	}

	rangeKv := strings.Split(acceptRange, "=")

	if len(rangeKv) != 2 {
		return 0, 0, errInvalidCopySourceRange
	}

	if rangeKv[0] != "bytes" {
		return 0, 0, errInvalidCopySourceRange
	}

	bRange := strings.Split(rangeKv[1], "-")
	if len(bRange) != 2 {
		return 0, 0, errInvalidCopySourceRange
	}

	startOffset, err := strconv.ParseInt(bRange[0], 10, 64)
	if err != nil {
		return 0, 0, errInvalidCopySourceRange
	}

	if startOffset >= size {
		return 0, 0, s3err.CreateExceedingRangeErr(size)
	}

	if bRange[1] == "" {
		return startOffset, size - startOffset + 1, nil
	}

	endOffset, err := strconv.ParseInt(bRange[1], 10, 64)
	if err != nil {
		return 0, 0, errInvalidCopySourceRange
	}

	if endOffset < startOffset {
		return 0, 0, errInvalidCopySourceRange
	}

	if endOffset >= size {
		return 0, 0, s3err.CreateExceedingRangeErr(size)
	}

	return startOffset, endOffset - startOffset + 1, nil
}

// ParseCopySource parses x-amz-copy-source header and returns source bucket,
// source object, versionId, error respectively
func ParseCopySource(copySourceHeader string) (string, string, string, error) {
	if copySourceHeader[0] == '/' {
		copySourceHeader = copySourceHeader[1:]
	}

	var copySource, versionId string
	i := strings.LastIndex(copySourceHeader, "?versionId=")
	if i == -1 {
		copySource = copySourceHeader
	} else {
		copySource = copySourceHeader[:i]
		versionId = copySourceHeader[i+11:]
	}

	srcBucket, srcObject, ok := strings.Cut(copySource, "/")
	if !ok {
		return "", "", "", s3err.GetAPIError(s3err.ErrInvalidCopySourceBucket)
	}

	return srcBucket, srcObject, versionId, nil
}

// ParseObjectTags parses the url encoded input string into
// map[string]string with unescaped key/value pair
func ParseObjectTags(tagging string) (map[string]string, error) {
	if tagging == "" {
		return nil, nil
	}

	tagSet := make(map[string]string)

	for tagging != "" {
		var tag string
		tag, tagging, _ = strings.Cut(tagging, "&")
		// if 'tag' before the first appearance of '&' is empty continue
		if tag == "" {
			continue
		}

		key, value, found := strings.Cut(tag, "=")
		// if key is empty, but "=" is present, return invalid url ecnoding err
		if found && key == "" {
			return nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)
		}

		// return invalid tag key, if the key is longer than 128
		if len(key) > 128 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)
		}

		// return invalid tag value, if tag value is longer than 256
		if len(value) > 256 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)
		}

		// query unescape tag key
		key, err := url.QueryUnescape(key)
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)
		}

		// query unescape tag value
		value, err = url.QueryUnescape(value)
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)
		}

		// check tag key to be valid
		if !isValidTagComponent(key) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)
		}

		// check tag value to be valid
		if !isValidTagComponent(value) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)
		}

		// duplicate keys are not allowed: return invalid url encoding err
		_, ok := tagSet[key]
		if ok {
			return nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)
		}

		tagSet[key] = value
	}

	return tagSet, nil
}

// ParseCreateBucketTags parses and validates the bucket
// tagging from CreateBucket input
func ParseCreateBucketTags(tagging []types.Tag) (map[string]string, error) {
	if len(tagging) == 0 {
		return nil, nil
	}

	tagset := make(map[string]string, len(tagging))

	if len(tagging) > 50 {
		return nil, s3err.GetAPIError(s3err.ErrBucketTaggingLimited)
	}

	for _, tag := range tagging {
		// validate tag key length
		key := GetStringFromPtr(tag.Key)
		if len(key) == 0 || len(key) > 128 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)
		}

		// validate tag key string chars
		if !isValidTagComponent(key) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)
		}

		// validate tag value length
		value := GetStringFromPtr(tag.Value)
		if len(value) > 256 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)
		}

		// validate tag value string chars
		if !isValidTagComponent(value) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)
		}

		// make sure there are no duplicate keys
		_, ok := tagset[key]
		if ok {
			return nil, s3err.GetAPIError(s3err.ErrDuplicateTagKey)
		}

		tagset[key] = value
	}

	return tagset, nil
}

// tag component (key/value) name rule regexp
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Tag.html
var validTagComponent = regexp.MustCompile(`^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$`)

// isValidTagComponent validates the tag component(key/value) name
func isValidTagComponent(str string) bool {
	return validTagComponent.Match([]byte(str))
}

func GetMultipartMD5(parts []types.CompletedPart) string {
	var partsEtagBytes []byte
	for _, part := range parts {
		partsEtagBytes = append(partsEtagBytes, getEtagBytes(*part.ETag)...)
	}

	return fmt.Sprintf("\"%s-%d\"", md5String(partsEtagBytes), len(parts))
}

func getEtagBytes(etag string) []byte {
	decode, err := hex.DecodeString(strings.ReplaceAll(etag, string('"'), ""))
	if err != nil {
		return []byte(etag)
	}
	return decode
}

func md5String(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

type FileSectionReadCloser struct {
	R io.Reader
	F *os.File
}

func (f *FileSectionReadCloser) Read(p []byte) (int, error) {
	return f.R.Read(p)
}

func (f *FileSectionReadCloser) Close() error {
	return f.F.Close()
}

// MoveFile moves a file from source to destination.
func MoveFile(source, destination string, perm os.FileMode) error {
	// We use Rename as the atomic operation for object puts. The upload is
	// written to a temp file to not conflict with any other simultaneous
	// uploads. The final operation is to move the temp file into place for
	// the object. This ensures the object semantics of last upload completed
	// wins and is not some combination of writes from simultaneous uploads.
	err := os.Rename(source, destination)
	if err == nil || !errors.Is(err, syscall.EXDEV) {
		return err
	}

	// Rename can fail if the source and destination are not on the same
	// filesystem. The fallback is to copy the file and then remove the source.
	// We need to be careful that the desination does not exist before copying
	// to prevent any other simultaneous writes to the file.
	sourceFile, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer sourceFile.Close()

	var destFile *os.File
	for {
		destFile, err = os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				if removeErr := os.Remove(destination); removeErr != nil {
					return fmt.Errorf("remove existing destination: %w", removeErr)
				}
				continue
			}
			return fmt.Errorf("create destination: %w", err)
		}
		break
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	err = os.Remove(source)
	if err != nil {
		return fmt.Errorf("remove source: %w", err)
	}

	return nil
}

// GenerateEtag generates a new quoted etag from the provided hash.Hash
func GenerateEtag(h hash.Hash) string {
	dataSum := h.Sum(nil)
	return fmt.Sprintf("\"%s\"", hex.EncodeToString(dataSum[:]))
}

// AreEtagsSame compares 2 etags by ignoring quotes
func AreEtagsSame(e1, e2 string) bool {
	return strings.Trim(e1, `"`) == strings.Trim(e2, `"`)
}

func getBoolPtr(b bool) *bool {
	return &b
}

type PreConditions struct {
	IfMatch       *string
	IfNoneMatch   *string
	IfModSince    *time.Time
	IfUnmodeSince *time.Time
}

// EvaluatePreconditions takes the object ETag, the last modified time and
// evaluates the read preconditions:
// - if-match,
// - if-none-match
// - if-modified-since
// - if-unmodified-since
// if-match and if-none-match are ETag comparisions
// if-modified-since and if-unmodified-since are last modifed time comparisons
func EvaluatePreconditions(etag string, modTime time.Time, preconditions PreConditions) error {
	if preconditions.IfMatch == nil && preconditions.IfNoneMatch == nil && preconditions.IfModSince == nil && preconditions.IfUnmodeSince == nil {
		return nil
	}

	etag = strings.Trim(etag, `"`)

	// convert all conditions to *bool to evaluate the conditions
	var ifMatch, ifNoneMatch, ifModSince, ifUnmodeSince *bool
	if preconditions.IfMatch != nil {
		ifMatch = getBoolPtr(*preconditions.IfMatch == etag)
	}
	if preconditions.IfNoneMatch != nil {
		ifNoneMatch = getBoolPtr(*preconditions.IfNoneMatch != etag)
	}
	if preconditions.IfModSince != nil {
		ifModSince = getBoolPtr(preconditions.IfModSince.UTC().Before(modTime.UTC()))
	}
	if preconditions.IfUnmodeSince != nil {
		ifUnmodeSince = getBoolPtr(preconditions.IfUnmodeSince.UTC().After(modTime.UTC()))
	}

	if ifMatch != nil {
		// if `if-match` doesn't matches, return PreconditionFailed
		if !*ifMatch {
			return errPreconditionFailed
		}

		// if-match matches
		if *ifMatch {
			if ifNoneMatch != nil {
				// if `if-none-match` doesn't match return NotModified
				if !*ifNoneMatch {
					return errNotModified
				}

				// if both `if-match` and `if-none-match` match, return no error
				return nil
			}

			// if `if-match` matches but `if-modified-since` is false return NotModified
			if ifModSince != nil && !*ifModSince {
				return errNotModified
			}

			// ignore `if-unmodified-since` as `if-match` is true
			return nil
		}
	}

	if ifNoneMatch != nil {
		if *ifNoneMatch {
			// if `if-none-match` is true, but `if-unmodified-since` is false
			// return PreconditionFailed
			if ifUnmodeSince != nil && !*ifUnmodeSince {
				return errPreconditionFailed
			}

			// ignore `if-modified-since` as `if-none-match` is true
			return nil
		} else {
			// if `if-none-match` is false and `if-unmodified-since` is false
			// return PreconditionFailed
			if ifUnmodeSince != nil && !*ifUnmodeSince {
				return errPreconditionFailed
			}

			// in all other cases when `if-none-match` is false return NotModified
			return errNotModified
		}
	}

	if ifModSince != nil && !*ifModSince {
		// if both `if-modified-since` and `if-unmodified-since` are false
		// return PreconditionFailed
		if ifUnmodeSince != nil && !*ifUnmodeSince {
			return errPreconditionFailed
		}

		// if only `if-modified-since` is false, return NotModified
		return errNotModified
	}

	// if `if-unmodified-since` is false return PreconditionFailed
	if ifUnmodeSince != nil && !*ifUnmodeSince {
		return errPreconditionFailed
	}

	return nil
}

// EvaluateMatchPreconditions evaluates if-match and if-none-match preconditions
func EvaluateMatchPreconditions(etag string, ifMatch, ifNoneMatch *string) error {
	etag = strings.Trim(etag, `"`)
	if ifMatch != nil && *ifMatch != etag {
		return errPreconditionFailed
	}
	if ifNoneMatch != nil && *ifNoneMatch == etag {
		return errPreconditionFailed
	}

	return nil
}

// EvaluateObjectPutPreconditions evaluates if-match and if-none-match preconditions
// for object PUT(PutObject, CompleteMultipartUpload) actions
func EvaluateObjectPutPreconditions(etag string, ifMatch, ifNoneMatch *string, objExists bool) error {
	if ifMatch == nil && ifNoneMatch == nil {
		return nil
	}

	if ifNoneMatch != nil && *ifNoneMatch != "*" {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}

	if ifNoneMatch != nil && ifMatch != nil {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}

	if ifNoneMatch != nil && objExists {
		return s3err.GetAPIError(s3err.ErrPreconditionFailed)
	}

	if ifMatch != nil && !objExists {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	etag = strings.Trim(etag, `"`)

	if ifMatch != nil && *ifMatch != etag {
		return s3err.GetAPIError(s3err.ErrPreconditionFailed)
	}

	return nil
}

type ObjectDeletePreconditions struct {
	IfMatch            *string
	IfMatchLastModTime *time.Time
	IfMatchSize        *int64
}

// EvaluateObjectDeletePreconditions evaluates preconditions for DeleteObject
func EvaluateObjectDeletePreconditions(etag string, modTime time.Time, size int64, preconditions ObjectDeletePreconditions) error {
	ifMatch := preconditions.IfMatch
	if ifMatch != nil && *ifMatch != etag {
		return errPreconditionFailed
	}

	ifMatchTime := preconditions.IfMatchLastModTime
	if ifMatchTime != nil && ifMatchTime.Unix() != modTime.Unix() {
		return errPreconditionFailed
	}

	ifMatchSize := preconditions.IfMatchSize
	if ifMatchSize != nil && *ifMatchSize != size {
		return errPreconditionFailed
	}

	return nil
}

// IsValidDirectoryName returns true if the string is a valid name
// for a directory
func IsValidDirectoryName(name string) bool {
	// directories may not contain a path separator
	if strings.ContainsRune(name, '/') {
		return false
	}

	// directories may not contain null character
	if strings.ContainsRune(name, 0) {
		return false
	}

	return true
}
