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
)

// ParseObjectRange parses input range header and returns startoffset, length, isValid
// and error. If no endoffset specified, then length is set to the object size
// for invalid inputs, it returns no error, but isValid=false
// `InvalidRange` error is returnd, only if startoffset is greater than the object size
func ParseObjectRange(size int64, acceptRange string) (int64, int64, bool, error) {
	if acceptRange == "" {
		return 0, size, false, nil
	}

	rangeKv := strings.Split(acceptRange, "=")

	if len(rangeKv) != 2 {
		return 0, size, false, nil
	}

	if rangeKv[0] != "bytes" {
		return 0, size, false, nil
	}

	bRange := strings.Split(rangeKv[1], "-")
	if len(bRange) != 2 {
		return 0, size, false, nil
	}

	startOffset, err := strconv.ParseInt(bRange[0], 10, 64)
	if err != nil && bRange[0] != "" {
		return 0, size, false, nil
	}

	if bRange[1] == "" {
		if bRange[0] == "" {
			return 0, size, false, nil
		}
		if startOffset >= size {
			return 0, 0, false, errInvalidRange
		}
		return startOffset, size - startOffset, true, nil
	}

	endOffset, err := strconv.ParseInt(bRange[1], 10, 64)
	if err != nil {
		return 0, size, false, nil
	}

	if startOffset > endOffset {
		return 0, size, false, nil
	}

	// for ranges like 'bytes=-100' return the last bytes specified with 'endOffset'
	if bRange[0] == "" {
		endOffset = min(endOffset, size)
		return size - endOffset, endOffset, true, nil
	}

	if startOffset >= size {
		return 0, 0, false, errInvalidRange
	}

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
		return "", "", "", s3err.GetAPIError(s3err.ErrInvalidCopySource)
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

var validTagComponent = regexp.MustCompile(`^[a-zA-Z0-9:/_.\-+ ]+$`)

// isValidTagComponent matches strings which contain letters, decimal digits,
// and special chars: '/', '_', '-', '+', '.', ' ' (space)
func isValidTagComponent(str string) bool {
	if str == "" {
		return true
	}
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
