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
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const (
	// this is the media type for directories in AWS and Nextcloud
	DirContentType     = "application/x-directory"
	DefaultContentType = "binary/octet-stream"
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

var (
	errInvalidRange = s3err.GetAPIError(s3err.ErrInvalidRange)
)

// ParseRange parses input range header and returns startoffset, length, and
// error. If no endoffset specified, then length is set to -1.
func ParseRange(size int64, acceptRange string) (int64, int64, error) {
	if acceptRange == "" {
		return 0, size, nil
	}

	rangeKv := strings.Split(acceptRange, "=")

	if len(rangeKv) < 2 {
		return 0, 0, errInvalidRange
	}

	bRange := strings.Split(rangeKv[1], "-")
	if len(bRange) < 1 || len(bRange) > 2 {
		return 0, 0, errInvalidRange
	}

	startOffset, err := strconv.ParseInt(bRange[0], 10, 64)
	if err != nil {
		return 0, 0, errInvalidRange
	}

	endOffset := int64(-1)
	if len(bRange) == 1 || bRange[1] == "" {
		return startOffset, endOffset, nil
	}

	endOffset, err = strconv.ParseInt(bRange[1], 10, 64)
	if err != nil {
		return 0, 0, errInvalidRange
	}

	if endOffset < startOffset {
		return 0, 0, errInvalidRange
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

func CreateExceedingRangeErr(objSize int64) s3err.APIError {
	return s3err.APIError{
		Code:           "InvalidArgument",
		Description:    fmt.Sprintf("Range specified is not valid for source object of size: %d", objSize),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func GetMultipartMD5(parts []types.CompletedPart) string {
	var partsEtagBytes []byte
	for _, part := range parts {
		partsEtagBytes = append(partsEtagBytes, getEtagBytes(*part.ETag)...)
	}
	s3MD5 := fmt.Sprintf("%s-%d", md5String(partsEtagBytes), len(parts))
	return s3MD5
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
