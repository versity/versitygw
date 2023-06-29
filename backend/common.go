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
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	// RFC3339TimeFormat RFC3339 time format
	RFC3339TimeFormat = "2006-01-02T15:04:05.999Z"
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

func GetStringPtr(s string) *string {
	return &s
}

func GetTimePtr(t time.Time) *time.Time {
	return &t
}

var (
	errInvalidRange = s3err.GetAPIError(s3err.ErrInvalidRequest)
)

// ParseRange parses input range header and returns startoffset, length, and
// error. If no endoffset specified, then length is set to -1.
func ParseRange(file fs.FileInfo, acceptRange string) (int64, int64, error) {
	if acceptRange == "" {
		return 0, file.Size(), nil
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

func GetMultipartMD5(parts []types.Part) string {
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
