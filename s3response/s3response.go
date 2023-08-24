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

package s3response

import (
	"encoding/xml"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Part describes part metadata.
type Part struct {
	PartNumber   int
	LastModified string
	ETag         string
	Size         int64
}

// ListPartsResponse - s3 api list parts response.
type ListPartsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult" json:"-"`

	Bucket   string
	Key      string
	UploadID string `xml:"UploadId"`

	Initiator Initiator
	Owner     Owner

	// The class of storage used to store the object.
	StorageClass string

	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int
	IsTruncated          bool

	// List of parts.
	Parts []Part `xml:"Part"`
}

// ListMultipartUploadsResponse - s3 api list multipart uploads response.
type ListMultipartUploadsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult" json:"-"`

	Bucket             string
	KeyMarker          string
	UploadIDMarker     string `xml:"UploadIdMarker"`
	NextKeyMarker      string
	NextUploadIDMarker string `xml:"NextUploadIdMarker"`
	Delimiter          string
	Prefix             string
	EncodingType       string `xml:"EncodingType,omitempty"`
	MaxUploads         int
	IsTruncated        bool

	// List of pending uploads.
	Uploads []Upload `xml:"Upload"`

	// Delimed common prefixes.
	CommonPrefixes []CommonPrefix
}

// Upload desribes in progress multipart upload
type Upload struct {
	Key          string
	UploadID     string `xml:"UploadId"`
	Initiator    Initiator
	Owner        Owner
	StorageClass string
	Initiated    string
}

// CommonPrefix ListObjectsResponse common prefixes (directory abstraction)
type CommonPrefix struct {
	Prefix string
}

// Initiator same fields as Owner
type Initiator Owner

// Owner bucket ownership
type Owner struct {
	ID          string
	DisplayName string
}

type Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type TagSet struct {
	Tags []Tag `xml:"Tag"`
}

type Tagging struct {
	TagSet TagSet `xml:"TagSet"`
}

type DeleteObjects struct {
	Objects []types.ObjectIdentifier `xml:"Object"`
}

type DeleteObjectsResult struct {
	Deleted []types.DeletedObject
	Error   []types.Error
}
type SelectObjectContentPayload struct {
	Expression          *string
	ExpressionType      types.ExpressionType
	RequestProgress     *types.RequestProgress
	InputSerialization  *types.InputSerialization
	OutputSerialization *types.OutputSerialization
	ScanRange           *types.ScanRange
}

type SelectObjectContentResult struct {
	Records  *types.RecordsEvent
	Stats    *types.StatsEvent
	Progress *types.ProgressEvent
	Cont     *string
	End      *string
}
