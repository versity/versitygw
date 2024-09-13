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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const RFC3339TimeFormat = "2006-01-02T15:04:05.999Z"

// Part describes part metadata.
type Part struct {
	PartNumber   int
	LastModified time.Time
	ETag         string
	Size         int64
}

func (p Part) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Part
	aux := &struct {
		LastModified string `xml:"LastModified"`
		*Alias
	}{
		Alias: (*Alias)(&p),
	}

	aux.LastModified = p.LastModified.UTC().Format(RFC3339TimeFormat)

	return e.EncodeElement(aux, start)
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
	StorageClass types.StorageClass

	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int
	IsTruncated          bool

	// List of parts.
	Parts []Part `xml:"Part"`
}

type GetObjectAttributesResult struct {
	ETag         *string
	LastModified *time.Time
	ObjectSize   *int64
	StorageClass types.StorageClass
	VersionId    *string
	ObjectParts  *ObjectParts
}

func (r GetObjectAttributesResult) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias GetObjectAttributesResult
	aux := &struct {
		LastModified *string `xml:"LastModified"`
		*Alias
	}{
		Alias: (*Alias)(&r),
	}

	if r.LastModified != nil {
		formattedTime := r.LastModified.UTC().Format(RFC3339TimeFormat)
		aux.LastModified = &formattedTime
	}

	return e.EncodeElement(aux, start)
}

type ObjectParts struct {
	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int
	IsTruncated          bool
	Parts                []types.ObjectPart `xml:"Part"`
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

type ListObjectsResult struct {
	XMLName        xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult" json:"-"`
	Name           *string
	Prefix         *string
	Marker         *string
	NextMarker     *string
	MaxKeys        *int32
	Delimiter      *string
	IsTruncated    *bool
	Contents       []Object
	CommonPrefixes []types.CommonPrefix
	EncodingType   types.EncodingType
}

type ListObjectsV2Result struct {
	XMLName               xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult" json:"-"`
	Name                  *string
	Prefix                *string
	StartAfter            *string
	ContinuationToken     *string
	NextContinuationToken *string
	KeyCount              *int32
	MaxKeys               *int32
	Delimiter             *string
	IsTruncated           *bool
	Contents              []Object
	CommonPrefixes        []types.CommonPrefix
	EncodingType          types.EncodingType
}

type Object struct {
	ETag          *string
	Key           *string
	LastModified  *time.Time
	Owner         *types.Owner
	RestoreStatus *types.RestoreStatus
	Size          *int64
	StorageClass  types.ObjectStorageClass
}

func (o Object) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Object
	aux := &struct {
		LastModified *string `xml:"LastModified,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(&o),
	}

	if o.LastModified != nil {
		formattedTime := o.LastModified.UTC().Format(RFC3339TimeFormat)
		aux.LastModified = &formattedTime
	}

	return e.EncodeElement(aux, start)
}

// Upload describes in progress multipart upload
type Upload struct {
	Key          string
	UploadID     string `xml:"UploadId"`
	Initiator    Initiator
	Owner        Owner
	StorageClass types.StorageClass
	Initiated    time.Time
}

func (u Upload) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Upload
	aux := &struct {
		Initiated string `xml:"Initiated"`
		*Alias
	}{
		Alias: (*Alias)(&u),
	}

	aux.Initiated = u.Initiated.UTC().Format(RFC3339TimeFormat)

	return e.EncodeElement(aux, start)
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
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Tagging" json:"-"`
	TagSet  TagSet   `xml:"TagSet"`
}

type TaggingInput struct {
	TagSet TagSet `xml:"TagSet"`
}

type DeleteObjects struct {
	Objects []types.ObjectIdentifier `xml:"Object"`
}

type DeleteResult struct {
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
	Cont     *types.ContinuationEvent
	End      *types.EndEvent
}

type Bucket struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult" json:"-"`
	Owner   CanonicalUser
	Buckets ListAllMyBucketsList
}

type ListAllMyBucketsEntry struct {
	Name         string
	CreationDate time.Time
}

func (r ListAllMyBucketsEntry) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias ListAllMyBucketsEntry
	aux := &struct {
		CreationDate string `xml:"CreationDate"`
		*Alias
	}{
		Alias: (*Alias)(&r),
	}

	aux.CreationDate = r.CreationDate.UTC().Format(RFC3339TimeFormat)

	return e.EncodeElement(aux, start)
}

type ListAllMyBucketsList struct {
	Bucket []ListAllMyBucketsEntry
}

type CanonicalUser struct {
	ID          string
	DisplayName string
}

type CopyObjectResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult" json:"-"`
	LastModified time.Time
	ETag         string
}

func (r CopyObjectResult) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias CopyObjectResult
	aux := &struct {
		LastModified string `xml:"LastModified"`
		*Alias
	}{
		Alias: (*Alias)(&r),
	}

	aux.LastModified = r.LastModified.UTC().Format(RFC3339TimeFormat)

	return e.EncodeElement(aux, start)
}

type AccessControlPolicy struct {
	XMLName           xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy" json:"-"`
	Owner             CanonicalUser
	AccessControlList AccessControlList
}

type AccessControlList struct {
	Grant []Grant
}

type Grant struct {
	Grantee    Grantee
	Permission string
}

// Set the following to encode correctly:
//
//	Grantee: s3response.Grantee{
//		Xsi:         "http://www.w3.org/2001/XMLSchema-instance",
//		Type:        "CanonicalUser",
//	},
type Grantee struct {
	XMLName     xml.Name `xml:"Grantee"`
	Xsi         string   `xml:"xmlns:xsi,attr,omitempty"`
	Type        string   `xml:"xsi:type,attr,omitempty"`
	ID          string
	DisplayName string
}

type OwnershipControls struct {
	Rules []types.OwnershipControlsRule `xml:"Rule"`
}

type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult" json:"-"`
	Bucket   string
	Key      string
	UploadId string
}
