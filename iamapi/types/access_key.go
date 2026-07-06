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

package types

import (
	"encoding/xml"
	"time"
)

type CreateAccessKeyResponse struct {
	XMLName          xml.Name              `xml:"https://iam.amazonaws.com/doc/2010-05-08/ CreateAccessKeyResponse"`
	Result           CreateAccessKeyResult `xml:"CreateAccessKeyResult"`
	ResponseMetadata ResponseMetadata
}

func (r *CreateAccessKeyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type CreateAccessKeyResult struct {
	AccessKey AccessKey
}

type AccessKey struct {
	UserName        string `xml:",omitempty"`
	AccessKeyId     string
	Status          string
	SecretAccessKey string
	CreateDate      time.Time
}

type UpdateAccessKeyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ UpdateAccessKeyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *UpdateAccessKeyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type DeleteAccessKeyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ DeleteAccessKeyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *DeleteAccessKeyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetAccessKeyLastUsedResponse struct {
	XMLName          xml.Name                   `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetAccessKeyLastUsedResponse"`
	Result           GetAccessKeyLastUsedResult `xml:"GetAccessKeyLastUsedResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetAccessKeyLastUsedResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetAccessKeyLastUsedResult struct {
	UserName          string `xml:",omitempty"`
	AccessKeyLastUsed AccessKeyLastUsed
}

type AccessKeyLastUsed struct {
	LastUsedDate *time.Time `xml:",omitempty"`
	ServiceName  string
	Region       string
}

type ListAccessKeysResponse struct {
	XMLName          xml.Name             `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListAccessKeysResponse"`
	Result           ListAccessKeysResult `xml:"ListAccessKeysResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListAccessKeysResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListAccessKeysResult struct {
	AccessKeyMetadata AccessKeyMetadataList
	IsTruncated       bool
	Marker            string `xml:",omitempty"`
}

type AccessKeyMetadataList struct {
	Members []AccessKeyMetadata `xml:"member"`
}

type AccessKeyMetadata struct {
	UserName    string `xml:",omitempty"`
	AccessKeyId string
	Status      string
	CreateDate  time.Time
}

// AccessKeyEntry is the storage representation of an access key belonging to
// a User. It is never marshaled to XML directly; it round-trips through JSON
// for the internal and Vault storers.
type AccessKeyEntry struct {
	AccessKeyId     string
	SecretAccessKey string
	Status          string
	CreateDate      time.Time
	LastUsedDate    time.Time
	LastUsedService string
	LastUsedRegion  string
}
