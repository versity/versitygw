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

type ActionResponse interface {
	SetRequestID(string)
}

type ResponseMetadata struct {
	RequestID string `xml:"RequestId"`
}

type CreateUserResponse struct {
	XMLName          xml.Name         `xml:"https://iam.amazonaws.com/doc/2010-05-08/ CreateUserResponse"`
	Result           CreateUserResult `xml:"CreateUserResult"`
	ResponseMetadata ResponseMetadata
}

func (r *CreateUserResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type CreateUserResult struct {
	User User
}

type GetUserResponse struct {
	XMLName          xml.Name      `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetUserResponse"`
	Result           GetUserResult `xml:"GetUserResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetUserResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetUserResult struct {
	User User
}

type ListUsersResponse struct {
	XMLName          xml.Name        `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListUsersResponse"`
	Result           ListUsersResult `xml:"ListUsersResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListUsersResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListUsersResult struct {
	Users       Users
	IsTruncated bool
	Marker      string `xml:",omitempty"`
}

type Users struct {
	Members []User `xml:"member"`
}

type UpdateUserResponse struct {
	XMLName          xml.Name         `xml:"https://iam.amazonaws.com/doc/2010-05-08/ UpdateUserResponse"`
	Result           UpdateUserResult `xml:"UpdateUserResult"`
	ResponseMetadata ResponseMetadata
}

func (r *UpdateUserResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type UpdateUserResult struct {
	User *User
}

type DeleteUserResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ DeleteUserResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *DeleteUserResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type User struct {
	Path       string           `xml:",omitempty"`
	UserName   string           `xml:",omitempty"`
	UserID     string           `xml:"UserId"`
	Arn        string           `xml:"Arn"`
	CreateDate time.Time        `xml:"CreateDate"`
	Tags       []Tag            `xml:"Tags>member,omitempty"`
	AccessKeys []AccessKeyEntry `xml:"-"`
	Policies   Policies         `xml:"-"`
}

type Tag struct {
	Key   string
	Value string
}

// Tags is the XML wrapper for a tag list, rendering as
// <Tags><member>…</member></Tags> — and, when empty, as <Tags/> rather
// than being omitted, matching AWS's response for an untagged user.
type Tags struct {
	Members []Tag `xml:"member"`
}

type TagUserResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ TagUserResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *TagUserResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type UntagUserResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ UntagUserResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *UntagUserResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListUserTagsResponse struct {
	XMLName          xml.Name           `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListUserTagsResponse"`
	Result           ListUserTagsResult `xml:"ListUserTagsResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListUserTagsResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListUserTagsResult struct {
	Tags        Tags
	IsTruncated bool
	Marker      string `xml:",omitempty"`
}
