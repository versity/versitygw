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

type Role struct {
	Path                     string    `xml:",omitempty"`
	RoleName                 string    `xml:",omitempty"`
	RoleID                   string    `xml:"RoleId"`
	Arn                      string    `xml:"Arn"`
	CreateDate               time.Time `xml:"CreateDate"`
	AssumeRolePolicyDocument string    `xml:",omitempty"`
	Description              string    `xml:",omitempty"`
	MaxSessionDuration       int32     `xml:"MaxSessionDuration,omitempty"`
	RoleLastUsed             *RoleLastUsed
	Tags                     []Tag    `xml:"Tags>member,omitempty"`
	Policies                 Policies `xml:"-"` // unused until role inline-policy CRUD exists; see DeleteRole conflict check
}

// RoleLastUsed reports when, and in which region, a role was last used.
// LastUsedDate is a pointer so a never-used role renders as the empty
// <RoleLastUsed></RoleLastUsed> element AWS returns, rather than as a role
// used at the zero time.
type RoleLastUsed struct {
	LastUsedDate *time.Time `xml:",omitempty"`
	Region       string     `xml:",omitempty"`
}

// EnsureRoleLastUsed defaults RoleLastUsed to a never-used value if unset,
// without clobbering an already-set one. A zero LastUsedDate is normalized
// away to nil: a role stored before last-used tracking existed persists the
// zero time, which must still report as never used.
func (r *Role) EnsureRoleLastUsed() {
	if r.RoleLastUsed == nil {
		r.RoleLastUsed = &RoleLastUsed{}
		return
	}
	if r.RoleLastUsed.LastUsedDate != nil && r.RoleLastUsed.LastUsedDate.IsZero() {
		r.RoleLastUsed.LastUsedDate = nil
	}
}

type CreateRoleResponse struct {
	XMLName          xml.Name         `xml:"https://iam.amazonaws.com/doc/2010-05-08/ CreateRoleResponse"`
	Result           CreateRoleResult `xml:"CreateRoleResult"`
	ResponseMetadata ResponseMetadata
}

func (r *CreateRoleResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type CreateRoleResult struct {
	Role *Role
}

type GetRoleResponse struct {
	XMLName          xml.Name      `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetRoleResponse"`
	Result           GetRoleResult `xml:"GetRoleResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetRoleResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetRoleResult struct {
	Role *Role
}

type ListRolesResponse struct {
	XMLName          xml.Name        `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListRolesResponse"`
	Result           ListRolesResult `xml:"ListRolesResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListRolesResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListRolesResult struct {
	Roles       Roles
	IsTruncated bool
	Marker      string `xml:",omitempty"`
}

type Roles struct {
	Members []Role `xml:"member"`
}

type DeleteRoleResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ DeleteRoleResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *DeleteRoleResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type UpdateAssumeRolePolicyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ UpdateAssumeRolePolicyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *UpdateAssumeRolePolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type TagRoleResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ TagRoleResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *TagRoleResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type UntagRoleResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ UntagRoleResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *UntagRoleResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListRoleTagsResponse struct {
	XMLName          xml.Name           `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListRoleTagsResponse"`
	Result           ListRoleTagsResult `xml:"ListRoleTagsResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListRoleTagsResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListRoleTagsResult struct {
	Tags        Tags
	IsTruncated bool
	Marker      string `xml:",omitempty"`
}
