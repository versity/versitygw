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

type RoleLastUsed struct {
	LastUsedDate time.Time `xml:",omitempty"`
	Region       string    `xml:",omitempty"`
}

// EnsureRoleLastUsed defaults RoleLastUsed to a zero value if unset,
// without clobbering an already-set value.
func (r *Role) EnsureRoleLastUsed() {
	if r.RoleLastUsed == nil {
		r.RoleLastUsed = &RoleLastUsed{}
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
