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

// Policies holds every kind of policy attached to an identity (user, role ...)
// Inline is the only populated field for now
type Policies struct {
	Inline []PolicyEntry `json:"inline,omitempty"`
}

// PolicyEntry is the storage representation of a single inline policy. It
// round-trips through JSON for the internal and Vault storers and is
// never marshaled to XML directly — mirrors AccessKeyEntry. PolicyDocument
// holds the exact bytes submitted by the caller (after validation), not a
// re-serialized form
type PolicyEntry struct {
	PolicyName     string
	PolicyDocument string
	CreateDate     time.Time
	UpdateDate     time.Time
}

type PutUserPolicyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ PutUserPolicyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *PutUserPolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type DeleteUserPolicyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ DeleteUserPolicyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *DeleteUserPolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetUserPolicyResponse struct {
	XMLName          xml.Name            `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetUserPolicyResponse"`
	Result           GetUserPolicyResult `xml:"GetUserPolicyResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetUserPolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

// GetUserPolicyResult's PolicyDocument must be RFC 3986 percent-encoded by
// the caller before assignment — see iamutil.EncodePolicyDocument. Real
// IAM returns PolicyDocument URL-encoded; xml.Marshal does not do this
// encoding on its own.
type GetUserPolicyResult struct {
	UserName       string
	PolicyName     string
	PolicyDocument string
}

type ListUserPoliciesResponse struct {
	XMLName          xml.Name               `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListUserPoliciesResponse"`
	Result           ListUserPoliciesResult `xml:"ListUserPoliciesResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListUserPoliciesResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListUserPoliciesResult struct {
	PolicyNames PolicyNameList
	IsTruncated bool
	Marker      string `xml:",omitempty"`
}

type PolicyNameList struct {
	Members []string `xml:"member"`
}

type PutRolePolicyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ PutRolePolicyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *PutRolePolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type DeleteRolePolicyResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ DeleteRolePolicyResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *DeleteRolePolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetRolePolicyResponse struct {
	XMLName          xml.Name            `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetRolePolicyResponse"`
	Result           GetRolePolicyResult `xml:"GetRolePolicyResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetRolePolicyResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetRolePolicyResult struct {
	RoleName       string
	PolicyName     string
	PolicyDocument string
}

type ListRolePoliciesResponse struct {
	XMLName          xml.Name               `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListRolePoliciesResponse"`
	Result           ListRolePoliciesResult `xml:"ListRolePoliciesResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListRolePoliciesResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListRolePoliciesResult struct {
	PolicyNames PolicyNameList
	IsTruncated bool
	Marker      string `xml:",omitempty"`
}
