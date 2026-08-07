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

// Session is the storage-layer representation of a temporary credential set
// minted by AssumeRoleWithWebIdentity. It is never marshaled to XML
// directly — GetCallerIdentity and (in a later change) S3 request
// authentication read it back by AccessKeyId to resolve the calling
// identity.
type Session struct {
	AccessKeyId     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	RoleArn         string    `json:"roleArn"`
	RoleName        string    `json:"roleName"`
	RoleID          string    `json:"roleId"`
	RoleSessionName string    `json:"roleSessionName"`
	Provider        string    `json:"provider"`
	Audience        string    `json:"audience"`
	Subject         string    `json:"subject"`
	CreateDate      time.Time `json:"createDate"`
	Expiration      time.Time `json:"expiration"`
	// Policy is the optional inline session policy document supplied via
	// AssumeRoleWithWebIdentity's Policy parameter, or "" if none was
	// supplied. It can only narrow, never widen, the assumed role's own
	// permissions.
	Policy string `json:"policy,omitempty"`
}

// Credentials is the temporary security credential set returned by
// AssumeRoleWithWebIdentity.
type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// AssumedRoleUser identifies the principal produced by assuming a role.
type AssumedRoleUser struct {
	AssumedRoleId string
	Arn           string
}

type AssumeRoleWithWebIdentityResponse struct {
	XMLName          xml.Name                        `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleWithWebIdentityResponse"`
	Result           AssumeRoleWithWebIdentityResult `xml:"AssumeRoleWithWebIdentityResult"`
	ResponseMetadata ResponseMetadata
}

func (r *AssumeRoleWithWebIdentityResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type AssumeRoleWithWebIdentityResult struct {
	Audience                    string `xml:",omitempty"`
	AssumedRoleUser             AssumedRoleUser
	Provider                    string
	Credentials                 Credentials
	SubjectFromWebIdentityToken string
	// PackedPolicySize is a percentage indicating how close the request's
	// session policy came to its size quota; nil (and therefore omitted,
	// matching AWS) when no session Policy parameter was supplied.
	PackedPolicySize *int64 `xml:",omitempty"`
}

type GetCallerIdentityResponse struct {
	XMLName          xml.Name                `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
	Result           GetCallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetCallerIdentityResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetCallerIdentityResult struct {
	Arn     string
	UserId  string
	Account string
}
