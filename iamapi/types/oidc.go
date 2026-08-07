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

// OIDCProvider is the storage-layer representation of an IAM OIDC identity
// provider. Unlike Role, it is never marshaled to XML directly — each real
// IAM action returns a different subset of its fields — so it is copied
// field-by-field into the narrower XML result types
type OIDCProvider struct {
	// Arn is the full arn:aws:iam::<account>:oidc-provider/<url> ARN.
	Arn string `json:"arn"`
	// Url is stored WITHOUT the "https://" scheme prefix. This is both the
	// ARN's resource-path suffix and the exact string
	// GetOpenIDConnectProvider echoes back in its own Url field. It is never
	// case-folded or otherwise normalized
	Url            string    `json:"url"`
	ClientIDList   []string  `json:"clientIDList,omitempty"`
	ThumbprintList []string  `json:"thumbprintList,omitempty"`
	CreateDate     time.Time `json:"createDate"`
	Tags           []Tag     `json:"tags,omitempty"`
}

type CreateOpenIDConnectProviderResponse struct {
	XMLName          xml.Name                          `xml:"https://iam.amazonaws.com/doc/2010-05-08/ CreateOpenIDConnectProviderResponse"`
	Result           CreateOpenIDConnectProviderResult `xml:"CreateOpenIDConnectProviderResult"`
	ResponseMetadata ResponseMetadata
}

func (r *CreateOpenIDConnectProviderResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type CreateOpenIDConnectProviderResult struct {
	OpenIDConnectProviderArn string `xml:"OpenIDConnectProviderArn"`
	Tags                     []Tag  `xml:"Tags>member,omitempty"`
}

type GetOpenIDConnectProviderResponse struct {
	XMLName          xml.Name                       `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetOpenIDConnectProviderResponse"`
	Result           GetOpenIDConnectProviderResult `xml:"GetOpenIDConnectProviderResult"`
	ResponseMetadata ResponseMetadata
}

func (r *GetOpenIDConnectProviderResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type GetOpenIDConnectProviderResult struct {
	Url            string    `xml:",omitempty"`
	ClientIDList   []string  `xml:"ClientIDList>member,omitempty"`
	ThumbprintList []string  `xml:"ThumbprintList>member,omitempty"`
	CreateDate     time.Time `xml:"CreateDate"`
	Tags           []Tag     `xml:"Tags>member,omitempty"`
}

type ListOpenIDConnectProvidersResponse struct {
	XMLName          xml.Name                         `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListOpenIDConnectProvidersResponse"`
	Result           ListOpenIDConnectProvidersResult `xml:"ListOpenIDConnectProvidersResult"`
	ResponseMetadata ResponseMetadata
}

func (r *ListOpenIDConnectProvidersResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type ListOpenIDConnectProvidersResult struct {
	OpenIDConnectProviderList OpenIDConnectProviderList
}

type OpenIDConnectProviderList struct {
	Members []OpenIDConnectProviderListEntry `xml:"member"`
}

type OpenIDConnectProviderListEntry struct {
	Arn string `xml:"Arn"`
}

type DeleteOpenIDConnectProviderResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ DeleteOpenIDConnectProviderResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *DeleteOpenIDConnectProviderResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type AddClientIDToOpenIDConnectProviderResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ AddClientIDToOpenIDConnectProviderResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *AddClientIDToOpenIDConnectProviderResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type RemoveClientIDFromOpenIDConnectProviderResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ RemoveClientIDFromOpenIDConnectProviderResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *RemoveClientIDFromOpenIDConnectProviderResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}

type UpdateOpenIDConnectProviderThumbprintResponse struct {
	XMLName          xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ UpdateOpenIDConnectProviderThumbprintResponse"`
	ResponseMetadata ResponseMetadata
}

func (r *UpdateOpenIDConnectProviderThumbprintResponse) SetRequestID(requestID string) {
	r.ResponseMetadata.RequestID = requestID
}
