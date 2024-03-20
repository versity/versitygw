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

package auth

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Action string

const (
	ListBuckets                   Action = "s3:ListBuckets"
	HeadBucketAction              Action = "s3:HeadBucket"
	GetBucketAclAction            Action = "s3:GetBucketAcl"
	CreateBucketAction            Action = "s3:CreateBucket"
	PutBucketAclAction            Action = "s3:PutBucketAcl"
	DeleteBucketAction            Action = "s3:DeleteBucket"
	PutBucketVersioningAction     Action = "s3:PutBucketVersioning"
	GetBucketVersioningAction     Action = "s3:GetBucketVersioning"
	PutBucketPolicyAction         Action = "s3:PutBucketPolicy"
	GetBucketPolicyAction         Action = "s3:GetBucketPolicy"
	CreateMultipartUploadAction   Action = "s3:CreateMultipartUpload"
	CompleteMultipartUploadAction Action = "s3:CompleteMultipartUpload"
	AbortMultipartUploadAction    Action = "s3:AbortMultipartUpload"
	ListMultipartUploadsAction    Action = "s3:ListMultipartUploads"
	ListPartsAction               Action = "s3:ListParts"
	UploadPartAction              Action = "s3:UploadPart"
	UploadPartCopyAction          Action = "s3:UploadPartCopy"
	PutObjectAction               Action = "s3:PutObject"
	HeadObjectAction              Action = "s3:HeadObject"
	GetObjectAction               Action = "s3:GetObject"
	GetObjectAclAction            Action = "s3:GetObjectAcl"
	GetObjectAttributesAction     Action = "s3:GetObjectAttributes"
	CopyObjectAction              Action = "s3:CopyObject"
	ListObjectsAction             Action = "s3:ListObjects"
	ListObjectsV2Action           Action = "s3:ListObjectsV2"
	DeleteObjectAction            Action = "s3:DeleteObject"
	DeleteObjectsAction           Action = "s3:DeleteObjects"
	PutObjectAclAction            Action = "s3:PutObjectAcl"
	ListObjectVersionsAction      Action = "s3:ListObjectVersions"
	RestoreObjectAction           Action = "s3:RestoreObject"
	SelectObjectContentAction     Action = "s3:SelectObjectContent"
	GetBucketTaggingAction        Action = "s3:GetBucketTagging"
	PutBucketTaggingAction        Action = "s3:PutBucketTagging"
	DeleteBucketTaggingAction     Action = "s3:DeleteBucketTagging"
	GetObjectTaggingAction        Action = "s3:GetObjectTagging"
	PutObjectTaggingAction        Action = "s3:PutObjectTagging"
	DeleteObjectTaggingAction     Action = "s3:DeleteObjectTagging"
	AllActions                    Action = "s3:*"
)

var supportedActionList = map[Action]struct{}{
	ListBuckets:                   {},
	HeadBucketAction:              {},
	GetBucketAclAction:            {},
	CreateBucketAction:            {},
	PutBucketAclAction:            {},
	DeleteBucketAction:            {},
	PutBucketVersioningAction:     {},
	GetBucketVersioningAction:     {},
	PutBucketPolicyAction:         {},
	GetBucketPolicyAction:         {},
	CreateMultipartUploadAction:   {},
	CompleteMultipartUploadAction: {},
	AbortMultipartUploadAction:    {},
	ListMultipartUploadsAction:    {},
	ListPartsAction:               {},
	UploadPartAction:              {},
	UploadPartCopyAction:          {},
	PutObjectAction:               {},
	HeadObjectAction:              {},
	GetObjectAction:               {},
	GetObjectAclAction:            {},
	GetObjectAttributesAction:     {},
	CopyObjectAction:              {},
	ListObjectsAction:             {},
	ListObjectsV2Action:           {},
	DeleteObjectAction:            {},
	DeleteObjectsAction:           {},
	PutObjectAclAction:            {},
	ListObjectVersionsAction:      {},
	RestoreObjectAction:           {},
	SelectObjectContentAction:     {},
	GetBucketTaggingAction:        {},
	PutBucketTaggingAction:        {},
	DeleteBucketTaggingAction:     {},
	GetObjectTaggingAction:        {},
	PutObjectTaggingAction:        {},
	DeleteObjectTaggingAction:     {},
	AllActions:                    {},
}

var supportedObjectActionList = map[Action]struct{}{
	CreateMultipartUploadAction:   {},
	CompleteMultipartUploadAction: {},
	AbortMultipartUploadAction:    {},
	ListMultipartUploadsAction:    {},
	ListPartsAction:               {},
	UploadPartAction:              {},
	UploadPartCopyAction:          {},
	PutObjectAction:               {},
	HeadObjectAction:              {},
	GetObjectAction:               {},
	GetObjectAclAction:            {},
	GetObjectAttributesAction:     {},
	CopyObjectAction:              {},
	ListObjectsAction:             {},
	ListObjectsV2Action:           {},
	DeleteObjectAction:            {},
	DeleteObjectsAction:           {},
	PutObjectAclAction:            {},
	ListObjectVersionsAction:      {},
	RestoreObjectAction:           {},
	SelectObjectContentAction:     {},
	GetObjectTaggingAction:        {},
	PutObjectTaggingAction:        {},
	DeleteObjectTaggingAction:     {},
	AllActions:                    {},
}

// Validates Action: it should either wildcard match with supported actions list or be in it
func (a Action) IsValid() error {
	if !strings.HasPrefix(string(a), "s3:") {
		return fmt.Errorf("invalid action: %v", a)
	}

	if a == AllActions {
		return nil
	}

	if a[len(a)-1] == '*' {
		pattern := strings.TrimSuffix(string(a), "*")
		for act := range supportedActionList {
			if strings.HasPrefix(string(act), pattern) {
				return nil
			}
		}

		return fmt.Errorf("invalid wildcard usage: %v prefix is not in the supported actions list", pattern)
	}

	_, found := supportedActionList[a]
	if !found {
		return fmt.Errorf("unsupported action: %v", a)
	}
	return nil
}

// Checks if the action is object action
func (a Action) IsObjectAction() bool {
	if a[len(a)-1] == '*' {
		pattern := strings.TrimSuffix(string(a), "*")
		for act := range supportedObjectActionList {
			if strings.HasPrefix(string(act), pattern) {
				return true
			}
		}

		return false
	}

	_, found := supportedObjectActionList[a]
	return found
}

type Actions map[Action]struct{}

// Override UnmarshalJSON method to decode both []string and string properties
func (a *Actions) UnmarshalJSON(data []byte) error {
	ss := []string{}
	var err error
	if err = json.Unmarshal(data, &ss); err == nil {
		if len(ss) == 0 {
			return fmt.Errorf("actions can't be empty")
		}
		*a = make(Actions)
		for _, s := range ss {
			err = a.Add(s)
			if err != nil {
				return err
			}
		}
	} else {
		var s string
		if err = json.Unmarshal(data, &s); err == nil {
			if s == "" {
				return fmt.Errorf("actions can't be empty")
			}
			*a = make(Actions)
			err = a.Add(s)
			if err != nil {
				return err
			}
		}
	}

	return err
}

// Validates and adds a new Action to Actions map
func (a Actions) Add(str string) error {
	action := Action(str)
	err := action.IsValid()
	if err != nil {
		return err
	}

	a[action] = struct{}{}
	return nil
}
