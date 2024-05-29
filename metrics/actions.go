// Copyright 2024 Versity Software
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

package metrics

var (
	ActionUndetected                 = "ActionUnDetected"
	ActionAbortMultipartUpload       = "s3_AbortMultipartUpload"
	ActionCompleteMultipartUpload    = "s3_CompleteMultipartUpload"
	ActionCopyObject                 = "s3_CopyObject"
	ActionCreateBucket               = "s3_CreateBucket"
	ActionCreateMultipartUpload      = "s3_CreateMultipartUpload"
	ActionDeleteBucket               = "s3_DeleteBucket"
	ActionDeleteBucketPolicy         = "s3_DeleteBucketPolicy"
	ActionDeleteBucketTagging        = "s3_DeleteBucketTagging"
	ActionDeleteObject               = "s3_DeleteObject"
	ActionDeleteObjectTagging        = "s3_DeleteObjectTagging"
	ActionDeleteObjects              = "s3_DeleteObjects"
	ActionGetBucketAcl               = "s3_GetBucketAcl"
	ActionGetBucketPolicy            = "s3_GetBucketPolicy"
	ActionGetBucketTagging           = "s3_GetBucketTagging"
	ActionGetBucketVersioning        = "s3_GetBucketVersioning"
	ActionGetObject                  = "s3_GetObject"
	ActionGetObjectAcl               = "s3_GetObjectAcl"
	ActionGetObjectAttributes        = "s3_GetObjectAttributes"
	ActionGetObjectLegalHold         = "s3_GetObjectLegalHold"
	ActionGetObjectLockConfiguration = "s3_GetObjectLockConfiguration"
	ActionGetObjectRetention         = "s3_GetObjectRetention"
	ActionGetObjectTagging           = "s3_GetObjectTagging"
	ActionHeadBucket                 = "s3_HeadBucket"
	ActionHeadObject                 = "s3_HeadObject"
	ActionListAllMyBuckets           = "s3_ListAllMyBuckets"
	ActionListMultipartUploads       = "s3_ListMultipartUploads"
	ActionListObjectVersions         = "s3_ListObjectVersions"
	ActionListObjects                = "s3_ListObjects"
	ActionListObjectsV2              = "s3_ListObjectsV2"
	ActionListParts                  = "s3_ListParts"
	ActionPutBucketAcl               = "s3_PutBucketAcl"
	ActionPutBucketPolicy            = "s3_PutBucketPolicy"
	ActionPutBucketTagging           = "s3_PutBucketTagging"
	ActionPutBucketVersioning        = "s3_PutBucketVersioning"
	ActionPutObject                  = "s3_PutObject"
	ActionPutObjectAcl               = "s3_PutObjectAcl"
	ActionPutObjectLegalHold         = "s3_PutObjectLegalHold"
	ActionPutObjectLockConfiguration = "s3_PutObjectLockConfiguration"
	ActionPutObjectRetention         = "s3_PutObjectRetention"
	ActionPutObjectTagging           = "s3_PutObjectTagging"
	ActionRestoreObject              = "s3_RestoreObject"
	ActionSelectObjectContent        = "s3_SelectObjectContent"
	ActionUploadPart                 = "s3_UploadPart"
	ActionUploadPartCopy             = "s3_UploadPartCopy"
)
