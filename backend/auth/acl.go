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

import "github.com/aws/aws-sdk-go-v2/service/s3/types"

type ACL struct {
	ACL      types.BucketCannedACL
	Owner    string
	Grantees []Grantee
}

type Grantee struct {
	Permission types.Permission
	Access     string
}

type GetBucketAclOutput struct {
	Owner             *types.Owner
	AccessControlList AccessControlList
}

type AccessControlList struct {
	Grants []types.Grant
}
