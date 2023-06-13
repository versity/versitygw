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
	"os"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Configuration file structure. Map with the key of bucket name and value of ACL
type ACLConfig map[string]ACL

type Grantee struct {
	Permission types.Permission
	Access     string
}

type ACL struct {
	Owner     string
	CannedACL types.BucketCannedACL
	Grantee   []Grantee
}

type ACLService interface{}

type ACLServiceUnsupported struct{}

var _ ACLService = &ACLServiceUnsupported{}

func InitACL() (ACLService, error) {
	_, err := os.ReadFile("acl.json")
	if err != nil {
		jsonData, err := json.MarshalIndent(ACLConfig{}, "", "  ")
		if err != nil {
			return nil, err
		}

		if err := os.WriteFile("acl.json", jsonData, 0644); err != nil {
			return nil, err
		}
	}
	return ACLServiceUnsupported{}, nil
}
