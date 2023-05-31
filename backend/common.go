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

package backend

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func IsValidBucketName(name string) bool { return true }

type ByBucketName []types.Bucket

func (d ByBucketName) Len() int           { return len(d) }
func (d ByBucketName) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d ByBucketName) Less(i, j int) bool { return *d[i].Name < *d[j].Name }

type ByObjectName []types.Object

func (d ByObjectName) Len() int           { return len(d) }
func (d ByObjectName) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d ByObjectName) Less(i, j int) bool { return *d[i].Key < *d[j].Key }

func GetStringPtr(s string) *string {
	return &s
}

func GetTimePtr(t time.Time) *time.Time {
	return &t
}
