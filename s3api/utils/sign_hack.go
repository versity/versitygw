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

package utils

import (
	"reflect"
	"unsafe"
)

// This is a hack to replace the default IgnoredHeaders in the aws-sdk-go-v2
// internal/v4 package. Some AWS applications
// (e.g. AWS Java SDK v1, Athena JDBC driver, s3 browser) sign the requests
// including the User-Agent header. The aws sdk doesn't allow directly
// modifying the ignored header list. Below is a hack to replace this list
// with our own.

type Rule interface {
	IsValid(value string) bool
}
type Rules []Rule

//go:linkname __ignoredHeaders github.com/aws/aws-sdk-go-v2/aws/signer/internal/v4.IgnoredHeaders
var __ignoredHeaders unsafe.Pointer

func init() {
	// Avoids "go.info.github.com/aws/aws-sdk-go-v2/aws/signer/internal/v4.IgnoredHeaders:
	// relocation target go.info.github.com/xxx/xxx/xxx.Rules not defined"
	var ignoredHeaders = (*Rules)(unsafe.Pointer(&__ignoredHeaders))

	// clear the map, and set just the ignored headers we want
	reflect.ValueOf((*ignoredHeaders)[0]).FieldByName("Rule").Elem().Clear()
	reflect.ValueOf((*ignoredHeaders)[0]).FieldByName("Rule").Elem().SetMapIndex(
		reflect.ValueOf("Authorization"), reflect.ValueOf(struct{}{}))
	reflect.ValueOf((*ignoredHeaders)[0]).FieldByName("Rule").Elem().SetMapIndex(
		reflect.ValueOf("Expect"), reflect.ValueOf(struct{}{}))
}
