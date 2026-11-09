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

//go:build !linux

package posix

// ownDefaultACL reports whether the directory path has a default ACL other
// than the one of its parent. Default ACLs are only looked at on Linux, where
// InheritDefaultACL applies.
func ownDefaultACL(string) (bool, error) {
	return false, nil
}
