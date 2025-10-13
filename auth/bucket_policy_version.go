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

type PolicyVersion string

const (
	PolicyVersion2008 PolicyVersion = "2008-10-17"
	PolicyVersion2012 PolicyVersion = "2012-10-17"
)

// isValid checks if the policy version is valid or not
func (pv PolicyVersion) isValid() bool {
	switch pv {
	case PolicyVersion2008, PolicyVersion2012:
		return true
	default:
		return false
	}
}
