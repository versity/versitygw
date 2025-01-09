// Copyright 2025 Versity Software
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

package meta

import (
	"os"
)

// NoMeta is a metadata storer that does not store metadata.
// This can be useful for read only mounts where attempting to store metadata
// would fail.
type NoMeta struct{}

// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
// always returns ErrNoSuchKey
func (NoMeta) RetrieveAttribute(_ *os.File, _, _, _ string) ([]byte, error) {
	return nil, ErrNoSuchKey
}

// StoreAttribute stores the value of a specific attribute for an object or a bucket.
// always returns nil without storing the attribute
func (NoMeta) StoreAttribute(_ *os.File, _, _, _ string, _ []byte) error {
	return nil
}

// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
// always returns nil without deleting the attribute
func (NoMeta) DeleteAttribute(_, _, _ string) error {
	return nil
}

// ListAttributes lists all attributes for an object or a bucket.
// always returns an empty list of attributes
func (NoMeta) ListAttributes(_, _ string) ([]string, error) {
	return []string{}, nil
}

// DeleteAttributes removes all attributes for an object or a bucket.
// always returns nil without deleting any attributes
func (NoMeta) DeleteAttributes(bucket, object string) error {
	return nil
}
