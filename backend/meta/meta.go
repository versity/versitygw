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

package meta

import "os"

// MetadataStorer defines the interface for managing metadata.
// When object == "", the operation is on the bucket.
type MetadataStorer interface {
	// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
	// Returns the value of the attribute, or an error if the attribute does not exist.
	RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error)

	// StoreAttribute stores the value of a specific attribute for an object or a bucket.
	// If attribute already exists, new attribute should replace existing.
	// Returns an error if the operation fails.
	StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error

	// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
	// Returns an error if the operation fails.
	DeleteAttribute(bucket, object, attribute string) error

	// ListAttributes lists all attributes for an object or a bucket.
	// Returns list of attribute names, or an error if the operation fails.
	ListAttributes(bucket, object string) ([]string, error)

	// DeleteAttributes removes all attributes for an object or a bucket.
	// Returns an error if the operation fails.
	DeleteAttributes(bucket, object string) error
}
