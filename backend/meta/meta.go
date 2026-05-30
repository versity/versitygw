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

	// RenameObject renames all stored metadata from oldObject to newObject
	// within the given bucket. This must be called whenever the data
	// directory for an object is renamed so that metadata stays in sync.
	RenameObject(bucket, oldObject, newObject string) error

	// CommitMetadata atomically moves any per-upload temporary metadata written
	// via StoreAttribute(f, bucket, object, …) to the final sidecar location
	// for (bucket, object).  It must be called immediately after the data file
	// has been linked into the namespace (tmpfile.link).  For backends that do
	// not use a temporary staging area this is a no-op.
	//
	// token is the per-upload sidecar identifier computed by tmpfile.SidecarToken()
	// before link() closed the temp file descriptor.
	//
	// dataPath is the filesystem path of the committed data file (e.g.
	// filepath.Join(bucket, object) relative to the POSIX data root).  The
	// SideCar implementation uses it to verify that this upload is still the
	// inode at the final path before each attribute rename.  Other
	// implementations may pass an empty string or ignore the parameter.
	CommitMetadata(bucket, object, token, dataPath string) error

	// CleanupMetadata removes any per-upload temporary metadata staged by
	// StoreAttribute(f, bucket, object, …) without promoting it to the final
	// location.  It must be called when this upload lost the concurrent link()
	// race (didWinLink returned false) or when link() returned EEXIST, so that
	// the temporary staging directory does not accumulate.  For backends that do
	// not use a temporary staging area this is a no-op.
	//
	// token is the per-upload sidecar identifier computed by tmpfile.SidecarToken().
	CleanupMetadata(bucket, token string) error
}
