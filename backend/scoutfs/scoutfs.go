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

package scoutfs

import (
	"io/fs"

	"github.com/versity/versitygw/backend"
)

// ScoutfsOpts are the options for the ScoutFS backend
type ScoutfsOpts struct {
	// ChownUID sets the UID of the object to the UID of the user on PUT
	ChownUID bool
	// ChownGID sets the GID of the object to the GID of the user on PUT
	ChownGID bool
	// SetProjectID sets the Project ID of the bucket/object to the project ID of the user on PUT
	SetProjectID bool
	// BucketLinks enables symlinks to directories to be treated as buckets
	BucketLinks bool
	//VersioningDir sets the version directory to enable object versioning
	VersioningDir string
	// NewDirPerm specifies the permission to set on newly created directories
	NewDirPerm fs.FileMode
	// GlacierMode enables glacier emulation for offline files
	GlacierMode bool
	// DisableNoArchive prevents setting noarchive on temporary files
	DisableNoArchive bool
	// ValidateBucketNames enables minimal bucket name validation to prevent
	// incorrect access to the filesystem. This is only needed if the
	// frontend is not already validating bucket names.
	ValidateBucketNames bool
}

var _ backend.Backend = &ScoutFS{}
