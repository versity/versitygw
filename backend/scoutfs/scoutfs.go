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
	// NewDirPerm specifies the permission to set on newly created directories.
	// An explicit zero value (0000) is valid and is preserved when set via
	// SetNewDirPerm.
	NewDirPerm    fs.FileMode
	newDirPermSet bool
	// NewFilePerm specifies the permission to set on newly created object
	// files. Defaults to 0644 when unset; an explicit zero value (0000) is
	// valid and is preserved when set via SetNewFilePerm.
	NewFilePerm    fs.FileMode
	newFilePermSet bool
	// GlacierMode enables glacier emulation for offline files
	GlacierMode bool
	// DisableNoArchive prevents setting noarchive on temporary files
	DisableNoArchive bool
	// ValidateBucketNames enables minimal bucket name validation to prevent
	// incorrect access to the filesystem. This is only needed if the
	// frontend is not already validating bucket names.
	ValidateBucketNames bool
	// Concurrency sets the maximum number of concurrently running POSIX actions.
	// Defaults to 5000 when unset or non-positive.
	Concurrency int
	// CopyObjectThreshold sets the maximum allowed source object size (in bytes)
	// for CopyObject and UploadPartCopy operations. Requests exceeding this
	// threshold are rejected with an 'InvalidRequest' error. Defaults to the
	// S3 specification limit of 5 GiB.
	CopyObjectThreshold int64
	// DefaultEtag is returned for objects that do not have a stored etag
	// attribute (e.g. files placed on the filesystem outside of versitygw).
	// When empty, such objects are served with an empty ETag.
	DefaultEtag string
	// DataIntegrityEtag, when enabled, replaces the standard MD5-based ETag
	// with a checksum-derived value that embeds the algorithm name and checksum
	// (e.g. "CRC64NVME-<base64>"). For multipart uploads, part ETags become
	// CRC64NVME-based values and the completed object ETag is checksum-derived.
	DataIntegrityEtag bool
}

func (o *ScoutfsOpts) SetNewDirPerm(perm fs.FileMode) {
	o.NewDirPerm = perm
	o.newDirPermSet = true
}

func (o *ScoutfsOpts) SetNewFilePerm(perm fs.FileMode) {
	o.NewFilePerm = perm
	o.newFilePermSet = true
}

var _ backend.Backend = &ScoutFS{}
