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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/xattr"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type ScoutfsOpts struct {
	ChownUID         bool
	ChownGID         bool
	GlacierMode      bool
	BucketLinks      bool
	NewDirPerm       fs.FileMode
	DisableNoArchive bool
}

type ScoutFS struct {
	*posix.Posix
	rootfd  *os.File
	rootdir string

	// glaciermode enables the following behavior:
	// GET object:  if file offline, return invalid object state
	// HEAD object: if file offline, set obj storage class to GLACIER
	//              if file offline and staging, x-amz-restore: ongoing-request="true"
	//              if file offline and not staging, x-amz-restore: ongoing-request="false"
	//              if file online, x-amz-restore: ongoing-request="false", expiry-date="Fri, 2 Dec 2050 00:00:00 GMT"
	//              note: this expiry-date is not used but provided for client glacier compatibility
	// ListObjects: if file offline, set obj storage class to GLACIER
	// RestoreObject: add batch stage request to file
	glaciermode bool

	// disableNoArchive is used to disable setting scoutam noarchive flag
	// on mutlipart parts. This is enabled by default to prevent archive
	// copies of temporary multipart parts.
	disableNoArchive bool
}

var _ backend.Backend = &ScoutFS{}

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
)

var (
	stageComplete      = "ongoing-request=\"false\", expiry-date=\"Fri, 2 Dec 2050 00:00:00 GMT\""
	stageInProgress    = "true"
	stageNotInProgress = "false"
)

const (
	// ScoutFS special xattr types
	systemPrefix = "scoutfs.hide."
	onameAttr    = systemPrefix + "objname"
	flagskey     = systemPrefix + "sam_flags"
	stagecopykey = systemPrefix + "sam_stagereq"
)

const (
	// ScoutAM Flags

	// Staging - file requested stage
	Staging uint64 = 1 << iota
	// StageFail - all copies failed to stage
	StageFail
	// NoArchive - no archive copies of file should be made
	NoArchive
	// ExtCacheRequested means file policy requests Ext Cache
	ExtCacheRequested
	// ExtCacheDone means this file ext cache copy has been
	// created already (and possibly pruned, so may not exist)
	ExtCacheDone
)

func (s *ScoutFS) Shutdown() {
	s.Posix.Shutdown()
	s.rootfd.Close()
	_ = s.rootdir
}

func (*ScoutFS) String() string {
	return "ScoutFS Gateway"
}

func (s *ScoutFS) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	out, err := s.Posix.UploadPart(ctx, input)
	if err != nil {
		return nil, err
	}

	if !s.disableNoArchive {
		sum := sha256.Sum256([]byte(*input.Key))
		partPath := filepath.Join(
			*input.Bucket,                        // bucket
			metaTmpMultipartDir,                  // temp multipart dir
			fmt.Sprintf("%x", sum),               // hashed objname
			*input.UploadId,                      // upload id
			fmt.Sprintf("%v", *input.PartNumber), // part number
		)

		err = setNoArchive(partPath)
		if err != nil {
			return nil, fmt.Errorf("set noarchive: %w", err)
		}
	}

	return out, err
}

// CompleteMultipartUpload scoutfs complete upload uses scoutfs move blocks
// ioctl to not have to read and copy the part data to the final object. This
// saves a read and write cycle for all mutlipart uploads.
func (s *ScoutFS) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	return s.Posix.CompleteMultipartUploadWithCopy(ctx, input, moveData)
}

func (s *ScoutFS) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	res, err := s.Posix.HeadObject(ctx, input)
	if err != nil {
		return nil, err
	}

	if s.glaciermode {
		objPath := filepath.Join(*input.Bucket, *input.Key)

		stclass := types.StorageClassStandard
		requestOngoing := ""

		requestOngoing = stageComplete

		// Check if there are any offline exents associated with this file.
		// If so, we will set storage class to glacier.
		st, err := statMore(objPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil {
			return nil, fmt.Errorf("stat more: %w", err)
		}
		if st.Offline_blocks != 0 {
			stclass = types.StorageClassGlacier
			requestOngoing = stageNotInProgress

			ok, err := isStaging(objPath)
			if errors.Is(err, fs.ErrNotExist) {
				return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
			}
			if err != nil {
				return nil, fmt.Errorf("check stage status: %w", err)
			}
			if ok {
				requestOngoing = stageInProgress
			}
		}

		res.Restore = &requestOngoing
		res.StorageClass = stclass
	}

	return res, nil
}

func (s *ScoutFS) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	bucket := *input.Bucket
	object := *input.Key

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	objPath := filepath.Join(bucket, object)

	fi, err := os.Stat(objPath)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return nil, s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}

	if strings.HasSuffix(object, "/") && !fi.IsDir() {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	if s.glaciermode {
		// Check if there are any offline exents associated with this file.
		// If so, we will return the InvalidObjectState error.
		st, err := statMore(objPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil {
			return nil, fmt.Errorf("stat more: %w", err)
		}
		if st.Offline_blocks != 0 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidObjectState)
		}
	}

	return s.Posix.GetObject(ctx, input)
}

func (s *ScoutFS) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	return s.Posix.ListObjectsParametrized(ctx, input, s.fileToObj)
}

func (s *ScoutFS) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	return s.Posix.ListObjectsV2Parametrized(ctx, input, s.fileToObj)
}

func (s *ScoutFS) fileToObj(bucket string, fetchOwner bool) backend.GetObjFunc {
	posixFileToObj := s.Posix.FileToObj(bucket, fetchOwner)

	return func(path string, d fs.DirEntry) (s3response.Object, error) {
		res, err := posixFileToObj(path, d)
		if err != nil || d.IsDir() {
			return res, err
		}
		objPath := filepath.Join(bucket, path)
		if s.glaciermode {
			// Check if there are any offline exents associated with this file.
			// If so, we will return the Glacier storage class
			st, err := statMore(objPath)
			if errors.Is(err, fs.ErrNotExist) {
				return s3response.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return s3response.Object{}, fmt.Errorf("stat more: %w", err)
			}
			if st.Offline_blocks != 0 {
				res.StorageClass = types.ObjectStorageClassGlacier
			}
		}
		return res, nil
	}
}

// RestoreObject will set stage request on file if offline and do nothing if
// file is online
func (s *ScoutFS) RestoreObject(_ context.Context, input *s3.RestoreObjectInput) error {
	bucket := *input.Bucket
	object := *input.Key

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	err = setStaging(filepath.Join(bucket, object))
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("stage object: %w", err)
	}

	return nil
}

func isStaging(objname string) (bool, error) {
	b, err := xattr.Get(objname, flagskey)
	if err != nil && !isNoAttr(err) {
		return false, err
	}

	var flags uint64
	if !isNoAttr(err) {
		err = json.Unmarshal(b, &flags)
		if err != nil {
			return false, err
		}
	}

	return flags&Staging == Staging, nil
}

func setFlag(objname string, flag uint64) error {
	b, err := xattr.Get(objname, flagskey)
	if err != nil && !isNoAttr(err) {
		return err
	}

	var oldflags uint64
	if !isNoAttr(err) {
		err = json.Unmarshal(b, &oldflags)
		if err != nil {
			return err
		}
	}

	newflags := oldflags | flag

	if newflags == oldflags {
		// no flags change, just return
		return nil
	}

	b, err = json.Marshal(&newflags)
	if err != nil {
		return err
	}

	return xattr.Set(objname, flagskey, b)
}

func setStaging(objname string) error {
	return setFlag(objname, Staging)
}

func setNoArchive(objname string) error {
	return setFlag(objname, NoArchive)
}

func isNoAttr(err error) bool {
	xerr, ok := err.(*xattr.Error)
	if ok && xerr.Err == xattr.ENOATTR {
		return true
	}
	return false
}
