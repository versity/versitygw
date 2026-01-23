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

//go:build linux && amd64

package scoutfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/xattr"
	"github.com/versity/scoutfs-go"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

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
	// on multipart parts. This is enabled by default to prevent archive
	// copies of temporary multipart parts.
	disableNoArchive bool

	// enable posix level bucket name validations, not needed if the
	// frontend handlers are already validating bucket names
	validateBucketName bool

	// projectIDEnabled enables setting projectid of new buckets and objects
	// to the account project id when non-0
	projectIDEnabled bool
}

func New(rootdir string, opts ScoutfsOpts) (*ScoutFS, error) {
	metastore := meta.XattrMeta{}

	p, err := posix.New(rootdir, metastore, posix.PosixOpts{
		ChownUID:            opts.ChownUID,
		ChownGID:            opts.ChownGID,
		BucketLinks:         opts.BucketLinks,
		NewDirPerm:          opts.NewDirPerm,
		VersioningDir:       opts.VersioningDir,
		ValidateBucketNames: opts.ValidateBucketNames,
	})
	if err != nil {
		return nil, err
	}

	f, err := os.Open(rootdir)
	if err != nil {
		return nil, fmt.Errorf("open %v: %w", rootdir, err)
	}

	setProjectID := opts.SetProjectID
	if opts.SetProjectID {
		setProjectID = fGetFormatVersion(f).AtLeast(versionScoutFsV2)
		if !setProjectID {
			fmt.Println("WARNING:")
			fmt.Println("Disabling ProjectIDs for unsupported FS format version")
			fmt.Println("See documentation for format version upgrades")
		}
	}

	return &ScoutFS{
		Posix:            p,
		rootfd:           f,
		rootdir:          rootdir,
		glaciermode:      opts.GlacierMode,
		disableNoArchive: opts.DisableNoArchive,
		projectIDEnabled: setProjectID,
	}, nil
}

const (
	stageComplete      = "ongoing-request=\"false\", expiry-date=\"Fri, 2 Dec 2050 00:00:00 GMT\""
	stageInProgress    = "true"
	stageNotInProgress = "false"
)

const (
	// ScoutFS special xattr types
	systemPrefix = "scoutfs.hide."
	flagskey     = systemPrefix + "sam_flags"
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
}

func (*ScoutFS) String() string {
	return "ScoutFS Gateway"
}

func (s *ScoutFS) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, acl []byte) error {
	err := s.Posix.CreateBucket(ctx, input, acl)
	if err != nil {
		return err
	}

	if s.projectIDEnabled {
		acct, ok := ctx.Value("account").(auth.Account)
		if !ok {
			acct = auth.Account{}
		}

		if !isValidProjectID(acct.ProjectID) {
			// early return to avoid the open if we dont have a valid
			// project id
			return nil
		}

		f, err := os.Open(*input.Bucket)
		if err != nil {
			debuglogger.InternalError(fmt.Errorf("create bucket %q set project id - open: %v",
				*input.Bucket, err))
			return nil
		}

		err = s.setProjectID(f, acct.ProjectID)
		f.Close()
		if err != nil {
			debuglogger.InternalError(fmt.Errorf("create bucket %q set project id: %v",
				*input.Bucket, err))
		}
	}

	return nil
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
		st, err := scoutfs.StatMore(objPath)
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

func (s *ScoutFS) PutObject(ctx context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	return s.Posix.PutObjectWithPostFunc(ctx, po, func(f *os.File) error {
		err := s.setProjectID(f, acct.ProjectID)
		if err != nil {
			debuglogger.InternalError(fmt.Errorf("put object %v/%v set project id: %v",
				filepath.Join(*po.Bucket, *po.Key), acct.ProjectID, err))
		}

		return nil
	})
}

func (s *ScoutFS) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	return s.Posix.UploadPartWithPostFunc(ctx, input,
		func(f *os.File) error {
			if !s.disableNoArchive {
				err := setNoArchive(f)
				if err != nil {
					return fmt.Errorf("set noarchive: %w", err)
				}
			}

			err := s.setProjectID(f, acct.ProjectID)
			if err != nil {
				return fmt.Errorf("set project id %v: %w", acct.ProjectID, err)
			}

			return nil
		})
}

// CompleteMultipartUpload scoutfs complete upload uses scoutfs move blocks
// ioctl to not have to read and copy the part data to the final object. This
// saves a read and write cycle for all mutlipart uploads.
func (s *ScoutFS) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	return s.Posix.CompleteMultipartUploadWithCopy(ctx, input,
		func(from *os.File, to *os.File) error {
			// May fail if the files are not 4K aligned; check for alignment
			ffi, err := from.Stat()
			if err != nil {
				return fmt.Errorf("complete-mpu stat from: %w", err)
			}
			tfi, err := to.Stat()
			if err != nil {
				return fmt.Errorf("complete-mpu stat to: %w", err)
			}
			if ffi.Size()%4096 != 0 || tfi.Size()%4096 != 0 {
				return os.ErrInvalid
			}

			err = s.setProjectID(to, acct.ProjectID)
			if err != nil {
				debuglogger.InternalError(fmt.Errorf("complete-mpu %q/%q set project id %v: %v",
					*input.Bucket, *input.Key, acct.ProjectID, err))
			}

			err = scoutfs.MoveData(from, to)
			if err != nil {
				return fmt.Errorf("complete-mpu movedata: %w", err)
			}

			return nil
		})
}

func (s *ScoutFS) isBucketValid(bucket string) bool {
	if !s.validateBucketName {
		return true
	}

	return backend.IsValidDirectoryName(bucket)
}

func (s *ScoutFS) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	bucket := *input.Bucket
	object := *input.Key

	if !s.isBucketValid(bucket) {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

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
		st, err := scoutfs.StatMore(objPath)
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
	if s.glaciermode {
		return s.Posix.ListObjectsParametrized(ctx, input, s.glacierFileToObj)
	} else {
		return s.Posix.ListObjects(ctx, input)
	}
}

func (s *ScoutFS) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	if s.glaciermode {
		return s.Posix.ListObjectsV2Parametrized(ctx, input, s.glacierFileToObj)
	} else {
		return s.Posix.ListObjectsV2(ctx, input)
	}
}

// FileToObj function for ListObject calls that adds a Glacier storage class if the file is offline
func (s *ScoutFS) glacierFileToObj(bucket string, fetchOwner bool) backend.GetObjFunc {
	posixFileToObj := s.Posix.FileToObj(bucket, fetchOwner)

	return func(path string, d fs.DirEntry) (s3response.Object, error) {
		res, err := posixFileToObj(path, d)
		if err != nil || d.IsDir() {
			return res, err
		}
		objPath := filepath.Join(bucket, path)
		// Check if there are any offline exents associated with this file.
		// If so, we will return the Glacier storage class
		st, err := scoutfs.StatMore(objPath)
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		if err != nil {
			return s3response.Object{}, fmt.Errorf("stat more: %w", err)
		}
		if st.Offline_blocks != 0 {
			res.StorageClass = types.ObjectStorageClassGlacier
		}
		return res, nil
	}
}

// RestoreObject will set stage request on file if offline and do nothing if
// file is online
func (s *ScoutFS) RestoreObject(_ context.Context, input *s3.RestoreObjectInput) error {
	bucket := *input.Bucket
	object := *input.Key

	if !s.isBucketValid(bucket) {
		return s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

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
	f, err := os.Open(objname)
	if err != nil {
		return err
	}
	defer f.Close()

	return fsetFlag(f, flag)
}

func fsetFlag(f *os.File, flag uint64) error {
	b, err := xattr.FGet(f, flagskey)
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

	return xattr.FSet(f, flagskey, b)
}

func setStaging(objname string) error {
	return setFlag(objname, Staging)
}

func setNoArchive(f *os.File) error {
	return fsetFlag(f, NoArchive)
}

func isNoAttr(err error) bool {
	xerr, ok := err.(*xattr.Error)
	if ok && xerr.Err == xattr.ENOATTR {
		return true
	}
	return false
}

func (s *ScoutFS) setProjectID(f *os.File, proj int) error {
	if s.projectIDEnabled && isValidProjectID(proj) {
		err := scoutfs.SetProjectID(f, uint64(proj))
		if err != nil {
			return fmt.Errorf("set project id: %w", err)
		}
	}
	return nil
}

func isValidProjectID(proj int) bool {
	return proj > 0
}

const (
	sysscoutfs    = "/sys/fs/scoutfs/"
	formatversion = "format_version"
)

// GetFormatVersion returns ScoutFS version reported by sysfs
func fGetFormatVersion(f *os.File) scoutFsVersion {
	fsid, err := scoutfs.GetIDs(f)
	if err != nil {
		return versionScoutFsNotScoutFS
	}

	path := filepath.Join(sysscoutfs, fsid.ShortID, formatversion)
	buf, err := os.ReadFile(path)
	if err != nil {
		return versionScoutFsUnknown
	}

	str := strings.TrimSpace(string(buf))
	vers, err := strconv.Atoi(str)
	if err != nil {
		return versionScoutFsUnknown
	}

	return scoutFsVersion(vers)
}

const (
	// versionScoutFsUnknown is unknown version
	versionScoutFsUnknown scoutFsVersion = iota
	// versionScoutFsV1 is version 1
	versionScoutFsV1
	// versionScoutFsV2 is version 2
	versionScoutFsV2
	// versionScoutFsMin is minimum scoutfs version
	versionScoutFsMin = versionScoutFsV1
	// versionScoutFsMax is maximum scoutfs version
	versionScoutFsMax = versionScoutFsV2
	// versionScoutFsNotScoutFS means the target FS is not scoutfs
	versionScoutFsNotScoutFS = versionScoutFsMax + 1
)

// scoutFsVersion version
type scoutFsVersion int

// AtLeast returns true if version is valid and at least b
func (a scoutFsVersion) AtLeast(b scoutFsVersion) bool {
	return a.IsValid() && a >= b
}

func (a scoutFsVersion) IsValid() bool {
	return a >= versionScoutFsMin && a <= versionScoutFsMax
}
