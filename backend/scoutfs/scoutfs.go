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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/xattr"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type ScoutfsOpts struct {
	ChownUID    bool
	ChownGID    bool
	GlacierMode bool
	BucketLinks bool
	NewDirPerm  fs.FileMode
}

type ScoutFS struct {
	*posix.Posix
	rootfd  *os.File
	rootdir string

	// bucket/object metadata storage facility
	meta meta.MetadataStorer

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

	// chownuid/gid enable chowning of files to the account uid/gid
	// when objects are uploaded
	chownuid bool
	chowngid bool

	// euid/egid are the effective uid/gid of the running versitygw process
	// used to determine if chowning is needed
	euid int
	egid int

	// newDirPerm is the permissions to use when creating new directories
	newDirPerm fs.FileMode
}

var _ backend.Backend = &ScoutFS{}

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
	tagHdr              = "X-Amz-Tagging"
	metaHdr             = "X-Amz-Meta"
	contentTypeHdr      = "content-type"
	contentEncHdr       = "content-encoding"
	emptyMD5            = "d41d8cd98f00b204e9800998ecf8427e"
	etagkey             = "etag"
	objectRetentionKey  = "object-retention"
	objectLegalHoldKey  = "object-legal-hold"
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

	fsBlocksize = 4096
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

// getChownIDs returns the uid and gid that should be used for chowning
// the object to the account uid/gid. It also returns a boolean indicating
// if chowning is needed.
func (s *ScoutFS) getChownIDs(acct auth.Account) (int, int, bool) {
	uid := s.euid
	gid := s.egid
	var needsChown bool
	if s.chownuid && acct.UserID != s.euid {
		uid = acct.UserID
		needsChown = true
	}
	if s.chowngid && acct.GroupID != s.egid {
		gid = acct.GroupID
		needsChown = true
	}

	return uid, gid, needsChown
}

// CompleteMultipartUpload scoutfs complete upload uses scoutfs move blocks
// ioctl to not have to read and copy the part data to the final object. This
// saves a read and write cycle for all mutlipart uploads.
func (s *ScoutFS) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if input.UploadId == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if input.MultipartUpload == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	bucket := *input.Bucket
	object := *input.Key
	uploadID := *input.UploadId
	parts := input.MultipartUpload.Parts

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	sum, err := s.checkUploadIDExists(bucket, object, uploadID)
	if err != nil {
		return nil, err
	}

	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	// check all parts ok
	last := len(parts) - 1
	partsize := int64(0)
	var totalsize int64
	for i, part := range parts {
		if part.PartNumber == nil || *part.PartNumber < 1 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		partObjPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *part.PartNumber))
		fullPartPath := filepath.Join(bucket, partObjPath)
		fi, err := os.Lstat(fullPartPath)
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		if i == 0 {
			partsize = fi.Size()
		}

		// partsize must be a multiple of the filesystem blocksize
		// except for last part
		if i < last && partsize%fsBlocksize != 0 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		totalsize += fi.Size()
		// all parts except the last need to be the same size
		if i < last && partsize != fi.Size() {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		b, err := s.meta.RetrieveAttribute(nil, bucket, partObjPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}
		if parts[i].ETag == nil || etag != *parts[i].ETag {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
	}

	// use totalsize=0 because we wont be writing to the file, only moving
	// extents around.  so we dont want to fallocate this.
	f, err := s.openTmpFile(filepath.Join(bucket, metaTmpDir), bucket, object, 0, acct)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return nil, s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return nil, fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	for _, part := range parts {
		if part.PartNumber == nil || *part.PartNumber < 1 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		partObjPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *part.PartNumber))
		fullPartPath := filepath.Join(bucket, partObjPath)
		pf, err := os.Open(fullPartPath)
		if err != nil {
			return nil, fmt.Errorf("open part %v: %v", *part.PartNumber, err)
		}

		// scoutfs move data is a metadata only operation that moves the data
		// extent references from the source, appeding to the destination.
		// this needs to be 4k aligned.
		err = moveData(pf, f.File())
		pf.Close()
		if err != nil {
			return nil, fmt.Errorf("move blocks part %v: %v", *part.PartNumber, err)
		}
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	cType, _ := s.loadUserMetaData(bucket, upiddir, userMetaData)

	objname := filepath.Join(bucket, object)
	dir := filepath.Dir(objname)
	if dir != "" {
		uid, gid, doChown := s.getChownIDs(acct)
		err = backend.MkdirAll(dir, uid, gid, doChown, s.newDirPerm)
		if err != nil {
			return nil, err
		}
	}

	for k, v := range userMetaData {
		err = s.meta.StoreAttribute(f.File(), bucket, object, fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			return nil, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// load and set tagging
	tagging, err := s.meta.RetrieveAttribute(nil, bucket, upiddir, tagHdr)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object tagging: %w", err)
	}
	if err == nil {
		err := s.meta.StoreAttribute(f.File(), bucket, object, tagHdr, tagging)
		if err != nil {
			return nil, fmt.Errorf("set object tagging: %w", err)
		}
	}

	// set content-type
	if cType != "" {
		err := s.meta.StoreAttribute(f.File(), bucket, object, contentTypeHdr, []byte(cType))
		if err != nil {
			return nil, fmt.Errorf("set object content type: %w", err)
		}
	}

	// load and set legal hold
	lHold, err := s.meta.RetrieveAttribute(nil, bucket, upiddir, objectLegalHoldKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object legal hold: %w", err)
	}
	if err == nil {
		err := s.meta.StoreAttribute(f.File(), bucket, object, objectLegalHoldKey, lHold)
		if err != nil {
			return nil, fmt.Errorf("set object legal hold: %w", err)
		}
	}

	// load and set retention
	ret, err := s.meta.RetrieveAttribute(nil, bucket, upiddir, objectRetentionKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object retention: %w", err)
	}
	if err == nil {
		err := s.meta.StoreAttribute(f.File(), bucket, object, objectRetentionKey, ret)
		if err != nil {
			return nil, fmt.Errorf("set object retention: %w", err)
		}
	}

	// Calculate s3 compatible md5sum for complete multipart.
	s3MD5 := backend.GetMultipartMD5(parts)

	err = s.meta.StoreAttribute(f.File(), bucket, object, etagkey, []byte(s3MD5))
	if err != nil {
		return nil, fmt.Errorf("set etag attr: %w", err)
	}

	err = f.link()
	if err != nil {
		return nil, fmt.Errorf("link object in namespace: %w", err)
	}

	// cleanup tmp dirs
	os.RemoveAll(upiddir)
	// use Remove for objdir in case there are still other uploads
	// for same object name outstanding
	os.Remove(objdir)

	return &s3.CompleteMultipartUploadOutput{
		Bucket: &bucket,
		ETag:   &s3MD5,
		Key:    &object,
	}, nil
}

func (s *ScoutFS) checkUploadIDExists(bucket, object, uploadID string) ([32]byte, error) {
	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	_, err := os.Stat(filepath.Join(objdir, uploadID))
	if errors.Is(err, fs.ErrNotExist) {
		return [32]byte{}, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("stat upload: %w", err)
	}
	return sum, nil
}

// fll out the user metadata map with the metadata for the object
// and return the content type and encoding
func (s *ScoutFS) loadUserMetaData(bucket, object string, m map[string]string) (string, string) {
	ents, err := s.meta.ListAttributes(bucket, object)
	if err != nil || len(ents) == 0 {
		return "", ""
	}
	for _, e := range ents {
		if !isValidMeta(e) {
			continue
		}
		b, err := s.meta.RetrieveAttribute(nil, bucket, object, e)
		if err != nil {
			continue
		}
		if b == nil {
			m[strings.TrimPrefix(e, fmt.Sprintf("%v.", metaHdr))] = ""
			continue
		}
		m[strings.TrimPrefix(e, fmt.Sprintf("%v.", metaHdr))] = string(b)
	}

	var contentType, contentEncoding string
	b, _ := s.meta.RetrieveAttribute(nil, bucket, object, contentTypeHdr)
	contentType = string(b)
	if contentType != "" {
		m[contentTypeHdr] = contentType
	}

	b, _ = s.meta.RetrieveAttribute(nil, bucket, object, contentEncHdr)
	contentEncoding = string(b)
	if contentEncoding != "" {
		m[contentEncHdr] = contentEncoding
	}

	return contentType, contentEncoding
}

func isValidMeta(val string) bool {
	if strings.HasPrefix(val, metaHdr) {
		return true
	}
	if strings.EqualFold(val, "Expires") {
		return true
	}
	return false
}

func (s *ScoutFS) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	bucket := *input.Bucket
	object := *input.Key

	if input.PartNumber != nil {
		uploadId, sum, err := s.retrieveUploadId(bucket, object)
		if err != nil {
			return nil, err
		}

		ents, err := os.ReadDir(filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum), uploadId))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil {
			return nil, fmt.Errorf("read parts: %w", err)
		}

		partPath := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum), uploadId, fmt.Sprintf("%v", *input.PartNumber))

		part, err := os.Stat(filepath.Join(bucket, partPath))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		if errors.Is(err, syscall.ENAMETOOLONG) {
			return nil, s3err.GetAPIError(s3err.ErrKeyTooLong)
		}
		if err != nil {
			return nil, fmt.Errorf("stat part: %w", err)
		}

		b, err := s.meta.RetrieveAttribute(nil, bucket, partPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}
		partsCount := int32(len(ents))
		size := part.Size()

		return &s3.HeadObjectOutput{
			LastModified:  backend.GetTimePtr(part.ModTime()),
			ETag:          &etag,
			PartsCount:    &partsCount,
			ContentLength: &size,
		}, nil
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

	userMetaData := make(map[string]string)
	contentType, contentEncoding := s.loadUserMetaData(bucket, object, userMetaData)

	if fi.IsDir() {
		// this is the media type for directories in AWS and Nextcloud
		contentType = "application/x-directory"
	}

	b, err := s.meta.RetrieveAttribute(nil, bucket, object, etagkey)
	etag := string(b)
	if err != nil {
		etag = ""
	}

	stclass := types.StorageClassStandard
	requestOngoing := ""
	if s.glaciermode {
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
	}

	contentLength := fi.Size()

	var objectLockLegalHoldStatus types.ObjectLockLegalHoldStatus
	status, err := s.Posix.GetObjectLegalHold(ctx, bucket, object, *input.VersionId)
	if err == nil {
		if *status {
			objectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
		} else {
			objectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOff
		}
	}

	var objectLockMode types.ObjectLockMode
	var objectLockRetainUntilDate *time.Time
	retention, err := s.Posix.GetObjectRetention(ctx, bucket, object, *input.VersionId)
	if err == nil {
		var config types.ObjectLockRetention
		if err := json.Unmarshal(retention, &config); err == nil {
			objectLockMode = types.ObjectLockMode(config.Mode)
			objectLockRetainUntilDate = config.RetainUntilDate
		}
	}

	return &s3.HeadObjectOutput{
		ContentLength:             &contentLength,
		ContentType:               &contentType,
		ContentEncoding:           &contentEncoding,
		ETag:                      &etag,
		LastModified:              backend.GetTimePtr(fi.ModTime()),
		Metadata:                  userMetaData,
		StorageClass:              stclass,
		Restore:                   &requestOngoing,
		ObjectLockLegalHoldStatus: objectLockLegalHoldStatus,
		ObjectLockMode:            objectLockMode,
		ObjectLockRetainUntilDate: objectLockRetainUntilDate,
	}, nil
}

func (s *ScoutFS) retrieveUploadId(bucket, object string) (string, [32]byte, error) {
	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	entries, err := os.ReadDir(objdir)
	if err != nil || len(entries) == 0 {
		return "", [32]byte{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	return entries[0].Name(), sum, nil
}

func (s *ScoutFS) GetObject(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	bucket := *input.Bucket
	object := *input.Key
	acceptRange := *input.Range

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

	startOffset, length, err := backend.ParseRange(fi.Size(), acceptRange)
	if err != nil {
		return nil, err
	}

	objSize := fi.Size()
	if fi.IsDir() {
		// directory objects are always 0 len
		objSize = 0
		length = 0
	}

	if length == -1 {
		length = fi.Size() - startOffset + 1
	}

	if startOffset+length > fi.Size() {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	var contentRange string
	if acceptRange != "" {
		contentRange = fmt.Sprintf("bytes %v-%v/%v", startOffset, startOffset+length-1, objSize)
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

	f, err := os.Open(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("open object: %w", err)
	}

	rdr := io.NewSectionReader(f, startOffset, length)

	userMetaData := make(map[string]string)

	contentType, contentEncoding := s.loadUserMetaData(bucket, object, userMetaData)

	b, err := s.meta.RetrieveAttribute(nil, bucket, object, etagkey)
	etag := string(b)
	if err != nil {
		etag = ""
	}

	tags, err := s.getXattrTags(bucket, object)
	if err != nil {
		return nil, fmt.Errorf("get object tags: %w", err)
	}

	tagCount := int32(len(tags))

	return &s3.GetObjectOutput{
		AcceptRanges:    &acceptRange,
		ContentLength:   &length,
		ContentEncoding: &contentEncoding,
		ContentType:     &contentType,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
		TagCount:        &tagCount,
		StorageClass:    types.StorageClassStandard,
		ContentRange:    &contentRange,
		Body:            &backend.FileSectionReadCloser{R: rdr, F: f},
	}, nil
}

func (s *ScoutFS) getXattrTags(bucket, object string) (map[string]string, error) {
	tags := make(map[string]string)
	b, err := xattr.Get(filepath.Join(bucket, object), "user."+tagHdr)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if isNoAttr(err) {
		return tags, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tags: %w", err)
	}

	err = json.Unmarshal(b, &tags)
	if err != nil {
		return nil, fmt.Errorf("unmarshal tags: %w", err)
	}

	return tags, nil
}

func (s *ScoutFS) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	if input.Bucket == nil {
		return s3response.ListObjectsResult{}, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	bucket := *input.Bucket
	prefix := ""
	if input.Prefix != nil {
		prefix = *input.Prefix
	}
	marker := ""
	if input.Marker != nil {
		marker = *input.Marker
	}
	delim := ""
	if input.Delimiter != nil {
		delim = *input.Delimiter
	}
	maxkeys := int32(0)
	if input.MaxKeys != nil {
		maxkeys = *input.MaxKeys
	}

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.ListObjectsResult{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.ListObjectsResult{}, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(ctx, fileSystem, prefix, delim, marker, maxkeys,
		s.fileToObj(bucket), []string{metaTmpDir}, []string{})
	if err != nil {
		return s3response.ListObjectsResult{}, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return s3response.ListObjectsResult{
		CommonPrefixes: results.CommonPrefixes,
		Contents:       results.Objects,
		Delimiter:      &delim,
		IsTruncated:    &results.Truncated,
		Marker:         &marker,
		MaxKeys:        &maxkeys,
		Name:           &bucket,
		NextMarker:     &results.NextMarker,
		Prefix:         &prefix,
	}, nil
}

func (s *ScoutFS) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	if input.Bucket == nil {
		return s3response.ListObjectsV2Result{}, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	bucket := *input.Bucket
	prefix := ""
	if input.Prefix != nil {
		prefix = *input.Prefix
	}
	marker := ""
	if input.ContinuationToken != nil {
		marker = *input.ContinuationToken
	}
	delim := ""
	if input.Delimiter != nil {
		delim = *input.Delimiter
	}
	maxkeys := int32(0)
	if input.MaxKeys != nil {
		maxkeys = *input.MaxKeys
	}

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.ListObjectsV2Result{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.ListObjectsV2Result{}, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(ctx, fileSystem, prefix, delim, marker, int32(maxkeys),
		s.fileToObj(bucket), []string{metaTmpDir}, []string{})
	if err != nil {
		return s3response.ListObjectsV2Result{}, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return s3response.ListObjectsV2Result{
		CommonPrefixes:        results.CommonPrefixes,
		Contents:              results.Objects,
		Delimiter:             &delim,
		IsTruncated:           &results.Truncated,
		ContinuationToken:     &marker,
		MaxKeys:               &maxkeys,
		Name:                  &bucket,
		NextContinuationToken: &results.NextMarker,
		Prefix:                &prefix,
	}, nil
}

func (s *ScoutFS) fileToObj(bucket string) backend.GetObjFunc {
	return func(path string, d fs.DirEntry) (s3response.Object, error) {
		objPath := filepath.Join(bucket, path)
		if d.IsDir() {
			// directory object only happens if directory empty
			// check to see if this is a directory object by checking etag
			etagBytes, err := s.meta.RetrieveAttribute(nil, bucket, path, etagkey)
			if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
				return s3response.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return s3response.Object{}, fmt.Errorf("get etag: %w", err)
			}
			etag := string(etagBytes)

			fi, err := d.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return s3response.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return s3response.Object{}, fmt.Errorf("get fileinfo: %w", err)
			}

			key := path + "/"
			mtime := fi.ModTime()

			return s3response.Object{
				ETag:         &etag,
				Key:          &key,
				LastModified: &mtime,
				StorageClass: types.ObjectStorageClassStandard,
			}, nil
		}

		// file object, get object info and fill out object data
		b, err := s.meta.RetrieveAttribute(nil, bucket, path, etagkey)
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return s3response.Object{}, fmt.Errorf("get etag: %w", err)
		}
		// note: meta.ErrNoSuchKey will return etagBytes = []byte{}
		// so this will just set etag to "" if its not already set

		etag := string(b)

		fi, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		if err != nil {
			return s3response.Object{}, fmt.Errorf("get fileinfo: %w", err)
		}

		sc := types.ObjectStorageClassStandard
		if s.glaciermode {
			// Check if there are any offline exents associated with this file.
			// If so, we will return the InvalidObjectState error.
			st, err := statMore(objPath)
			if errors.Is(err, fs.ErrNotExist) {
				return s3response.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return s3response.Object{}, fmt.Errorf("stat more: %w", err)
			}
			if st.Offline_blocks != 0 {
				sc = types.ObjectStorageClassGlacier
			}
		}

		size := fi.Size()
		mtime := fi.ModTime()

		return s3response.Object{
			ETag:         &etag,
			Key:          &path,
			LastModified: &mtime,
			Size:         &size,
			StorageClass: sc,
		}, nil
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

func setStaging(objname string) error {
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

	newflags := oldflags | Staging

	if newflags == oldflags {
		// no flags change, just return
		return nil
	}

	return fSetNewGlobalFlags(objname, newflags)
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

func fSetNewGlobalFlags(objname string, flags uint64) error {
	b, err := json.Marshal(&flags)
	if err != nil {
		return err
	}

	return xattr.Set(objname, flagskey, b)
}

func isNoAttr(err error) bool {
	xerr, ok := err.(*xattr.Error)
	if ok && xerr.Err == xattr.ENOATTR {
		return true
	}
	return false
}
