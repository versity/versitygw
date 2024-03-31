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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/xattr"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/s3err"
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
}

var _ backend.Backend = &ScoutFS{}

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
	tagHdr              = "X-Amz-Tagging"
	emptyMD5            = "d41d8cd98f00b204e9800998ecf8427e"
	etagkey             = "user.etag"
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

// Option sets various options for scoutfs
type Option func(s *ScoutFS)

// WithGlacierEmulation sets glacier mode emulation
func WithGlacierEmulation() Option {
	return func(s *ScoutFS) { s.glaciermode = true }
}

func (s *ScoutFS) Shutdown() {
	s.Posix.Shutdown()
	s.rootfd.Close()
	_ = s.rootdir
}

func (*ScoutFS) String() string {
	return "ScoutFS Gateway"
}

// CompleteMultipartUpload scoutfs complete upload uses scoutfs move blocks
// ioctl to not have to read and copy the part data to the final object. This
// saves a read and write cycle for all mutlipart uploads.
func (s *ScoutFS) CompleteMultipartUpload(_ context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
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

	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	// check all parts ok
	last := len(parts) - 1
	partsize := int64(0)
	var totalsize int64
	for i, p := range parts {
		if p.PartNumber == nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		partPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *p.PartNumber))
		fi, err := os.Lstat(partPath)
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		if i == 0 {
			partsize = fi.Size()
		}
		totalsize += fi.Size()
		// all parts except the last need to be the same size
		if i < last && partsize != fi.Size() {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		// non-last part sizes need to be multiples of 4k for move blocks
		// TODO: fallback to no move blocks if not 4k aligned?
		if i == 0 && i < last && fi.Size()%4096 != 0 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		b, err := xattr.Get(partPath, "user.etag")
		etag := string(b)
		if err != nil {
			etag = ""
		}
		if etag != *parts[i].ETag {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
	}

	// use totalsize=0 because we wont be writing to the file, only moving
	// extents around.  so we dont want to fallocate this.
	f, err := openTmpFile(filepath.Join(bucket, metaTmpDir), bucket, object, 0)
	if err != nil {
		return nil, fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	for _, p := range parts {
		pf, err := os.Open(filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *p.PartNumber)))
		if err != nil {
			return nil, fmt.Errorf("open part %v: %v", *p.PartNumber, err)
		}

		// scoutfs move data is a metadata only operation that moves the data
		// extent references from the source, appeding to the destination.
		// this needs to be 4k aligned.
		err = moveData(pf, f.f)
		pf.Close()
		if err != nil {
			return nil, fmt.Errorf("move blocks part %v: %v", *p.PartNumber, err)
		}
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	loadUserMetaData(upiddir, userMetaData)

	objname := filepath.Join(bucket, object)
	dir := filepath.Dir(objname)
	if dir != "" {
		err = backend.MkdirAll(dir, os.FileMode(0755))
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
		}
	}
	err = f.link()
	if err != nil {
		return nil, fmt.Errorf("link object in namespace: %w", err)
	}

	for k, v := range userMetaData {
		err = xattr.Set(objname, "user."+k, []byte(v))
		if err != nil {
			// cleanup object if returning error
			os.Remove(objname)
			return nil, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// Calculate s3 compatible md5sum for complete multipart.
	s3MD5 := backend.GetMultipartMD5(parts)

	err = xattr.Set(objname, "user.etag", []byte(s3MD5))
	if err != nil {
		// cleanup object if returning error
		os.Remove(objname)
		return nil, fmt.Errorf("set etag attr: %w", err)
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

func loadUserMetaData(path string, m map[string]string) (contentType, contentEncoding string) {
	ents, err := xattr.List(path)
	if err != nil || len(ents) == 0 {
		return
	}
	for _, e := range ents {
		if !isValidMeta(e) {
			continue
		}
		b, err := xattr.Get(path, e)
		if err == errNoData {
			m[strings.TrimPrefix(e, "user.")] = ""
			continue
		}
		if err != nil {
			continue
		}
		m[strings.TrimPrefix(e, "user.")] = string(b)
	}

	b, err := xattr.Get(path, "user.content-type")
	contentType = string(b)
	if err != nil {
		contentType = ""
	}
	if contentType != "" {
		m["content-type"] = contentType
	}

	b, err = xattr.Get(path, "user.content-encoding")
	contentEncoding = string(b)
	if err != nil {
		contentEncoding = ""
	}
	if contentEncoding != "" {
		m["content-encoding"] = contentEncoding
	}

	return
}

func isValidMeta(val string) bool {
	if strings.HasPrefix(val, "user.X-Amz-Meta") {
		return true
	}
	if strings.EqualFold(val, "user.Expires") {
		return true
	}
	return false
}

func (s *ScoutFS) HeadObject(_ context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
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
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}

	userMetaData := make(map[string]string)
	contentType, contentEncoding := loadUserMetaData(objPath, userMetaData)

	b, err := xattr.Get(objPath, etagkey)
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

	return &s3.HeadObjectOutput{
		ContentLength:   &contentLength,
		ContentType:     &contentType,
		ContentEncoding: &contentEncoding,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
		StorageClass:    stclass,
		Restore:         &requestOngoing,
	}, nil
}

func (s *ScoutFS) GetObject(_ context.Context, input *s3.GetObjectInput, writer io.Writer) (*s3.GetObjectOutput, error) {
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
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}

	startOffset, length, err := backend.ParseRange(fi, acceptRange)
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
	defer f.Close()

	rdr := io.NewSectionReader(f, startOffset, length)
	_, err = io.Copy(writer, rdr)
	if err != nil {
		return nil, fmt.Errorf("copy data: %w", err)
	}

	userMetaData := make(map[string]string)

	contentType, contentEncoding := loadUserMetaData(objPath, userMetaData)

	b, err := xattr.Get(objPath, etagkey)
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

func (s *ScoutFS) ListObjects(_ context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
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
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(fileSystem, prefix, delim, marker, maxkeys,
		s.fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return nil, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return &s3.ListObjectsOutput{
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

func (s *ScoutFS) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
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
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(fileSystem, prefix, delim, marker, int32(maxkeys),
		s.fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return nil, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return &s3.ListObjectsV2Output{
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
	return func(path string, d fs.DirEntry) (types.Object, error) {
		objPath := filepath.Join(bucket, path)
		if d.IsDir() {
			// directory object only happens if directory empty
			// check to see if this is a directory object by checking etag
			etagBytes, err := xattr.Get(objPath, etagkey)
			if isNoAttr(err) || errors.Is(err, fs.ErrNotExist) {
				return types.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return types.Object{}, fmt.Errorf("get etag: %w", err)
			}
			etag := string(etagBytes)

			fi, err := d.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return types.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return types.Object{}, fmt.Errorf("get fileinfo: %w", err)
			}

			key := path + "/"

			return types.Object{
				ETag:         &etag,
				Key:          &key,
				LastModified: backend.GetTimePtr(fi.ModTime()),
			}, nil
		}

		// file object, get object info and fill out object data
		etagBytes, err := xattr.Get(objPath, etagkey)
		if errors.Is(err, fs.ErrNotExist) {
			return types.Object{}, backend.ErrSkipObj
		}
		if err != nil && !isNoAttr(err) {
			return types.Object{}, fmt.Errorf("get etag: %w", err)
		}
		etag := string(etagBytes)

		fi, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return types.Object{}, backend.ErrSkipObj
		}
		if err != nil {
			return types.Object{}, fmt.Errorf("get fileinfo: %w", err)
		}

		sc := types.ObjectStorageClassStandard
		if s.glaciermode {
			// Check if there are any offline exents associated with this file.
			// If so, we will return the InvalidObjectState error.
			st, err := statMore(objPath)
			if errors.Is(err, fs.ErrNotExist) {
				return types.Object{}, backend.ErrSkipObj
			}
			if err != nil {
				return types.Object{}, fmt.Errorf("stat more: %w", err)
			}
			if st.Offline_blocks != 0 {
				sc = types.ObjectStorageClassGlacier
			}
		}

		size := fi.Size()

		return types.Object{
			ETag:         &etag,
			Key:          &path,
			LastModified: backend.GetTimePtr(fi.ModTime()),
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
	if err == nil {
		return false
	}
	xerr, ok := err.(*xattr.Error)
	if ok && xerr.Err == xattr.ENOATTR {
		return true
	}
	if err == errNoData {
		return true
	}
	return false
}
