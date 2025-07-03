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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/xattr"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/s3api/utils"
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

	// disableNoArchive is used to disable setting scoutam noarchive flag
	// on mutlipart parts. This is enabled by default to prevent archive
	// copies of temporary multipart parts.
	disableNoArchive bool
}

var _ backend.Backend = &ScoutFS{}

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
	tagHdr              = "X-Amz-Tagging"
	metaHdr             = "X-Amz-Meta"
	contentTypeHdr      = "content-type"
	contentEncHdr       = "content-encoding"
	contentLangHdr      = "content-language"
	contentDispHdr      = "content-disposition"
	cacheCtrlHdr        = "cache-control"
	expiresHdr          = "expires"
	emptyMD5            = "d41d8cd98f00b204e9800998ecf8427e"
	etagkey             = "etag"
	checksumsKey        = "checksums"
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
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	var res s3response.CompleteMultipartUploadResult

	if input.Key == nil {
		return res, "", s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if input.UploadId == nil {
		return res, "", s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if input.MultipartUpload == nil {
		return res, "", s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	bucket := *input.Bucket
	object := *input.Key
	uploadID := *input.UploadId
	parts := input.MultipartUpload.Parts

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return res, "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return res, "", fmt.Errorf("stat bucket: %w", err)
	}

	sum, err := s.checkUploadIDExists(bucket, object, uploadID)
	if err != nil {
		return res, "", err
	}

	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	checksums, err := s.retrieveChecksums(nil, bucket, filepath.Join(objdir, uploadID))
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return res, "", fmt.Errorf("get mp checksums: %w", err)
	}

	// ChecksumType should be the same as specified on CreateMultipartUpload
	if input.ChecksumType != "" && checksums.Type != input.ChecksumType {
		checksumType := checksums.Type
		if checksumType == "" {
			checksumType = types.ChecksumType("null")
		}

		return res, "", s3err.GetChecksumTypeMismatchOnMpErr(checksumType)
	}

	// check all parts ok
	last := len(parts) - 1
	var totalsize int64

	// The initialie values is the lower limit of partNumber: 0
	var partNumber int32
	for i, part := range parts {
		if part.PartNumber == nil {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		if *part.PartNumber < 1 {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidCompleteMpPartNumber)
		}
		if *part.PartNumber <= partNumber {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPartOrder)
		}

		partNumber = *part.PartNumber

		partObjPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *part.PartNumber))
		fullPartPath := filepath.Join(bucket, partObjPath)
		fi, err := os.Lstat(fullPartPath)
		if err != nil {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		totalsize += fi.Size()
		// all parts except the last need to be greater, thena
		// the minimum allowed size (5 Mib)
		if i < last && fi.Size() < backend.MinPartSize {
			return res, "", s3err.GetAPIError(s3err.ErrEntityTooSmall)
		}

		b, err := s.meta.RetrieveAttribute(nil, bucket, partObjPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}
		if parts[i].ETag == nil || !backend.AreEtagsSame(etag, *parts[i].ETag) {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		partChecksum, err := s.retrieveChecksums(nil, bucket, partObjPath)
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return res, "", fmt.Errorf("get part checksum: %w", err)
		}

		// If checksum has been provided on mp initalization
		err = validatePartChecksum(partChecksum, part)
		if err != nil {
			return res, "", err
		}
	}

	if input.MpuObjectSize != nil && totalsize != *input.MpuObjectSize {
		return res, "", s3err.GetIncorrectMpObjectSizeErr(totalsize, *input.MpuObjectSize)
	}

	// use totalsize=0 because we wont be writing to the file, only moving
	// extents around.  so we dont want to fallocate this.
	f, err := s.openTmpFile(filepath.Join(bucket, metaTmpDir), bucket, object, 0, acct)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return res, "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return res, "", fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	for _, part := range parts {
		if part.PartNumber == nil || *part.PartNumber < 1 {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		partObjPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *part.PartNumber))
		fullPartPath := filepath.Join(bucket, partObjPath)
		pf, err := os.Open(fullPartPath)
		if err != nil {
			return res, "", fmt.Errorf("open part %v: %v", *part.PartNumber, err)
		}

		// scoutfs move data is a metadata only operation that moves the data
		// extent references from the source, appeding to the destination.
		// this needs to be 4k aligned.
		err = moveData(pf, f.File())
		pf.Close()
		if err != nil {
			return res, "", fmt.Errorf("move blocks part %v: %v", *part.PartNumber, err)
		}
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	objMeta := s.loadUserMetaData(bucket, upiddir, userMetaData)
	err = s.storeObjectMetadata(f.File(), bucket, object, objMeta)
	if err != nil {
		return res, "", err
	}

	objname := filepath.Join(bucket, object)
	dir := filepath.Dir(objname)
	if dir != "" {
		uid, gid, doChown := s.getChownIDs(acct)
		err = backend.MkdirAll(dir, uid, gid, doChown, s.newDirPerm)
		if err != nil {
			return res, "", err
		}
	}

	for k, v := range userMetaData {
		err = s.meta.StoreAttribute(f.File(), bucket, object, fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			return res, "", fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// load and set tagging
	tagging, err := s.meta.RetrieveAttribute(nil, bucket, upiddir, tagHdr)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return res, "", fmt.Errorf("get object tagging: %w", err)
	}
	if err == nil {
		err := s.meta.StoreAttribute(f.File(), bucket, object, tagHdr, tagging)
		if err != nil {
			return res, "", fmt.Errorf("set object tagging: %w", err)
		}
	}

	// load and set legal hold
	lHold, err := s.meta.RetrieveAttribute(nil, bucket, upiddir, objectLegalHoldKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return res, "", fmt.Errorf("get object legal hold: %w", err)
	}
	if err == nil {
		err := s.meta.StoreAttribute(f.File(), bucket, object, objectLegalHoldKey, lHold)
		if err != nil {
			return res, "", fmt.Errorf("set object legal hold: %w", err)
		}
	}

	// load and set retention
	ret, err := s.meta.RetrieveAttribute(nil, bucket, upiddir, objectRetentionKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return res, "", fmt.Errorf("get object retention: %w", err)
	}
	if err == nil {
		err := s.meta.StoreAttribute(f.File(), bucket, object, objectRetentionKey, ret)
		if err != nil {
			return res, "", fmt.Errorf("set object retention: %w", err)
		}
	}

	// Calculate s3 compatible md5sum for complete multipart.
	s3MD5 := backend.GetMultipartMD5(parts)

	err = s.meta.StoreAttribute(f.File(), bucket, object, etagkey, []byte(s3MD5))
	if err != nil {
		return res, "", fmt.Errorf("set etag attr: %w", err)
	}

	err = f.link()
	if err != nil {
		return res, "", fmt.Errorf("link object in namespace: %w", err)
	}

	// cleanup tmp dirs
	os.RemoveAll(filepath.Join(bucket, upiddir))
	// use Remove for objdir in case there are still other uploads
	// for same object name outstanding
	os.Remove(filepath.Join(bucket, objdir))

	return s3response.CompleteMultipartUploadResult{
		Bucket: &bucket,
		ETag:   &s3MD5,
		Key:    &object,
	}, "", nil
}

func (s *ScoutFS) storeObjectMetadata(f *os.File, bucket, object string, m objectMetadata) error {
	if getString(m.ContentType) != "" {
		err := s.meta.StoreAttribute(f, bucket, object, contentTypeHdr, []byte(*m.ContentType))
		if err != nil {
			return fmt.Errorf("set content-type: %w", err)
		}
	}
	if getString(m.ContentEncoding) != "" {
		err := s.meta.StoreAttribute(f, bucket, object, contentEncHdr, []byte(*m.ContentEncoding))
		if err != nil {
			return fmt.Errorf("set content-encoding: %w", err)
		}
	}
	if getString(m.ContentDisposition) != "" {
		err := s.meta.StoreAttribute(f, bucket, object, contentDispHdr, []byte(*m.ContentDisposition))
		if err != nil {
			return fmt.Errorf("set content-disposition: %w", err)
		}
	}
	if getString(m.ContentLanguage) != "" {
		err := s.meta.StoreAttribute(f, bucket, object, contentLangHdr, []byte(*m.ContentLanguage))
		if err != nil {
			return fmt.Errorf("set content-language: %w", err)
		}
	}
	if getString(m.CacheControl) != "" {
		err := s.meta.StoreAttribute(f, bucket, object, cacheCtrlHdr, []byte(*m.CacheControl))
		if err != nil {
			return fmt.Errorf("set cache-control: %w", err)
		}
	}
	if getString(m.Expires) != "" {
		err := s.meta.StoreAttribute(f, bucket, object, expiresHdr, []byte(*m.Expires))
		if err != nil {
			return fmt.Errorf("set cache-control: %w", err)
		}
	}

	return nil
}

func validatePartChecksum(checksum s3response.Checksum, part types.CompletedPart) error {
	n := numberOfChecksums(part)
	if n > 1 {
		return s3err.GetAPIError(s3err.ErrInvalidChecksumPart)
	}
	if checksum.Algorithm == "" {
		if n != 0 {
			return s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		return nil
	}

	algo := checksum.Algorithm
	if n == 0 {
		return s3err.APIError{
			Code:           "InvalidRequest",
			Description:    fmt.Sprintf("The upload was created using a %v checksum. The complete request must include the checksum for each part. It was missing for part %v in the request.", strings.ToLower(string(algo)), *part.PartNumber),
			HTTPStatusCode: http.StatusBadRequest,
		}
	}

	for _, cs := range []struct {
		checksum         *string
		expectedChecksum string
		algo             types.ChecksumAlgorithm
	}{
		{part.ChecksumCRC32, getString(checksum.CRC32), types.ChecksumAlgorithmCrc32},
		{part.ChecksumCRC32C, getString(checksum.CRC32C), types.ChecksumAlgorithmCrc32c},
		{part.ChecksumSHA1, getString(checksum.SHA1), types.ChecksumAlgorithmSha1},
		{part.ChecksumSHA256, getString(checksum.SHA256), types.ChecksumAlgorithmSha256},
		{part.ChecksumCRC64NVME, getString(checksum.CRC64NVME), types.ChecksumAlgorithmCrc64nvme},
	} {
		if cs.checksum == nil {
			continue
		}

		if !utils.IsValidChecksum(*cs.checksum, cs.algo) {
			return s3err.GetAPIError(s3err.ErrInvalidChecksumPart)
		}

		if *cs.checksum != cs.expectedChecksum {
			if algo == cs.algo {
				return s3err.GetAPIError(s3err.ErrInvalidPart)
			}

			return s3err.APIError{
				Code:           "BadDigest",
				Description:    fmt.Sprintf("The %v you specified for part %v did not match what we received.", strings.ToLower(string(cs.algo)), *part.PartNumber),
				HTTPStatusCode: http.StatusBadRequest,
			}
		}
	}

	return nil
}

func numberOfChecksums(part types.CompletedPart) int {
	counter := 0
	if getString(part.ChecksumCRC32) != "" {
		counter++
	}
	if getString(part.ChecksumCRC32C) != "" {
		counter++
	}
	if getString(part.ChecksumSHA1) != "" {
		counter++
	}
	if getString(part.ChecksumSHA256) != "" {
		counter++
	}
	if getString(part.ChecksumCRC64NVME) != "" {
		counter++
	}

	return counter
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

type objectMetadata struct {
	ContentType        *string
	ContentEncoding    *string
	ContentDisposition *string
	ContentLanguage    *string
	CacheControl       *string
	Expires            *string
}

// fll out the user metadata map with the metadata for the object
// and return the content type and encoding
func (s *ScoutFS) loadUserMetaData(bucket, object string, m map[string]string) objectMetadata {
	ents, err := s.meta.ListAttributes(bucket, object)
	if err != nil || len(ents) == 0 {
		return objectMetadata{}
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

	var result objectMetadata

	b, err := s.meta.RetrieveAttribute(nil, bucket, object, contentTypeHdr)
	if err == nil {
		result.ContentType = backend.GetPtrFromString(string(b))
	}

	b, err = s.meta.RetrieveAttribute(nil, bucket, object, contentEncHdr)
	if err == nil {
		result.ContentEncoding = backend.GetPtrFromString(string(b))
	}

	b, err = s.meta.RetrieveAttribute(nil, bucket, object, contentDispHdr)
	if err == nil {
		result.ContentDisposition = backend.GetPtrFromString(string(b))
	}

	b, err = s.meta.RetrieveAttribute(nil, bucket, object, contentLangHdr)
	if err == nil {
		result.ContentLanguage = backend.GetPtrFromString(string(b))
	}

	b, err = s.meta.RetrieveAttribute(nil, bucket, object, cacheCtrlHdr)
	if err == nil {
		result.CacheControl = backend.GetPtrFromString(string(b))
	}

	b, err = s.meta.RetrieveAttribute(nil, bucket, object, expiresHdr)
	if err == nil {
		result.Expires = backend.GetPtrFromString(string(b))
	}

	return result
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
		s.fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return s3response.ListObjectsResult{}, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return s3response.ListObjectsResult{
		CommonPrefixes: results.CommonPrefixes,
		Contents:       results.Objects,
		Delimiter:      backend.GetPtrFromString(delim),
		Marker:         backend.GetPtrFromString(marker),
		NextMarker:     backend.GetPtrFromString(results.NextMarker),
		Prefix:         backend.GetPtrFromString(prefix),
		IsTruncated:    &results.Truncated,
		MaxKeys:        &maxkeys,
		Name:           &bucket,
	}, nil
}

func (s *ScoutFS) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	bucket := *input.Bucket
	prefix := ""
	if input.Prefix != nil {
		prefix = *input.Prefix
	}
	marker := ""
	if input.ContinuationToken != nil {
		if input.StartAfter != nil {
			marker = max(*input.StartAfter, *input.ContinuationToken)
		} else {
			marker = *input.ContinuationToken
		}
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
		s.fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return s3response.ListObjectsV2Result{}, fmt.Errorf("walk %v: %w", bucket, err)
	}

	count := int32(len(results.Objects))

	return s3response.ListObjectsV2Result{
		CommonPrefixes:        results.CommonPrefixes,
		Contents:              results.Objects,
		IsTruncated:           &results.Truncated,
		MaxKeys:               &maxkeys,
		Name:                  &bucket,
		KeyCount:              &count,
		Delimiter:             backend.GetPtrFromString(delim),
		ContinuationToken:     backend.GetPtrFromString(marker),
		NextContinuationToken: backend.GetPtrFromString(results.NextMarker),
		Prefix:                backend.GetPtrFromString(prefix),
		StartAfter:            backend.GetPtrFromString(*input.StartAfter),
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

			size := int64(0)
			mtime := fi.ModTime()

			return s3response.Object{
				ETag:         &etag,
				Key:          &path,
				LastModified: &mtime,
				Size:         &size,
				StorageClass: types.ObjectStorageClassStandard,
			}, nil
		}

		// Retreive the object checksum algorithm
		checksums, err := s.retrieveChecksums(nil, bucket, path)
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return s3response.Object{}, backend.ErrSkipObj
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
			ETag:              &etag,
			Key:               &path,
			LastModified:      &mtime,
			Size:              &size,
			StorageClass:      sc,
			ChecksumAlgorithm: []types.ChecksumAlgorithm{checksums.Algorithm},
			ChecksumType:      checksums.Type,
		}, nil
	}
}

func (s *ScoutFS) retrieveChecksums(f *os.File, bucket, object string) (checksums s3response.Checksum, err error) {
	checksumsAtr, err := s.meta.RetrieveAttribute(f, bucket, object, checksumsKey)
	if err != nil {
		return checksums, err
	}

	err = json.Unmarshal(checksumsAtr, &checksums)
	return checksums, err
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

func getString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
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
