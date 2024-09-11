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

package posix

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type Posix struct {
	backend.BackendUnsupported

	// bucket/object metadata storage facility
	meta meta.MetadataStorer

	rootfd  *os.File
	rootdir string

	// chownuid/gid enable chowning of files to the account uid/gid
	// when objects are uploaded
	chownuid bool
	chowngid bool

	// euid/egid are the effective uid/gid of the running versitygw process
	// used to determine if chowning is needed
	euid int
	egid int

	// bucketlinks is a flag to enable symlinks to directories at the top
	// level gateway directory to be treated as buckets the same as directories
	bucketlinks bool
}

var _ backend.Backend = &Posix{}

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
	onameAttr           = "objname"
	tagHdr              = "X-Amz-Tagging"
	metaHdr             = "X-Amz-Meta"
	contentTypeHdr      = "content-type"
	contentEncHdr       = "content-encoding"
	emptyMD5            = "d41d8cd98f00b204e9800998ecf8427e"
	aclkey              = "acl"
	ownershipkey        = "ownership"
	etagkey             = "etag"
	policykey           = "policy"
	bucketLockKey       = "bucket-lock"
	objectRetentionKey  = "object-retention"
	objectLegalHoldKey  = "object-legal-hold"

	doFalloc   = true
	skipFalloc = false
)

type PosixOpts struct {
	ChownUID    bool
	ChownGID    bool
	BucketLinks bool
}

func New(rootdir string, meta meta.MetadataStorer, opts PosixOpts) (*Posix, error) {
	err := os.Chdir(rootdir)
	if err != nil {
		return nil, fmt.Errorf("chdir %v: %w", rootdir, err)
	}

	f, err := os.Open(rootdir)
	if err != nil {
		return nil, fmt.Errorf("open %v: %w", rootdir, err)
	}

	return &Posix{
		meta:        meta,
		rootfd:      f,
		rootdir:     rootdir,
		euid:        os.Geteuid(),
		egid:        os.Getegid(),
		chownuid:    opts.ChownUID,
		chowngid:    opts.ChownGID,
		bucketlinks: opts.BucketLinks,
	}, nil
}

func (p *Posix) Shutdown() {
	p.rootfd.Close()
}

func (p *Posix) String() string {
	return "Posix Gateway"
}

func (p *Posix) ListBuckets(_ context.Context, owner string, isAdmin bool) (s3response.ListAllMyBucketsResult, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return s3response.ListAllMyBucketsResult{},
			fmt.Errorf("readdir buckets: %w", err)
	}

	var buckets []s3response.ListAllMyBucketsEntry
	for _, entry := range entries {
		fi, err := entry.Info()
		if err != nil {
			// skip entries returning errors
			continue
		}

		if p.bucketlinks && entry.Type() == fs.ModeSymlink {
			fi, err = os.Stat(entry.Name())
			if err != nil {
				// skip entries returning errors
				continue
			}
		}

		if !fi.IsDir() {
			// buckets must be a directory
			continue
		}

		// return all the buckets for admin users
		if isAdmin {
			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name:         entry.Name(),
				CreationDate: fi.ModTime(),
			})
			continue
		}

		aclTag, err := p.meta.RetrieveAttribute(entry.Name(), "", aclkey)
		if errors.Is(err, meta.ErrNoSuchKey) {
			// skip buckets without acl tag
			continue
		}
		if err != nil {
			return s3response.ListAllMyBucketsResult{}, fmt.Errorf("get acl tag: %w", err)
		}

		var acl auth.ACL
		err = json.Unmarshal(aclTag, &acl)
		if err != nil {
			return s3response.ListAllMyBucketsResult{}, fmt.Errorf("parse acl tag: %w", err)
		}

		if acl.Owner == owner {
			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name:         entry.Name(),
				CreationDate: fi.ModTime(),
			})
		}
	}

	sort.Sort(backend.ByBucketName(buckets))

	return s3response.ListAllMyBucketsResult{
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: buckets,
		},
		Owner: s3response.CanonicalUser{
			ID: owner,
		},
	}, nil
}

func (p *Posix) HeadBucket(_ context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

	_, err := os.Lstat(*input.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	return &s3.HeadBucketOutput{}, nil
}

var (
	// TODO: make this configurable
	defaultDirPerm fs.FileMode = 0755
)

func (p *Posix) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, acl []byte) error {
	if input.Bucket == nil {
		return s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	uid, gid, doChown := p.getChownIDs(acct)

	bucket := *input.Bucket

	err := os.Mkdir(bucket, defaultDirPerm)
	if err != nil && os.IsExist(err) {
		aclJSON, err := p.meta.RetrieveAttribute(bucket, "", aclkey)
		if err != nil {
			return fmt.Errorf("get bucket acl: %w", err)
		}
		var acl auth.ACL
		if err := json.Unmarshal(aclJSON, &acl); err != nil {
			return fmt.Errorf("unmarshal acl: %w", err)
		}

		if acl.Owner == acct.Access {
			return s3err.GetAPIError(s3err.ErrBucketAlreadyOwnedByYou)
		}
		return s3err.GetAPIError(s3err.ErrBucketAlreadyExists)
	}
	if err != nil {
		return fmt.Errorf("mkdir bucket: %w", err)
	}

	if doChown {
		err := os.Chown(bucket, uid, gid)
		if err != nil {
			return fmt.Errorf("chown bucket: %w", err)
		}
	}

	if err := p.meta.StoreAttribute(bucket, "", aclkey, acl); err != nil {
		return fmt.Errorf("set acl: %w", err)
	}
	if err := p.meta.StoreAttribute(bucket, "", ownershipkey, []byte(input.ObjectOwnership)); err != nil {
		return fmt.Errorf("set ownership: %w", err)
	}

	if input.ObjectLockEnabledForBucket != nil && *input.ObjectLockEnabledForBucket {
		now := time.Now()
		defaultLock := auth.BucketLockConfig{
			Enabled:   true,
			CreatedAt: &now,
		}

		defaultLockParsed, err := json.Marshal(defaultLock)
		if err != nil {
			return fmt.Errorf("parse default bucket lock state: %w", err)
		}

		if err := p.meta.StoreAttribute(bucket, "", bucketLockKey, defaultLockParsed); err != nil {
			return fmt.Errorf("set default bucket lock: %w", err)
		}
	}

	return nil
}

func (p *Posix) DeleteBucket(_ context.Context, input *s3.DeleteBucketInput) error {
	if input.Bucket == nil {
		return s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

	names, err := os.ReadDir(*input.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("readdir bucket: %w", err)
	}

	if len(names) == 1 && names[0].Name() == metaTmpDir {
		// if .sgwtmp is only item in directory
		// then clean this up before trying to remove the bucket
		err = os.RemoveAll(filepath.Join(*input.Bucket, metaTmpDir))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove temp dir: %w", err)
		}
	}

	err = os.Remove(*input.Bucket)
	if err != nil && err.(*os.PathError).Err == syscall.ENOTEMPTY {
		return s3err.GetAPIError(s3err.ErrBucketNotEmpty)
	}
	if err != nil {
		return fmt.Errorf("remove bucket: %w", err)
	}

	err = p.meta.DeleteAttributes(*input.Bucket, "")
	if err != nil {
		return fmt.Errorf("remove bucket attributes: %w", err)
	}

	return nil
}

func (p *Posix) PutBucketOwnershipControls(_ context.Context, bucket string, ownership types.ObjectOwnership) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if err := p.meta.StoreAttribute(bucket, "", ownershipkey, []byte(ownership)); err != nil {
		return fmt.Errorf("set ownership: %w", err)
	}

	return nil
}
func (p *Posix) GetBucketOwnershipControls(_ context.Context, bucket string) (types.ObjectOwnership, error) {
	var ownship types.ObjectOwnership
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return ownship, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return ownship, fmt.Errorf("stat bucket: %w", err)
	}

	ownership, err := p.meta.RetrieveAttribute(bucket, "", ownershipkey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return ownship, s3err.GetAPIError(s3err.ErrOwnershipControlsNotFound)
	}
	if err != nil {
		return ownship, fmt.Errorf("get bucket ownership status: %w", err)
	}

	return types.ObjectOwnership(ownership), nil
}
func (p *Posix) DeleteBucketOwnershipControls(_ context.Context, bucket string) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if err := p.meta.DeleteAttribute(bucket, "", ownershipkey); err != nil {
		if errors.Is(err, meta.ErrNoSuchKey) {
			return nil
		}

		return fmt.Errorf("delete ownership: %w", err)
	}

	return nil
}

func (p *Posix) CreateMultipartUpload(ctx context.Context, mpu *s3.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	if mpu.Bucket == nil {
		return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if mpu.Key == nil {
		return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	bucket := *mpu.Bucket
	object := *mpu.Key

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("stat bucket: %w", err)
	}

	if strings.HasSuffix(*mpu.Key, "/") {
		// directory objects can't be uploaded with mutlipart uploads
		// because posix directories can't contain data
		return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
	}

	// parse object tags
	tagsStr := getString(mpu.Tagging)
	tags := make(map[string]string)
	if tagsStr != "" {
		tagParts := strings.Split(tagsStr, "&")
		for _, prt := range tagParts {
			p := strings.Split(prt, "=")
			if len(p) != 2 {
				return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrInvalidTag)
			}
			if len(p[0]) > 128 || len(p[1]) > 256 {
				return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrInvalidTag)
			}
			tags[p[0]] = p[1]
		}
	}

	// generate random uuid for upload id
	uploadID := uuid.New().String()
	// hash object name for multipart container
	objNameSum := sha256.Sum256([]byte(*mpu.Key))
	// multiple uploads for same object name allowed,
	// they will all go into the same hashed name directory
	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", objNameSum))
	tmppath := filepath.Join(bucket, objdir)
	// the unique upload id is a directory for all of the parts
	// associated with this specific multipart upload
	err = os.MkdirAll(filepath.Join(tmppath, uploadID), 0755)
	if err != nil {
		return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("create upload temp dir: %w", err)
	}

	// set an attribute with the original object name so that we can
	// map the hashed name back to the original object name
	err = p.meta.StoreAttribute(bucket, objdir, onameAttr, []byte(object))
	if err != nil {
		// if we fail, cleanup the container directories
		// but ignore errors because there might still be
		// other uploads for the same object name outstanding
		os.RemoveAll(filepath.Join(tmppath, uploadID))
		os.Remove(tmppath)
		return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("set name attr for upload: %w", err)
	}

	// set user metadata
	for k, v := range mpu.Metadata {
		err := p.meta.StoreAttribute(bucket, filepath.Join(objdir, uploadID),
			fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// set object tagging
	if tagsStr != "" {
		err := p.PutObjectTagging(ctx, bucket, filepath.Join(objdir, uploadID), tags)
		if err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, err
		}
	}

	// set content-type
	ctype := getString(mpu.ContentType)
	if ctype != "" {
		err := p.meta.StoreAttribute(bucket, filepath.Join(objdir, uploadID),
			contentTypeHdr, []byte(*mpu.ContentType))
		if err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("set content-type: %w", err)
		}
	}

	// set content-encoding
	cenc := getString(mpu.ContentEncoding)
	if cenc != "" {
		err := p.meta.StoreAttribute(bucket, filepath.Join(objdir, uploadID), contentEncHdr,
			[]byte(*mpu.ContentEncoding))
		if err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("set content-encoding: %w", err)
		}
	}

	// set object legal hold
	if mpu.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn {
		if err := p.PutObjectLegalHold(ctx, bucket, filepath.Join(objdir, uploadID), "", true); err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, err
		}
	}

	// Set object retention
	if mpu.ObjectLockMode != "" {
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(mpu.ObjectLockMode),
			RetainUntilDate: mpu.ObjectLockRetainUntilDate,
		}
		retParsed, err := json.Marshal(retention)
		if err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("parse object lock retention: %w", err)
		}
		if err := p.PutObjectRetention(ctx, bucket, filepath.Join(objdir, uploadID), "", true, retParsed); err != nil {
			// cleanup object if returning error
			os.RemoveAll(filepath.Join(tmppath, uploadID))
			os.Remove(tmppath)
			return s3response.InitiateMultipartUploadResult{}, err
		}
	}

	return s3response.InitiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      object,
		UploadId: uploadID,
	}, nil
}

// getChownIDs returns the uid and gid that should be used for chowning
// the object to the account uid/gid. It also returns a boolean indicating
// if chowning is needed.
func (p *Posix) getChownIDs(acct auth.Account) (int, int, bool) {
	uid := p.euid
	gid := p.egid
	var needsChown bool
	if p.chownuid && acct.UserID != p.euid {
		uid = acct.UserID
		needsChown = true
	}
	if p.chowngid && acct.GroupID != p.egid {
		gid = acct.GroupID
		needsChown = true
	}

	return uid, gid, needsChown
}

func (p *Posix) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
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

	sum, err := p.checkUploadIDExists(bucket, object, uploadID)
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
		totalsize += fi.Size()
		// all parts except the last need to be the same size
		if i < last && partsize != fi.Size() {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		b, err := p.meta.RetrieveAttribute(bucket, partObjPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}
		if parts[i].ETag == nil || etag != *parts[i].ETag {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
	}

	f, err := p.openTmpFile(filepath.Join(bucket, metaTmpDir), bucket, object,
		totalsize, acct, skipFalloc)
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
		_, err = io.Copy(f.File(), pf)
		pf.Close()
		if err != nil {
			if errors.Is(err, syscall.EDQUOT) {
				return nil, s3err.GetAPIError(s3err.ErrQuotaExceeded)
			}
			return nil, fmt.Errorf("copy part %v: %v", part.PartNumber, err)
		}
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	cType, cEnc := p.loadUserMetaData(bucket, upiddir, userMetaData)

	objname := filepath.Join(bucket, object)
	dir := filepath.Dir(objname)
	if dir != "" {
		uid, gid, doChown := p.getChownIDs(acct)
		err = backend.MkdirAll(dir, uid, gid, doChown)
		if err != nil {
			return nil, err
		}
	}
	err = f.link()
	if err != nil {
		return nil, fmt.Errorf("link object in namespace: %w", err)
	}

	for k, v := range userMetaData {
		err = p.meta.StoreAttribute(bucket, object, fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			// cleanup object if returning error
			os.Remove(objname)
			return nil, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// load and set tagging
	tagging, err := p.meta.RetrieveAttribute(bucket, upiddir, tagHdr)
	if err == nil {
		if err := p.meta.StoreAttribute(bucket, object, tagHdr, tagging); err != nil {
			// cleanup object
			os.Remove(objname)
			return nil, fmt.Errorf("set object tagging: %w", err)
		}
	}
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object tagging: %w", err)
	}

	// set content-type
	if cType != "" {
		if err := p.meta.StoreAttribute(bucket, object, contentTypeHdr, []byte(cType)); err != nil {
			// cleanup object
			os.Remove(objname)
			return nil, fmt.Errorf("set object content type: %w", err)
		}
	}

	// set content-encoding
	if cEnc != "" {
		if err := p.meta.StoreAttribute(bucket, object, contentEncHdr, []byte(cEnc)); err != nil {
			// cleanup object
			os.Remove(objname)
			return nil, fmt.Errorf("set object content encoding: %w", err)
		}
	}

	// load and set legal hold
	lHold, err := p.meta.RetrieveAttribute(bucket, upiddir, objectLegalHoldKey)
	if err == nil {
		if err := p.meta.StoreAttribute(bucket, object, objectLegalHoldKey, lHold); err != nil {
			// cleanup object
			os.Remove(objname)
			return nil, fmt.Errorf("set object legal hold: %w", err)
		}
	}
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object legal hold: %w", err)
	}

	// load and set retention
	ret, err := p.meta.RetrieveAttribute(bucket, upiddir, objectRetentionKey)
	if err == nil {
		if err := p.meta.StoreAttribute(bucket, object, objectRetentionKey, ret); err != nil {
			// cleanup object
			os.Remove(objname)
			return nil, fmt.Errorf("set object retention: %w", err)
		}
	}
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object retention: %w", err)
	}

	// Calculate s3 compatible md5sum for complete multipart.
	s3MD5 := backend.GetMultipartMD5(parts)

	err = p.meta.StoreAttribute(bucket, object, etagkey, []byte(s3MD5))
	if err != nil {
		// cleanup object if returning error
		os.Remove(objname)
		return nil, fmt.Errorf("set etag attr: %w", err)
	}

	// cleanup tmp dirs
	os.RemoveAll(filepath.Join(bucket, objdir, uploadID))
	// use Remove for objdir in case there are still other uploads
	// for same object name outstanding, this will fail if there are
	os.Remove(filepath.Join(bucket, objdir))

	return &s3.CompleteMultipartUploadOutput{
		Bucket: &bucket,
		ETag:   &s3MD5,
		Key:    &object,
	}, nil
}

func (p *Posix) checkUploadIDExists(bucket, object, uploadID string) ([32]byte, error) {
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

func (p *Posix) retrieveUploadId(bucket, object string) (string, [32]byte, error) {
	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	entries, err := os.ReadDir(objdir)
	if err != nil || len(entries) == 0 {
		return "", [32]byte{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	return entries[0].Name(), sum, nil
}

// fll out the user metadata map with the metadata for the object
// and return the content type and encoding
func (p *Posix) loadUserMetaData(bucket, object string, m map[string]string) (string, string) {
	ents, err := p.meta.ListAttributes(bucket, object)
	if err != nil || len(ents) == 0 {
		return "", ""
	}
	for _, e := range ents {
		if !isValidMeta(e) {
			continue
		}
		b, err := p.meta.RetrieveAttribute(bucket, object, e)
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
	b, _ := p.meta.RetrieveAttribute(bucket, object, contentTypeHdr)
	contentType = string(b)

	b, _ = p.meta.RetrieveAttribute(bucket, object, contentEncHdr)
	contentEncoding = string(b)

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

func (p *Posix) AbortMultipartUpload(_ context.Context, mpu *s3.AbortMultipartUploadInput) error {
	if mpu.Bucket == nil {
		return s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if mpu.Key == nil {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if mpu.UploadId == nil {
		return s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}

	bucket := *mpu.Bucket
	object := *mpu.Key
	uploadID := *mpu.UploadId

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	_, err = os.Stat(filepath.Join(objdir, uploadID))
	if err != nil {
		return s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}

	err = os.RemoveAll(filepath.Join(objdir, uploadID))
	if err != nil {
		return fmt.Errorf("remove multipart upload container: %w", err)
	}
	os.Remove(objdir)

	return nil
}

func (p *Posix) ListMultipartUploads(_ context.Context, mpu *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	var lmu s3response.ListMultipartUploadsResult

	if mpu.Bucket == nil {
		return lmu, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}

	bucket := *mpu.Bucket
	var delimiter string
	if mpu.Delimiter != nil {
		delimiter = *mpu.Delimiter
	}
	var prefix string
	if mpu.Prefix != nil {
		prefix = *mpu.Prefix
	}

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return lmu, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return lmu, fmt.Errorf("stat bucket: %w", err)
	}

	// ignore readdir error and use the empty list returned
	objs, _ := os.ReadDir(filepath.Join(bucket, metaTmpMultipartDir))

	var uploads []s3response.Upload
	var resultUpds []s3response.Upload

	var keyMarker string
	if mpu.KeyMarker != nil {
		keyMarker = *mpu.KeyMarker
	}
	var uploadIDMarker string
	if mpu.UploadIdMarker != nil {
		uploadIDMarker = *mpu.UploadIdMarker
	}
	keyMarkerInd, uploadIdMarkerFound := -1, false

	for _, obj := range objs {
		if !obj.IsDir() {
			continue
		}

		b, err := p.meta.RetrieveAttribute(bucket, filepath.Join(metaTmpMultipartDir, obj.Name()), onameAttr)
		if err != nil {
			continue
		}
		objectName := string(b)
		if mpu.Prefix != nil && !strings.HasPrefix(objectName, *mpu.Prefix) {
			continue
		}

		upids, err := os.ReadDir(filepath.Join(bucket, metaTmpMultipartDir, obj.Name()))
		if err != nil {
			continue
		}

		for _, upid := range upids {
			if !upid.IsDir() {
				continue
			}

			// userMetaData := make(map[string]string)
			// upiddir := filepath.Join(bucket, metaTmpMultipartDir, obj.Name(), upid.Name())
			// loadUserMetaData(upiddir, userMetaData)

			fi, err := upid.Info()
			if err != nil {
				return lmu, fmt.Errorf("stat %q: %w", upid.Name(), err)
			}

			uploadID := upid.Name()
			if !uploadIdMarkerFound && uploadIDMarker == uploadID {
				uploadIdMarkerFound = true
			}
			if keyMarkerInd == -1 && objectName == keyMarker {
				keyMarkerInd = len(uploads)
			}
			uploads = append(uploads, s3response.Upload{
				Key:          objectName,
				UploadID:     uploadID,
				StorageClass: types.StorageClassStandard,
				Initiated:    fi.ModTime(),
			})
		}
	}

	maxUploads := 0
	if mpu.MaxUploads != nil {
		maxUploads = int(*mpu.MaxUploads)
	}
	if (uploadIDMarker != "" && !uploadIdMarkerFound) || (keyMarker != "" && keyMarkerInd == -1) {
		return s3response.ListMultipartUploadsResult{
			Bucket:         bucket,
			Delimiter:      delimiter,
			KeyMarker:      keyMarker,
			MaxUploads:     maxUploads,
			Prefix:         prefix,
			UploadIDMarker: uploadIDMarker,
			Uploads:        []s3response.Upload{},
		}, nil
	}

	sort.SliceStable(uploads, func(i, j int) bool {
		return uploads[i].Key < uploads[j].Key
	})

	for i := keyMarkerInd + 1; i < len(uploads); i++ {
		if maxUploads == 0 {
			break
		}
		if keyMarker != "" && uploadIDMarker != "" && uploads[i].UploadID < uploadIDMarker {
			continue
		}
		if i != len(uploads)-1 && len(resultUpds) == maxUploads {
			return s3response.ListMultipartUploadsResult{
				Bucket:             bucket,
				Delimiter:          delimiter,
				KeyMarker:          keyMarker,
				MaxUploads:         maxUploads,
				NextKeyMarker:      resultUpds[i-1].Key,
				NextUploadIDMarker: resultUpds[i-1].UploadID,
				IsTruncated:        true,
				Prefix:             prefix,
				UploadIDMarker:     uploadIDMarker,
				Uploads:            resultUpds,
			}, nil
		}

		resultUpds = append(resultUpds, uploads[i])
	}

	return s3response.ListMultipartUploadsResult{
		Bucket:         bucket,
		Delimiter:      delimiter,
		KeyMarker:      keyMarker,
		MaxUploads:     maxUploads,
		Prefix:         prefix,
		UploadIDMarker: uploadIDMarker,
		Uploads:        resultUpds,
	}, nil
}

func (p *Posix) ListParts(_ context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	var lpr s3response.ListPartsResult

	if input.Bucket == nil {
		return lpr, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return lpr, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if input.UploadId == nil {
		return lpr, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}

	bucket := *input.Bucket
	object := *input.Key
	uploadID := *input.UploadId
	stringMarker := ""
	if input.PartNumberMarker != nil {
		stringMarker = *input.PartNumberMarker
	}
	maxParts := 0
	if input.MaxParts != nil {
		maxParts = int(*input.MaxParts)
	}

	var partNumberMarker int
	if stringMarker != "" {
		var err error
		partNumberMarker, err = strconv.Atoi(stringMarker)
		if err != nil {
			return lpr, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker)
		}
	}

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return lpr, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return lpr, fmt.Errorf("stat bucket: %w", err)
	}

	sum, err := p.checkUploadIDExists(bucket, object, uploadID)
	if err != nil {
		return lpr, err
	}

	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum))
	tmpdir := filepath.Join(bucket, objdir)

	ents, err := os.ReadDir(filepath.Join(tmpdir, uploadID))
	if errors.Is(err, fs.ErrNotExist) {
		return lpr, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if err != nil {
		return lpr, fmt.Errorf("readdir upload: %w", err)
	}

	var parts []s3response.Part
	for _, e := range ents {
		pn, err := strconv.Atoi(e.Name())
		if err != nil {
			// file is not a valid part file
			continue
		}
		if pn <= partNumberMarker {
			continue
		}

		partPath := filepath.Join(objdir, uploadID, e.Name())
		b, err := p.meta.RetrieveAttribute(bucket, partPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}

		fi, err := os.Lstat(filepath.Join(bucket, partPath))
		if err != nil {
			continue
		}

		parts = append(parts, s3response.Part{
			PartNumber:   pn,
			ETag:         etag,
			LastModified: fi.ModTime(),
			Size:         fi.Size(),
		})
	}

	sort.Slice(parts,
		func(i int, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })

	oldLen := len(parts)
	if maxParts > 0 && len(parts) > maxParts {
		parts = parts[:maxParts]
	}
	newLen := len(parts)

	nextpart := 0
	if len(parts) != 0 {
		nextpart = parts[len(parts)-1].PartNumber
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	p.loadUserMetaData(bucket, upiddir, userMetaData)

	return s3response.ListPartsResult{
		Bucket:               bucket,
		IsTruncated:          oldLen != newLen,
		Key:                  object,
		MaxParts:             maxParts,
		NextPartNumberMarker: nextpart,
		PartNumberMarker:     partNumberMarker,
		Parts:                parts,
		UploadID:             uploadID,
		StorageClass:         types.StorageClassStandard,
	}, nil
}

func (p *Posix) UploadPart(ctx context.Context, input *s3.UploadPartInput) (string, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	if input.Bucket == nil {
		return "", s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return "", s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	bucket := *input.Bucket
	object := *input.Key
	uploadID := *input.UploadId
	part := input.PartNumber
	length := int64(0)
	if input.ContentLength != nil {
		length = *input.ContentLength
	}
	r := input.Body

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return "", fmt.Errorf("stat bucket: %w", err)
	}

	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	_, err = os.Stat(filepath.Join(bucket, objdir, uploadID))
	if errors.Is(err, fs.ErrNotExist) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if err != nil {
		return "", fmt.Errorf("stat uploadid: %w", err)
	}

	partPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", *part))

	f, err := p.openTmpFile(filepath.Join(bucket, objdir),
		bucket, partPath, length, acct, doFalloc)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return "", fmt.Errorf("open temp file: %w", err)
	}

	hash := md5.New()
	tr := io.TeeReader(r, hash)
	_, err = io.Copy(f, tr)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return "", fmt.Errorf("write part data: %w", err)
	}

	err = f.link()
	if err != nil {
		return "", fmt.Errorf("link object in namespace: %w", err)
	}

	f.cleanup()

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum)
	err = p.meta.StoreAttribute(bucket, partPath, etagkey, []byte(etag))
	if err != nil {
		return "", fmt.Errorf("set etag attr: %w", err)
	}

	return etag, nil
}

func (p *Posix) UploadPartCopy(ctx context.Context, upi *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	if upi.Bucket == nil {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if upi.Key == nil {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	_, err := os.Stat(*upi.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat bucket: %w", err)
	}

	sum := sha256.Sum256([]byte(*upi.Key))
	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	_, err = os.Stat(filepath.Join(*upi.Bucket, objdir, *upi.UploadId))
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat uploadid: %w", err)
	}

	partPath := filepath.Join(objdir, *upi.UploadId, fmt.Sprintf("%v", *upi.PartNumber))

	substrs := strings.SplitN(*upi.CopySource, "/", 2)
	if len(substrs) != 2 {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrInvalidCopySource)
	}

	srcBucket := substrs[0]
	srcObject := substrs[1]

	_, err = os.Stat(srcBucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat bucket: %w", err)
	}

	objPath := filepath.Join(srcBucket, srcObject)
	fi, err := os.Stat(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat object: %w", err)
	}

	startOffset, length, err := backend.ParseRange(fi.Size(), *upi.CopySourceRange)
	if err != nil {
		return s3response.CopyObjectResult{}, err
	}

	if length == -1 {
		length = fi.Size() - startOffset + 1
	}

	if startOffset+length > fi.Size()+1 {
		return s3response.CopyObjectResult{}, backend.CreateExceedingRangeErr(fi.Size())
	}

	f, err := p.openTmpFile(filepath.Join(*upi.Bucket, objdir),
		*upi.Bucket, partPath, length, acct, doFalloc)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return s3response.CopyObjectResult{}, fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	srcf, err := os.Open(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("open object: %w", err)
	}
	defer srcf.Close()

	rdr := io.NewSectionReader(srcf, startOffset, length)
	hash := md5.New()
	tr := io.TeeReader(rdr, hash)

	_, err = io.Copy(f, tr)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return s3response.CopyObjectResult{}, fmt.Errorf("copy part data: %w", err)
	}

	err = f.link()
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("link object in namespace: %w", err)
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum)
	err = p.meta.StoreAttribute(*upi.Bucket, partPath, etagkey, []byte(etag))
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("set etag attr: %w", err)
	}

	fi, err = os.Stat(filepath.Join(*upi.Bucket, partPath))
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat part path: %w", err)
	}

	return s3response.CopyObjectResult{
		ETag:         etag,
		LastModified: fi.ModTime(),
	}, nil
}

func (p *Posix) PutObject(ctx context.Context, po *s3.PutObjectInput) (string, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	if po.Bucket == nil {
		return "", s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if po.Key == nil {
		return "", s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	tagsStr := getString(po.Tagging)
	tags := make(map[string]string)
	_, err := os.Stat(*po.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return "", fmt.Errorf("stat bucket: %w", err)
	}

	if tagsStr != "" {
		tagParts := strings.Split(tagsStr, "&")
		for _, prt := range tagParts {
			p := strings.Split(prt, "=")
			if len(p) != 2 {
				return "", s3err.GetAPIError(s3err.ErrInvalidTag)
			}
			if len(p[0]) > 128 || len(p[1]) > 256 {
				return "", s3err.GetAPIError(s3err.ErrInvalidTag)
			}
			tags[p[0]] = p[1]
		}
	}

	name := filepath.Join(*po.Bucket, *po.Key)

	uid, gid, doChown := p.getChownIDs(acct)

	contentLength := int64(0)
	if po.ContentLength != nil {
		contentLength = *po.ContentLength
	}
	if strings.HasSuffix(*po.Key, "/") {
		// object is directory
		if contentLength != 0 {
			// posix directories can't contain data, send error
			// if reuests has a data payload associated with a
			// directory object
			return "", s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
		}

		err = backend.MkdirAll(name, uid, gid, doChown)
		if err != nil {
			if errors.Is(err, syscall.EDQUOT) {
				return "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
			}
			return "", err
		}

		for k, v := range po.Metadata {
			err := p.meta.StoreAttribute(*po.Bucket, *po.Key,
				fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
			if err != nil {
				return "", fmt.Errorf("set user attr %q: %w", k, err)
			}
		}

		// set etag attribute to signify this dir was specifically put
		err = p.meta.StoreAttribute(*po.Bucket, *po.Key, etagkey,
			[]byte(emptyMD5))
		if err != nil {
			return "", fmt.Errorf("set etag attr: %w", err)
		}

		return emptyMD5, nil
	}

	// object is file
	d, err := os.Stat(name)
	if err == nil && d.IsDir() {
		return "", s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return "", s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("stat object: %w", err)
	}

	f, err := p.openTmpFile(filepath.Join(*po.Bucket, metaTmpDir),
		*po.Bucket, *po.Key, contentLength, acct, doFalloc)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return "", fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	hash := md5.New()
	rdr := io.TeeReader(po.Body, hash)
	_, err = io.Copy(f, rdr)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return "", fmt.Errorf("write object data: %w", err)
	}
	dir := filepath.Dir(name)
	if dir != "" {
		err = backend.MkdirAll(dir, uid, gid, doChown)
		if err != nil {
			return "", s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
		}
	}

	err = f.link()
	if err != nil {
		return "", s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
	}

	for k, v := range po.Metadata {
		err := p.meta.StoreAttribute(*po.Bucket, *po.Key,
			fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			return "", fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// Set object tagging
	if tagsStr != "" {
		err := p.PutObjectTagging(ctx, *po.Bucket, *po.Key, tags)
		if err != nil {
			return "", err
		}
	}

	// Set object legal hold
	if po.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn {
		err := p.PutObjectLegalHold(ctx, *po.Bucket, *po.Key, "", true)
		if err != nil {
			return "", err
		}
	}

	// Set object retention
	if po.ObjectLockMode != "" {
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(po.ObjectLockMode),
			RetainUntilDate: po.ObjectLockRetainUntilDate,
		}
		retParsed, err := json.Marshal(retention)
		if err != nil {
			return "", fmt.Errorf("parse object lock retention: %w", err)
		}
		err = p.PutObjectRetention(ctx, *po.Bucket, *po.Key, "", true, retParsed)
		if err != nil {
			return "", err
		}
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum[:])
	err = p.meta.StoreAttribute(*po.Bucket, *po.Key, etagkey, []byte(etag))
	if err != nil {
		return "", fmt.Errorf("set etag attr: %w", err)
	}

	ctype := getString(po.ContentType)
	if ctype != "" {
		err := p.meta.StoreAttribute(*po.Bucket, *po.Key, contentTypeHdr,
			[]byte(*po.ContentType))
		if err != nil {
			return "", fmt.Errorf("set content-type attr: %w", err)
		}
	}

	cenc := getString(po.ContentEncoding)
	if cenc != "" {
		err := p.meta.StoreAttribute(*po.Bucket, *po.Key, contentEncHdr,
			[]byte(*po.ContentEncoding))
		if err != nil {
			return "", fmt.Errorf("set content-encoding attr: %w", err)
		}
	}

	return etag, nil
}

func (p *Posix) DeleteObject(_ context.Context, input *s3.DeleteObjectInput) error {
	if input.Bucket == nil {
		return s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	bucket := *input.Bucket
	object := *input.Key

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	objpath := filepath.Join(bucket, object)

	fi, err := os.Stat(objpath)
	if err != nil {
		// AWS returns success if the object does not exist or
		// is invalid somehow.
		// TODO: log if !errors.Is(err, fs.ErrNotExist) somewhere?

		return nil
	}
	if strings.HasSuffix(object, "/") && !fi.IsDir() {
		// requested object is expecting a directory with a trailing
		// slash, but the object is not a directory. treat this as
		// a non-existent object.
		// AWS returns success if the object does not exist
		return nil
	}

	err = os.Remove(objpath)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("delete object: %w", err)
	}

	err = p.meta.DeleteAttributes(bucket, object)
	if err != nil {
		return fmt.Errorf("delete object attributes: %w", err)
	}

	return p.removeParents(bucket, object)
}

func (p *Posix) removeParents(bucket, object string) error {
	// this will remove all parent directories that were not
	// specifically uploaded with a put object. we detect
	// this with a special attribute to indicate these. stop
	// at either the bucket or the first parent we encounter
	// with the attribute, whichever comes first.
	objPath := object
	for {
		parent := filepath.Dir(objPath)

		if parent == "." {
			// stop removing parents if we hit the bucket directory.
			break
		}

		_, err := p.meta.RetrieveAttribute(bucket, parent, etagkey)
		if err == nil {
			// a directory with a valid etag means this was specifically
			// uploaded with a put object, so stop here and leave this
			// directory in place.
			break
		}

		err = os.Remove(filepath.Join(bucket, parent))
		if err != nil {
			break
		}

		objPath = parent
	}
	return nil
}

func (p *Posix) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	// delete object already checks bucket
	delResult, errs := []types.DeletedObject{}, []types.Error{}
	for _, obj := range input.Delete.Objects {
		//TODO: Make the delete operation concurrent
		err := p.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: input.Bucket,
			Key:    obj.Key,
		})
		if err == nil {
			delResult = append(delResult, types.DeletedObject{Key: obj.Key})
		} else {
			serr, ok := err.(s3err.APIError)
			if ok {
				errs = append(errs, types.Error{
					Key:     obj.Key,
					Code:    &serr.Code,
					Message: &serr.Description,
				})
			} else {
				errs = append(errs, types.Error{
					Key:     obj.Key,
					Code:    getStringPtr("InternalError"),
					Message: getStringPtr(err.Error()),
				})
			}
		}
	}

	return s3response.DeleteResult{
		Deleted: delResult,
		Error:   errs,
	}, nil
}

func (p *Posix) GetObject(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if input.Range == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRange)
	}

	bucket := *input.Bucket
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	object := *input.Key
	objPath := filepath.Join(bucket, object)

	fi, err := os.Stat(objPath)
	if errors.Is(err, fs.ErrNotExist) {
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

	acceptRange := *input.Range
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
		length = objSize - startOffset
	}

	if startOffset+length > objSize {
		length = objSize - startOffset
	}

	var contentRange string
	if acceptRange != "" {
		contentRange = fmt.Sprintf("bytes %v-%v/%v",
			startOffset, startOffset+length-1, objSize)
	}

	if fi.IsDir() {
		userMetaData := make(map[string]string)

		_, contentEncoding := p.loadUserMetaData(bucket, object, userMetaData)
		contentType := backend.DirContentType

		b, err := p.meta.RetrieveAttribute(bucket, object, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}

		var tagCount *int32
		tags, err := p.getAttrTags(bucket, object)
		if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)) {
			return nil, err
		}
		if tags != nil {
			tgCount := int32(len(tags))
			tagCount = &tgCount
		}

		return &s3.GetObjectOutput{
			AcceptRanges:    &acceptRange,
			ContentLength:   &length,
			ContentEncoding: &contentEncoding,
			ContentType:     &contentType,
			ETag:            &etag,
			LastModified:    backend.GetTimePtr(fi.ModTime()),
			Metadata:        userMetaData,
			TagCount:        tagCount,
			ContentRange:    &contentRange,
			StorageClass:    types.StorageClassStandard,
		}, nil
	}

	userMetaData := make(map[string]string)

	contentType, contentEncoding := p.loadUserMetaData(bucket, object, userMetaData)

	b, err := p.meta.RetrieveAttribute(bucket, object, etagkey)
	etag := string(b)
	if err != nil {
		etag = ""
	}

	var tagCount *int32
	tags, err := p.getAttrTags(bucket, object)
	if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)) {
		return nil, err
	}
	if tags != nil {
		tgCount := int32(len(tags))
		tagCount = &tgCount
	}

	f, err := os.Open(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("open object: %w", err)
	}

	rdr := io.NewSectionReader(f, startOffset, length)

	return &s3.GetObjectOutput{
		AcceptRanges:    &acceptRange,
		ContentLength:   &length,
		ContentEncoding: &contentEncoding,
		ContentType:     &contentType,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
		TagCount:        tagCount,
		ContentRange:    &contentRange,
		StorageClass:    types.StorageClassStandard,
		Body:            &backend.FileSectionReadCloser{R: rdr, F: f},
	}, nil
}

func (p *Posix) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	bucket := *input.Bucket
	object := *input.Key

	if input.PartNumber != nil {
		uploadId, sum, err := p.retrieveUploadId(bucket, object)
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

		b, err := p.meta.RetrieveAttribute(bucket, partPath, etagkey)
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
			StorageClass:  types.StorageClassStandard,
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
	if errors.Is(err, fs.ErrNotExist) {
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
	contentType, contentEncoding := p.loadUserMetaData(bucket, object, userMetaData)

	if fi.IsDir() {
		contentType = backend.DirContentType
	}

	b, err := p.meta.RetrieveAttribute(bucket, object, etagkey)
	etag := string(b)
	if err != nil {
		etag = ""
	}

	size := fi.Size()

	var objectLockLegalHoldStatus types.ObjectLockLegalHoldStatus
	status, err := p.GetObjectLegalHold(ctx, bucket, object, "")
	if err == nil {
		if *status {
			objectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
		} else {
			objectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOff
		}
	}

	var objectLockMode types.ObjectLockMode
	var objectLockRetainUntilDate *time.Time
	retention, err := p.GetObjectRetention(ctx, bucket, object, "")
	if err == nil {
		var config types.ObjectLockRetention
		if err := json.Unmarshal(retention, &config); err == nil {
			objectLockMode = types.ObjectLockMode(config.Mode)
			objectLockRetainUntilDate = config.RetainUntilDate
		}
	}

	//TODO: the method must handle multipart upload case

	return &s3.HeadObjectOutput{
		ContentLength:             &size,
		ContentType:               &contentType,
		ContentEncoding:           &contentEncoding,
		ETag:                      &etag,
		LastModified:              backend.GetTimePtr(fi.ModTime()),
		Metadata:                  userMetaData,
		ObjectLockLegalHoldStatus: objectLockLegalHoldStatus,
		ObjectLockMode:            objectLockMode,
		ObjectLockRetainUntilDate: objectLockRetainUntilDate,
		StorageClass:              types.StorageClassStandard,
	}, nil
}

func (p *Posix) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResult, error) {
	data, err := p.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: input.Bucket,
		Key:    input.Key,
	})
	if err != nil {
		return s3response.GetObjectAttributesResult{}, nil
	}

	return s3response.GetObjectAttributesResult{
		ETag:         data.ETag,
		LastModified: data.LastModified,
		ObjectSize:   data.ContentLength,
		StorageClass: data.StorageClass,
	}, nil
}

func (p *Posix) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidCopyDest)
	}
	if input.CopySource == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidCopySource)
	}
	if input.ExpectedBucketOwner == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	srcBucket, srcObject, ok := strings.Cut(*input.CopySource, "/")
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrInvalidCopySource)
	}
	dstBucket := *input.Bucket
	dstObject := *input.Key

	_, err := os.Stat(srcBucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	_, err = os.Stat(dstBucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	objPath := filepath.Join(srcBucket, srcObject)
	f, err := os.Open(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return nil, s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if err != nil {
		return nil, fmt.Errorf("open object: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}
	if strings.HasSuffix(srcObject, "/") && !fi.IsDir() {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	mdmap := make(map[string]string)
	p.loadUserMetaData(srcBucket, srcObject, mdmap)

	var etag string

	dstObjdPath := filepath.Join(dstBucket, dstObject)
	if dstObjdPath == objPath {
		if input.MetadataDirective == types.MetadataDirectiveCopy {
			return &s3.CopyObjectOutput{}, s3err.GetAPIError(s3err.ErrInvalidCopyDest)
		}

		for k := range mdmap {
			err := p.meta.DeleteAttribute(dstBucket, dstObject,
				fmt.Sprintf("%v.%v", metaHdr, k))
			if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
				return nil, fmt.Errorf("delete user metadata: %w", err)
			}
		}
		for k, v := range input.Metadata {
			err := p.meta.StoreAttribute(dstBucket, dstObject,
				fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
			if err != nil {
				return nil, fmt.Errorf("set user attr %q: %w", k, err)
			}
		}

		b, _ := p.meta.RetrieveAttribute(dstBucket, dstObject, etagkey)
		etag = string(b)
	} else {
		contentLength := fi.Size()

		etag, err = p.PutObject(ctx,
			&s3.PutObjectInput{
				Bucket:        &dstBucket,
				Key:           &dstObject,
				Body:          f,
				ContentLength: &contentLength,
				Metadata:      input.Metadata,
			})
		if err != nil {
			return nil, err
		}
	}

	fi, err = os.Stat(dstObjdPath)
	if err != nil {
		return nil, fmt.Errorf("stat dst object: %w", err)
	}

	return &s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{
			ETag:         &etag,
			LastModified: backend.GetTimePtr(fi.ModTime()),
		},
	}, nil
}

func (p *Posix) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
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
		p.fileToObj(bucket), []string{metaTmpDir})
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

func (p *Posix) fileToObj(bucket string) backend.GetObjFunc {
	return func(path string, d fs.DirEntry) (s3response.Object, error) {
		if d.IsDir() {
			// directory object only happens if directory empty
			// check to see if this is a directory object by checking etag
			etagBytes, err := p.meta.RetrieveAttribute(bucket, path, etagkey)
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

		// file object, get object info and fill out object data
		etagBytes, err := p.meta.RetrieveAttribute(bucket, path, etagkey)
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return s3response.Object{}, fmt.Errorf("get etag: %w", err)
		}
		// note: meta.ErrNoSuchKey will return etagBytes = []byte{}
		// so this will just set etag to "" if its not already set

		etag := string(etagBytes)

		fi, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		if err != nil {
			return s3response.Object{}, fmt.Errorf("get fileinfo: %w", err)
		}

		size := fi.Size()
		mtime := fi.ModTime()

		return s3response.Object{
			ETag:         &etag,
			Key:          &path,
			LastModified: &mtime,
			Size:         &size,
			StorageClass: types.ObjectStorageClassStandard,
		}, nil
	}
}

func (p *Posix) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
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
		if input.StartAfter != nil {
			if *input.StartAfter > *input.ContinuationToken {
				marker = *input.StartAfter
			} else {
				marker = *input.ContinuationToken
			}
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
	results, err := backend.Walk(ctx, fileSystem, prefix, delim, marker, maxkeys,
		p.fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return s3response.ListObjectsV2Result{}, fmt.Errorf("walk %v: %w", bucket, err)
	}

	count := int32(len(results.Objects))

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
		KeyCount:              &count,
	}, nil
}

func (p *Posix) PutBucketAcl(_ context.Context, bucket string, data []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if err := p.meta.StoreAttribute(bucket, "", aclkey, data); err != nil {
		return fmt.Errorf("set acl: %w", err)
	}

	return nil
}

func (p *Posix) GetBucketAcl(_ context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	_, err := os.Stat(*input.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	b, err := p.meta.RetrieveAttribute(*input.Bucket, "", aclkey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return []byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get acl: %w", err)
	}
	return b, nil
}

func (p *Posix) PutBucketTagging(_ context.Context, bucket string, tags map[string]string) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if tags == nil {
		err = p.meta.DeleteAttribute(bucket, "", tagHdr)
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return fmt.Errorf("remove tags: %w", err)
		}

		return nil
	}

	b, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}

	err = p.meta.StoreAttribute(bucket, "", tagHdr, b)
	if err != nil {
		return fmt.Errorf("set tags: %w", err)
	}

	return nil
}

func (p *Posix) GetBucketTagging(_ context.Context, bucket string) (map[string]string, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	tags, err := p.getAttrTags(bucket, "")
	if err != nil {
		return nil, err
	}

	return tags, nil
}

func (p *Posix) DeleteBucketTagging(ctx context.Context, bucket string) error {
	return p.PutBucketTagging(ctx, bucket, nil)
}

func (p *Posix) GetObjectTagging(_ context.Context, bucket, object string) (map[string]string, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	return p.getAttrTags(bucket, object)
}

func (p *Posix) getAttrTags(bucket, object string) (map[string]string, error) {
	tags := make(map[string]string)
	b, err := p.meta.RetrieveAttribute(bucket, object, tagHdr)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)
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

func (p *Posix) PutObjectTagging(_ context.Context, bucket, object string, tags map[string]string) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if tags == nil {
		err = p.meta.DeleteAttribute(bucket, object, tagHdr)
		if errors.Is(err, fs.ErrNotExist) {
			return s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if errors.Is(err, meta.ErrNoSuchKey) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("remove tags: %w", err)
		}
		return nil
	}

	b, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}

	err = p.meta.StoreAttribute(bucket, object, tagHdr, b)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("set tags: %w", err)
	}

	return nil
}

func (p *Posix) DeleteObjectTagging(ctx context.Context, bucket, object string) error {
	return p.PutObjectTagging(ctx, bucket, object, nil)
}

func (p *Posix) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if policy == nil {
		err := p.meta.DeleteAttribute(bucket, "", policykey)
		if err != nil {
			if errors.Is(err, meta.ErrNoSuchKey) {
				return nil
			}

			return fmt.Errorf("remove policy: %w", err)
		}

		return nil
	}

	err = p.meta.StoreAttribute(bucket, "", policykey, policy)
	if err != nil {
		return fmt.Errorf("set policy: %w", err)
	}

	return nil
}

func (p *Posix) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	policy, err := p.meta.RetrieveAttribute(bucket, "", policykey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("get bucket policy: %w", err)
	}

	return policy, nil
}

func (p *Posix) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return p.PutBucketPolicy(ctx, bucket, nil)
}

func (p *Posix) PutObjectLockConfiguration(_ context.Context, bucket string, config []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	cfg, err := p.meta.RetrieveAttribute(bucket, "", bucketLockKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)
	}
	if err != nil {
		return fmt.Errorf("get object lock config: %w", err)
	}

	var bucketLockCfg auth.BucketLockConfig
	if err := json.Unmarshal(cfg, &bucketLockCfg); err != nil {
		return fmt.Errorf("unmarshal object lock config: %w", err)
	}

	if !bucketLockCfg.Enabled {
		return s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)
	}

	if err := p.meta.StoreAttribute(bucket, "", bucketLockKey, config); err != nil {
		return fmt.Errorf("set object lock config: %w", err)
	}

	return nil
}

func (p *Posix) GetObjectLockConfiguration(_ context.Context, bucket string) ([]byte, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	cfg, err := p.meta.RetrieveAttribute(bucket, "", bucketLockKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get object lock config: %w", err)
	}

	return cfg, nil
}

func (p *Posix) PutObjectLegalHold(_ context.Context, bucket, object, versionId string, status bool) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	cfg, err := p.meta.RetrieveAttribute(bucket, "", bucketLockKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}
	if err != nil {
		return fmt.Errorf("get object lock config: %w", err)
	}

	var bucketLockConfig auth.BucketLockConfig
	if err := json.Unmarshal(cfg, &bucketLockConfig); err != nil {
		return fmt.Errorf("parse bucket lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}

	var statusData []byte
	if status {
		statusData = []byte{1}
	} else {
		statusData = []byte{0}
	}

	err = p.meta.StoreAttribute(bucket, object, objectLegalHoldKey, statusData)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("set object lock config: %w", err)
	}

	return nil
}

func (p *Posix) GetObjectLegalHold(_ context.Context, bucket, object, versionId string) (*bool, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	data, err := p.meta.RetrieveAttribute(bucket, object, objectLegalHoldKey)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)
	}
	if err != nil {
		return nil, fmt.Errorf("get object lock config: %w", err)
	}

	result := data[0] == 1

	return &result, nil
}

func (p *Posix) PutObjectRetention(_ context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	cfg, err := p.meta.RetrieveAttribute(bucket, "", bucketLockKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}
	if err != nil {
		return fmt.Errorf("get object lock config: %w", err)
	}

	var bucketLockConfig auth.BucketLockConfig
	if err := json.Unmarshal(cfg, &bucketLockConfig); err != nil {
		return fmt.Errorf("parse bucket lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}

	objectLockCfg, err := p.meta.RetrieveAttribute(bucket, object, objectRetentionKey)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, meta.ErrNoSuchKey) {
		if err := p.meta.StoreAttribute(bucket, object, objectRetentionKey, retention); err != nil {
			return fmt.Errorf("set object lock config: %w", err)
		}

		return nil
	}
	if err != nil {
		return fmt.Errorf("get object lock config: %w", err)
	}

	var lockCfg types.ObjectLockRetention
	if err := json.Unmarshal(objectLockCfg, &lockCfg); err != nil {
		return fmt.Errorf("unmarshal object lock config: %w", err)
	}

	switch lockCfg.Mode {
	// Compliance mode can't be overridden
	case types.ObjectLockRetentionModeCompliance:
		return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
	// To override governance mode user should have "s3:BypassGovernanceRetention" permission
	case types.ObjectLockRetentionModeGovernance:
		if !bypass {
			return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
	}

	if err := p.meta.StoreAttribute(bucket, object, objectRetentionKey, retention); err != nil {
		return fmt.Errorf("set object lock config: %w", err)
	}

	return nil
}

func (p *Posix) GetObjectRetention(_ context.Context, bucket, object, versionId string) ([]byte, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	data, err := p.meta.RetrieveAttribute(bucket, object, objectRetentionKey)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)
	}
	if err != nil {
		return nil, fmt.Errorf("get object lock config: %w", err)
	}

	return data, nil
}

func (p *Posix) ChangeBucketOwner(ctx context.Context, bucket string, acl []byte) error {
	return p.PutBucketAcl(ctx, bucket, acl)
}

func (p *Posix) ListBucketsAndOwners(ctx context.Context) (buckets []s3response.Bucket, err error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return buckets, fmt.Errorf("readdir buckets: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fi, err := entry.Info()
		if err != nil {
			continue
		}

		aclTag, err := p.meta.RetrieveAttribute(entry.Name(), "", aclkey)
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return buckets, fmt.Errorf("get acl tag: %w", err)
		}

		var acl auth.ACL
		if len(aclTag) > 0 {
			err = json.Unmarshal(aclTag, &acl)
			if err != nil {
				return buckets, fmt.Errorf("parse acl tag: %w", err)
			}
		}

		buckets = append(buckets, s3response.Bucket{
			Name:  fi.Name(),
			Owner: acl.Owner,
		})
	}

	sort.SliceStable(buckets, func(i, j int) bool {
		return buckets[i].Name < buckets[j].Name
	})

	return buckets, nil
}

func getString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func getStringPtr(str string) *string {
	return &str
}
