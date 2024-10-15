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
	"github.com/oklog/ulid/v2"
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

	// bucket versioning directory path
	versioningDir string
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
	versioningKey       = "versioning"
	deleteMarkerKey     = "delete-marker"
	versionIdKey        = "version-id"

	nullVersionId = "null"

	doFalloc   = true
	skipFalloc = false
)

type PosixOpts struct {
	ChownUID      bool
	ChownGID      bool
	BucketLinks   bool
	VersioningDir string
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

	var verioningdirAbs string

	// Ensure the versioning directory isn't within the root directory
	if opts.VersioningDir != "" {
		rootdirAbs, err := filepath.Abs(rootdir)
		if err != nil {
			return nil, fmt.Errorf("get absolute path of %v: %w", rootdir, err)
		}

		verioningdirAbs, err = filepath.Abs(opts.VersioningDir)
		if err != nil {
			return nil, fmt.Errorf("get absolute path of %v: %w", opts.VersioningDir, err)
		}

		// Ensure the paths end with a separator
		if !strings.HasSuffix(rootdirAbs, string(filepath.Separator)) {
			rootdirAbs += string(filepath.Separator)
		}

		if !strings.HasSuffix(verioningdirAbs, string(filepath.Separator)) {
			verioningdirAbs += string(filepath.Separator)
		}

		// Ensure the posix root directory doesn't contain the versioning directory
		if strings.HasPrefix(verioningdirAbs, rootdirAbs) {
			return nil, fmt.Errorf("the root directory %v contains the versioning directory %v", rootdir, opts.VersioningDir)
		}

		vDir, err := os.Stat(verioningdirAbs)
		if err != nil {
			return nil, fmt.Errorf("stat versioning dir: %w", err)
		}

		// Check the versioning path to be a directory
		if !vDir.IsDir() {
			return nil, fmt.Errorf("versioning path should be a directory")
		}
	}

	fmt.Printf("Bucket versioning enabled with directory: %v\n", verioningdirAbs)

	return &Posix{
		meta:          meta,
		rootfd:        f,
		rootdir:       rootdir,
		euid:          os.Geteuid(),
		egid:          os.Getegid(),
		chownuid:      opts.ChownUID,
		chowngid:      opts.ChownGID,
		bucketlinks:   opts.BucketLinks,
		versioningDir: verioningdirAbs,
	}, nil
}

func (p *Posix) Shutdown() {
	p.rootfd.Close()
}

func (p *Posix) String() string {
	return "Posix Gateway"
}

// returns the versioning state
func (p *Posix) versioningEnabled() bool {
	return p.versioningDir != ""
}

func (p *Posix) doesBucketAndObjectExist(bucket, object string) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	_, err = os.Stat(filepath.Join(bucket, object))
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("stat object: %w", err)
	}

	return nil
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

		aclTag, err := p.meta.RetrieveAttribute(nil, entry.Name(), "", aclkey)
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
		aclJSON, err := p.meta.RetrieveAttribute(nil, bucket, "", aclkey)
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

	err = p.meta.StoreAttribute(nil, bucket, "", aclkey, acl)
	if err != nil {
		return fmt.Errorf("set acl: %w", err)
	}
	err = p.meta.StoreAttribute(nil, bucket, "", ownershipkey, []byte(input.ObjectOwnership))
	if err != nil {
		return fmt.Errorf("set ownership: %w", err)
	}

	if input.ObjectLockEnabledForBucket != nil && *input.ObjectLockEnabledForBucket {
		// First enable bucket versioning
		// Bucket versioning is enabled automatically with object lock
		if p.versioningEnabled() {
			err = p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				return err
			}
		}

		now := time.Now()
		defaultLock := auth.BucketLockConfig{
			Enabled:   true,
			CreatedAt: &now,
		}

		defaultLockParsed, err := json.Marshal(defaultLock)
		if err != nil {
			return fmt.Errorf("parse default bucket lock state: %w", err)
		}

		err = p.meta.StoreAttribute(nil, bucket, "", bucketLockKey, defaultLockParsed)
		if err != nil {
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

	err = p.meta.StoreAttribute(nil, bucket, "", ownershipkey, []byte(ownership))
	if err != nil {
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

	ownership, err := p.meta.RetrieveAttribute(nil, bucket, "", ownershipkey)
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

	err = p.meta.DeleteAttribute(bucket, "", ownershipkey)
	if err != nil {
		if errors.Is(err, meta.ErrNoSuchKey) {
			return nil
		}

		return fmt.Errorf("delete ownership: %w", err)
	}

	return nil
}

func (p *Posix) PutBucketVersioning(ctx context.Context, bucket string, status types.BucketVersioningStatus) error {
	if !p.versioningEnabled() {
		return s3err.GetAPIError(s3err.ErrVersioningNotConfigured)
	}
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	// Store 1 bit for bucket versioning state
	var versioning []byte
	switch status {
	case types.BucketVersioningStatusEnabled:
		// '1' maps to 'Enabled'
		versioning = []byte{1}
	case types.BucketVersioningStatusSuspended:
		lockRaw, err := p.GetObjectLockConfiguration(ctx, bucket)
		if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)) {
			return err
		}
		if err == nil {
			lockStatus, err := auth.ParseBucketLockConfigurationOutput(lockRaw)
			if err != nil {
				return err
			}
			if lockStatus.ObjectLockEnabled == types.ObjectLockEnabledEnabled {
				return s3err.GetAPIError(s3err.ErrSuspendedVersioningNotAllowed)
			}
		}

		// '0' maps to 'Suspended'
		versioning = []byte{0}
	}

	err = p.meta.StoreAttribute(nil, bucket, "", versioningKey, versioning)
	if err != nil {
		return fmt.Errorf("set versioning: %w", err)
	}

	return nil
}

func (p *Posix) GetBucketVersioning(_ context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
	if !p.versioningEnabled() {
		return s3response.GetBucketVersioningOutput{}, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)
	}

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.GetBucketVersioningOutput{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.GetBucketVersioningOutput{}, fmt.Errorf("stat bucket: %w", err)
	}

	vData, err := p.meta.RetrieveAttribute(nil, bucket, "", versioningKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return s3response.GetBucketVersioningOutput{}, nil
	} else if err != nil {
		return s3response.GetBucketVersioningOutput{}, fmt.Errorf("get bucket versioning config: %w", err)
	}

	enabled, suspended := types.BucketVersioningStatusEnabled, types.BucketVersioningStatusSuspended
	switch vData[0] {
	case 1:
		return s3response.GetBucketVersioningOutput{
			Status: &enabled,
		}, nil
	case 0:
		return s3response.GetBucketVersioningOutput{
			Status: &suspended,
		}, nil
	}

	return s3response.GetBucketVersioningOutput{}, nil
}

// Returns the specified bucket versioning status
func (p *Posix) getBucketVersioningStatus(ctx context.Context, bucket string) (types.BucketVersioningStatus, error) {
	res, err := p.GetBucketVersioning(ctx, bucket)
	if errors.Is(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)) {
		return "", nil
	}
	if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)) {
		return "", err
	}

	if res.Status == nil {
		return "", nil
	}

	return *res.Status, nil
}

// Checks if the given bucket versioning status is 'Enabled'
func (p *Posix) isBucketVersioningEnabled(s types.BucketVersioningStatus) bool {
	return s == types.BucketVersioningStatusEnabled
}

// Checks if the given bucket versioning status is 'Suspended'
func (p *Posix) isBucketVersioningSuspended(s types.BucketVersioningStatus) bool {
	return s == types.BucketVersioningStatusSuspended
}

// Generates the object version path in the versioning directory
func (p *Posix) genObjVersionPath(bucket, key string) string {
	return filepath.Join(p.versioningDir, bucket, genObjVersionKey(key))
}

// Generates the versioning path for the given object key
func genObjVersionKey(key string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))

	return filepath.Join(sum[:2], sum[2:4], sum[4:6], sum)
}

// Removes the null versionId object from versioning directory
func (p *Posix) deleteNullVersionIdObject(bucket, key string) error {
	versionPath := filepath.Join(p.genObjVersionPath(bucket, key), nullVersionId)

	err := os.Remove(versionPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	return err
}

// Creates a new copy(version) of an object in the versioning directory
func (p *Posix) createObjVersion(bucket, key string, size int64, acc auth.Account) (versionPath string, err error) {
	sf, err := os.Open(filepath.Join(bucket, key))
	if err != nil {
		return "", err
	}
	defer sf.Close()

	var versionId string
	data, err := p.meta.RetrieveAttribute(sf, bucket, key, versionIdKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return versionPath, fmt.Errorf("get object versionId: %w", err)
	}
	if err == nil {
		versionId = string(data)
	} else {
		versionId = nullVersionId
	}

	attrs, err := p.meta.ListAttributes(bucket, key)
	if err != nil {
		return versionPath, fmt.Errorf("load object attributes: %w", err)
	}

	versionBucketPath := filepath.Join(p.versioningDir, bucket)
	versioningKey := filepath.Join(genObjVersionKey(key), versionId)
	versionTmpPath := filepath.Join(versionBucketPath, metaTmpDir)
	f, err := p.openTmpFile(versionTmpPath, versionBucketPath, versioningKey, size, acc, doFalloc)
	if err != nil {
		return versionPath, err
	}
	defer f.cleanup()

	_, err = io.Copy(f.File(), sf)
	if err != nil {
		return versionPath, err
	}

	versionPath = filepath.Join(versionBucketPath, versioningKey)

	err = os.MkdirAll(filepath.Join(versionBucketPath, genObjVersionKey(key)), defaultDirPerm)
	if err != nil {
		return versionPath, err
	}

	// Copy the object attributes(metadata)
	for _, attr := range attrs {
		data, err := p.meta.RetrieveAttribute(sf, bucket, key, attr)
		if err != nil {
			return versionPath, fmt.Errorf("list %v attribute: %w", attr, err)
		}

		err = p.meta.StoreAttribute(f.File(), versionPath, "", attr, data)
		if err != nil {
			return versionPath, fmt.Errorf("store %v attribute: %w", attr, err)
		}
	}

	if err := f.link(); err != nil {
		return versionPath, err
	}

	return versionPath, nil
}

func (p *Posix) ListObjectVersions(ctx context.Context, input *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
	bucket := *input.Bucket
	var prefix, delim, keyMarker, versionIdMarker string
	var max int

	if input.Prefix != nil {
		prefix = *input.Prefix
	}
	if input.Delimiter != nil {
		delim = *input.Delimiter
	}
	if input.KeyMarker != nil {
		keyMarker = *input.KeyMarker
	}
	if input.VersionIdMarker != nil {
		versionIdMarker = *input.VersionIdMarker
	}
	if input.MaxKeys != nil {
		max = int(*input.MaxKeys)
	}

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.ListVersionsResult{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.ListVersionsResult{}, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.WalkVersions(ctx, fileSystem, prefix, delim, keyMarker, versionIdMarker, max,
		p.fileToObjVersions(bucket), []string{metaTmpDir})
	if err != nil {
		return s3response.ListVersionsResult{}, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return s3response.ListVersionsResult{
		CommonPrefixes:      results.CommonPrefixes,
		DeleteMarkers:       results.DelMarkers,
		Delimiter:           &delim,
		IsTruncated:         &results.Truncated,
		KeyMarker:           &keyMarker,
		MaxKeys:             input.MaxKeys,
		Name:                input.Bucket,
		NextKeyMarker:       &results.NextMarker,
		NextVersionIdMarker: &results.NextVersionIdMarker,
		Prefix:              &prefix,
		VersionIdMarker:     &versionIdMarker,
		Versions:            results.ObjectVersions,
	}, nil
}

func getBoolPtr(b bool) *bool {
	return &b
}

// Check if the given object is a delete marker
func (p *Posix) isObjDeleteMarker(bucket, object string) (bool, error) {
	_, err := p.meta.RetrieveAttribute(nil, bucket, object, deleteMarkerKey)
	if errors.Is(err, fs.ErrNotExist) {
		return false, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, meta.ErrNoSuchKey) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get object delete-marker: %w", err)
	}

	return true, nil
}

// Converts the file to object version. Finds all the object versions,
// delete markers from the versioning directory and returns
func (p *Posix) fileToObjVersions(bucket string) backend.GetVersionsFunc {
	return func(path, versionIdMarker string, pastVersionIdMarker *bool, availableObjCount int, d fs.DirEntry) (*backend.ObjVersionFuncResult, error) {
		var objects []types.ObjectVersion
		var delMarkers []types.DeleteMarkerEntry
		// if the number of available objects is 0, return truncated response
		if availableObjCount <= 0 {
			return &backend.ObjVersionFuncResult{
				ObjectVersions: objects,
				DelMarkers:     delMarkers,
				Truncated:      true,
			}, nil
		}
		if d.IsDir() {
			// directory object only happens if directory empty
			// check to see if this is a directory object by checking etag
			etagBytes, err := p.meta.RetrieveAttribute(nil, bucket, path, etagkey)
			if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
				return nil, backend.ErrSkipObj
			}
			if err != nil {
				return nil, fmt.Errorf("get etag: %w", err)
			}
			etag := string(etagBytes)

			fi, err := d.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return nil, backend.ErrSkipObj
			}
			if err != nil {
				return nil, fmt.Errorf("get fileinfo: %w", err)
			}

			key := path + "/"
			// Directory objects don't contain data
			size := int64(0)
			versionId := "null"

			objects = append(objects, types.ObjectVersion{
				ETag:         &etag,
				Key:          &key,
				LastModified: backend.GetTimePtr(fi.ModTime()),
				IsLatest:     getBoolPtr(true),
				Size:         &size,
				VersionId:    &versionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
			})

			return &backend.ObjVersionFuncResult{
				ObjectVersions: objects,
				DelMarkers:     delMarkers,
				Truncated:      availableObjCount == 1,
			}, nil
		}

		// file object, get object info and fill out object data
		etagBytes, err := p.meta.RetrieveAttribute(nil, bucket, path, etagkey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, backend.ErrSkipObj
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return nil, fmt.Errorf("get etag: %w", err)
		}
		// note: meta.ErrNoSuchKey will return etagBytes = []byte{}
		// so this will just set etag to "" if its not already set
		etag := string(etagBytes)

		// If the object doesn't have versionId, it's 'null'
		versionId := "null"
		versionIdBytes, err := p.meta.RetrieveAttribute(nil, bucket, path, versionIdKey)
		if err == nil {
			versionId = string(versionIdBytes)
		}
		if versionId == versionIdMarker {
			*pastVersionIdMarker = true
		}
		if *pastVersionIdMarker {
			fi, err := d.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return nil, backend.ErrSkipObj
			}
			if err != nil {
				return nil, fmt.Errorf("get fileinfo: %w", err)
			}

			size := fi.Size()

			isDel, err := p.isObjDeleteMarker(bucket, path)
			if err != nil {
				return nil, err
			}

			if isDel {
				delMarkers = append(delMarkers, types.DeleteMarkerEntry{
					IsLatest:     getBoolPtr(true),
					VersionId:    &versionId,
					LastModified: backend.GetTimePtr(fi.ModTime()),
					Key:          &path,
				})
			} else {
				objects = append(objects, types.ObjectVersion{
					ETag:         &etag,
					Key:          &path,
					LastModified: backend.GetTimePtr(fi.ModTime()),
					Size:         &size,
					VersionId:    &versionId,
					IsLatest:     getBoolPtr(true),
					StorageClass: types.ObjectVersionStorageClassStandard,
				})
			}

			availableObjCount--
			if availableObjCount == 0 {
				return &backend.ObjVersionFuncResult{
					ObjectVersions:      objects,
					DelMarkers:          delMarkers,
					Truncated:           true,
					NextVersionIdMarker: versionId,
				}, nil
			}
		}

		if !p.versioningEnabled() {
			return &backend.ObjVersionFuncResult{
				ObjectVersions: objects,
				DelMarkers:     delMarkers,
			}, nil
		}

		// List all the versions of the object in the versioning directory
		versionPath := p.genObjVersionPath(bucket, path)
		dirEnts, err := os.ReadDir(versionPath)
		if errors.Is(err, fs.ErrNotExist) {
			return &backend.ObjVersionFuncResult{
				ObjectVersions: objects,
				DelMarkers:     delMarkers,
			}, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read version dir: %w", err)
		}

		if len(dirEnts) == 0 {
			return &backend.ObjVersionFuncResult{
				ObjectVersions: objects,
				DelMarkers:     delMarkers,
			}, nil
		}

		// First find the null versionId object(if exists)
		// before starting the object versions listing
		var nullVersionIdObj *types.ObjectVersion
		var nullObjDelMarker *types.DeleteMarkerEntry
		nf, err := os.Stat(filepath.Join(versionPath, nullVersionId))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err == nil {
			isDel, err := p.isObjDeleteMarker(versionPath, nullVersionId)
			if err != nil {
				return nil, err
			}

			// Check to see if the null versionId object is delete marker or not
			if isDel {
				nullObjDelMarker = &types.DeleteMarkerEntry{
					VersionId:    backend.GetStringPtr("null"),
					LastModified: backend.GetTimePtr(nf.ModTime()),
					Key:          &path,
					IsLatest:     getBoolPtr(false),
				}
			} else {
				etagBytes, err := p.meta.RetrieveAttribute(nil, versionPath, nullVersionId, etagkey)
				if errors.Is(err, fs.ErrNotExist) {
					return nil, backend.ErrSkipObj
				}
				if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
					return nil, fmt.Errorf("get etag: %w", err)
				}
				// note: meta.ErrNoSuchKey will return etagBytes = []byte{}
				// so this will just set etag to "" if its not already set
				etag := string(etagBytes)
				size := nf.Size()
				nullVersionIdObj = &types.ObjectVersion{
					ETag:         &etag,
					Key:          &path,
					LastModified: backend.GetTimePtr(nf.ModTime()),
					Size:         &size,
					VersionId:    backend.GetStringPtr("null"),
					IsLatest:     getBoolPtr(false),
					StorageClass: types.ObjectVersionStorageClassStandard,
				}
			}
		}

		isNullVersionIdObjFound := nullVersionIdObj != nil || nullObjDelMarker != nil

		if len(dirEnts) == 1 && (isNullVersionIdObjFound) {
			if nullObjDelMarker != nil {
				delMarkers = append(delMarkers, *nullObjDelMarker)
			}
			if nullVersionIdObj != nil {
				objects = append(objects, *nullVersionIdObj)
			}

			if availableObjCount == 1 {
				return &backend.ObjVersionFuncResult{
					ObjectVersions:      objects,
					DelMarkers:          delMarkers,
					Truncated:           true,
					NextVersionIdMarker: nullVersionId,
				}, nil
			}
		}

		isNullVersionIdObjAdded := false

		for i := len(dirEnts) - 1; i >= 0; i-- {
			dEntry := dirEnts[i]
			// Skip the null versionId object to not
			// break the object versions list
			if dEntry.Name() == nullVersionId {
				continue
			}

			f, err := dEntry.Info()
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("get fileinfo: %w", err)
			}

			// If the null versionId object is found, first push it
			// by checking its creation date, then continue the adding
			if isNullVersionIdObjFound && !isNullVersionIdObjAdded {
				if nf.ModTime().After(f.ModTime()) {
					if nullVersionIdObj != nil {
						objects = append(objects, *nullVersionIdObj)
					}
					if nullObjDelMarker != nil {
						delMarkers = append(delMarkers, *nullObjDelMarker)
					}

					isNullVersionIdObjAdded = true

					if availableObjCount--; availableObjCount == 0 {
						return &backend.ObjVersionFuncResult{
							ObjectVersions:      objects,
							DelMarkers:          delMarkers,
							Truncated:           true,
							NextVersionIdMarker: nullVersionId,
						}, nil
					}
				}
			}
			versionId := f.Name()
			size := f.Size()

			if !*pastVersionIdMarker {
				if versionId == versionIdMarker {
					*pastVersionIdMarker = true
				}
				continue
			}

			etagBytes, err := p.meta.RetrieveAttribute(nil, versionPath, versionId, etagkey)
			if errors.Is(err, fs.ErrNotExist) {
				return nil, backend.ErrSkipObj
			}
			if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
				return nil, fmt.Errorf("get etag: %w", err)
			}
			// note: meta.ErrNoSuchKey will return etagBytes = []byte{}
			// so this will just set etag to "" if its not already set
			etag := string(etagBytes)

			isDel, err := p.isObjDeleteMarker(versionPath, versionId)
			if err != nil {
				return nil, err
			}

			if isDel {
				delMarkers = append(delMarkers, types.DeleteMarkerEntry{
					VersionId:    &versionId,
					LastModified: backend.GetTimePtr(f.ModTime()),
					Key:          &path,
					IsLatest:     getBoolPtr(false),
				})
			} else {
				objects = append(objects, types.ObjectVersion{
					ETag:         &etag,
					Key:          &path,
					LastModified: backend.GetTimePtr(f.ModTime()),
					Size:         &size,
					VersionId:    &versionId,
					IsLatest:     getBoolPtr(false),
					StorageClass: types.ObjectVersionStorageClassStandard,
				})
			}

			// if the available object count reaches to 0, return truncated response with nextVersionIdMarker
			availableObjCount--
			if availableObjCount == 0 {
				return &backend.ObjVersionFuncResult{
					ObjectVersions:      objects,
					DelMarkers:          delMarkers,
					Truncated:           true,
					NextVersionIdMarker: versionId,
				}, nil
			}
		}

		// If null versionId object is found but not yet pushed,
		// push it after the listing, as it's the oldest object version
		if isNullVersionIdObjFound && !isNullVersionIdObjAdded {
			if nullVersionIdObj != nil {
				objects = append(objects, *nullVersionIdObj)
			}
			if nullObjDelMarker != nil {
				delMarkers = append(delMarkers, *nullObjDelMarker)
			}

			if availableObjCount--; availableObjCount == 0 {
				return &backend.ObjVersionFuncResult{
					ObjectVersions:      objects,
					DelMarkers:          delMarkers,
					Truncated:           true,
					NextVersionIdMarker: nullVersionId,
				}, nil
			}
		}

		return &backend.ObjVersionFuncResult{
			ObjectVersions: objects,
			DelMarkers:     delMarkers,
		}, nil
	}
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
	err = p.meta.StoreAttribute(nil, bucket, objdir, onameAttr, []byte(object))
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
		err := p.meta.StoreAttribute(nil, bucket, filepath.Join(objdir, uploadID),
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
		err := p.meta.StoreAttribute(nil, bucket, filepath.Join(objdir, uploadID),
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
		err := p.meta.StoreAttribute(nil, bucket, filepath.Join(objdir, uploadID), contentEncHdr,
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
		err := p.PutObjectLegalHold(ctx, bucket, filepath.Join(objdir, uploadID), "", true)
		if err != nil {
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
		err = p.PutObjectRetention(ctx, bucket, filepath.Join(objdir, uploadID), "", true, retParsed)
		if err != nil {
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

		b, err := p.meta.RetrieveAttribute(nil, bucket, partObjPath, etagkey)
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

	vStatus, err := p.getBucketVersioningStatus(ctx, bucket)
	if err != nil {
		return nil, err
	}
	vEnabled := p.isBucketVersioningEnabled(vStatus)

	d, err := os.Stat(objname)

	// if the versioninng is enabled first create the file object version
	if p.versioningEnabled() && vEnabled && err == nil && !d.IsDir() {
		_, err := p.createObjVersion(bucket, object, d.Size(), acct)
		if err != nil {
			return nil, fmt.Errorf("create object version: %w", err)
		}
	}

	// if the versioning is enabled, generate a new versionID for the object
	var versionID string
	if p.versioningEnabled() && vEnabled {
		versionID = ulid.Make().String()

		err := p.meta.StoreAttribute(f.File(), bucket, object, versionIdKey, []byte(versionID))
		if err != nil {
			return nil, fmt.Errorf("set versionId attr: %w", err)
		}
	}

	for k, v := range userMetaData {
		err = p.meta.StoreAttribute(f.File(), bucket, object, fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			return nil, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// load and set tagging
	tagging, err := p.meta.RetrieveAttribute(nil, bucket, upiddir, tagHdr)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object tagging: %w", err)
	}
	if err == nil {
		err := p.meta.StoreAttribute(f.File(), bucket, object, tagHdr, tagging)
		if err != nil {
			return nil, fmt.Errorf("set object tagging: %w", err)
		}
	}

	// set content-type
	if cType != "" {
		err := p.meta.StoreAttribute(f.File(), bucket, object, contentTypeHdr, []byte(cType))
		if err != nil {
			return nil, fmt.Errorf("set object content type: %w", err)
		}
	}

	// set content-encoding
	if cEnc != "" {
		err := p.meta.StoreAttribute(f.File(), bucket, object, contentEncHdr, []byte(cEnc))
		if err != nil {
			return nil, fmt.Errorf("set object content encoding: %w", err)
		}
	}

	// load and set legal hold
	lHold, err := p.meta.RetrieveAttribute(nil, bucket, upiddir, objectLegalHoldKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object legal hold: %w", err)
	}
	if err == nil {
		err := p.meta.StoreAttribute(f.File(), bucket, object, objectLegalHoldKey, lHold)
		if err != nil {
			return nil, fmt.Errorf("set object legal hold: %w", err)
		}
	}

	// load and set retention
	ret, err := p.meta.RetrieveAttribute(nil, bucket, upiddir, objectRetentionKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return nil, fmt.Errorf("get object retention: %w", err)
	}
	if err == nil {
		err := p.meta.StoreAttribute(f.File(), bucket, object, objectRetentionKey, ret)
		if err != nil {
			return nil, fmt.Errorf("set object retention: %w", err)
		}
	}

	// Calculate s3 compatible md5sum for complete multipart.
	s3MD5 := backend.GetMultipartMD5(parts)

	err = p.meta.StoreAttribute(f.File(), bucket, object, etagkey, []byte(s3MD5))
	if err != nil {
		return nil, fmt.Errorf("set etag attr: %w", err)
	}

	err = f.link()
	if err != nil {
		return nil, fmt.Errorf("link object in namespace: %w", err)
	}

	// cleanup tmp dirs
	os.RemoveAll(filepath.Join(bucket, objdir, uploadID))
	// use Remove for objdir in case there are still other uploads
	// for same object name outstanding, this will fail if there are
	os.Remove(filepath.Join(bucket, objdir))

	return &s3.CompleteMultipartUploadOutput{
		Bucket:    &bucket,
		ETag:      &s3MD5,
		Key:       &object,
		VersionId: &versionID,
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
		b, err := p.meta.RetrieveAttribute(nil, bucket, object, e)
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
	b, _ := p.meta.RetrieveAttribute(nil, bucket, object, contentTypeHdr)
	contentType = string(b)

	b, _ = p.meta.RetrieveAttribute(nil, bucket, object, contentEncHdr)
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

		b, err := p.meta.RetrieveAttribute(nil, bucket, filepath.Join(metaTmpMultipartDir, obj.Name()), onameAttr)
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
		b, err := p.meta.RetrieveAttribute(nil, bucket, partPath, etagkey)
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
	defer f.cleanup()

	hash := md5.New()
	tr := io.TeeReader(r, hash)
	_, err = io.Copy(f, tr)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return "", s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return "", fmt.Errorf("write part data: %w", err)
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum)
	err = p.meta.StoreAttribute(f.File(), bucket, partPath, etagkey, []byte(etag))
	if err != nil {
		return "", fmt.Errorf("set etag attr: %w", err)
	}

	err = f.link()
	if err != nil {
		return "", fmt.Errorf("link object in namespace: %w", err)
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

	srcBucket, srcObject, srcVersionId, err := backend.ParseCopySource(*upi.CopySource)
	if err != nil {
		return s3response.CopyObjectResult{}, err
	}

	_, err = os.Stat(srcBucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat bucket: %w", err)
	}

	vStatus, err := p.getBucketVersioningStatus(ctx, srcBucket)
	if err != nil {
		return s3response.CopyObjectResult{}, err
	}
	vEnabled := p.isBucketVersioningEnabled(vStatus)

	if srcVersionId != "" {
		if !p.versioningEnabled() || !vEnabled {
			return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		vId, err := p.meta.RetrieveAttribute(nil, srcBucket, srcObject, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return s3response.CopyObjectResult{}, fmt.Errorf("get src object version id: %w", err)
		}

		if string(vId) != srcVersionId {
			srcBucket = filepath.Join(p.versioningDir, srcBucket)
			srcObject = filepath.Join(genObjVersionKey(srcObject), srcVersionId)
		}
	}

	objPath := filepath.Join(srcBucket, srcObject)
	fi, err := os.Stat(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		if p.versioningEnabled() && vEnabled {
			return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNoSuchVersion)
		}
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

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum)
	err = p.meta.StoreAttribute(f.File(), *upi.Bucket, partPath, etagkey, []byte(etag))
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("set etag attr: %w", err)
	}

	err = f.link()
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("link object in namespace: %w", err)
	}

	fi, err = os.Stat(filepath.Join(*upi.Bucket, partPath))
	if err != nil {
		return s3response.CopyObjectResult{}, fmt.Errorf("stat part path: %w", err)
	}

	return s3response.CopyObjectResult{
		ETag:                etag,
		LastModified:        fi.ModTime(),
		CopySourceVersionId: srcVersionId,
	}, nil
}

func (p *Posix) PutObject(ctx context.Context, po *s3.PutObjectInput) (s3response.PutObjectOutput, error) {
	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	if po.Bucket == nil {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if po.Key == nil {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	tagsStr := getString(po.Tagging)
	tags := make(map[string]string)
	_, err := os.Stat(*po.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return s3response.PutObjectOutput{}, fmt.Errorf("stat bucket: %w", err)
	}

	if tagsStr != "" {
		tagParts := strings.Split(tagsStr, "&")
		for _, prt := range tagParts {
			p := strings.Split(prt, "=")
			if len(p) != 2 {
				return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrInvalidTag)
			}
			if len(p[0]) > 128 || len(p[1]) > 256 {
				return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrInvalidTag)
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
			return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
		}

		err = backend.MkdirAll(name, uid, gid, doChown)
		if err != nil {
			if errors.Is(err, syscall.EDQUOT) {
				return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrQuotaExceeded)
			}
			return s3response.PutObjectOutput{}, err
		}

		for k, v := range po.Metadata {
			err := p.meta.StoreAttribute(nil, *po.Bucket, *po.Key,
				fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
			if err != nil {
				return s3response.PutObjectOutput{}, fmt.Errorf("set user attr %q: %w", k, err)
			}
		}

		// set etag attribute to signify this dir was specifically put
		err = p.meta.StoreAttribute(nil, *po.Bucket, *po.Key, etagkey,
			[]byte(emptyMD5))
		if err != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("set etag attr: %w", err)
		}

		// for directory object no version is created
		return s3response.PutObjectOutput{
			ETag: emptyMD5,
		}, nil
	}

	vStatus, err := p.getBucketVersioningStatus(ctx, *po.Bucket)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	vEnabled := p.isBucketVersioningEnabled(vStatus)

	// object is file
	d, err := os.Stat(name)
	if err == nil && d.IsDir() {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
	}

	// if the versioninng is enabled first create the file object version
	if p.versioningEnabled() && vStatus != "" && err == nil {
		var isVersionIdMissing bool
		if p.isBucketVersioningSuspended(vStatus) {
			vIdBytes, err := p.meta.RetrieveAttribute(nil, *po.Bucket, *po.Key, versionIdKey)
			if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
				return s3response.PutObjectOutput{}, fmt.Errorf("get object versionId: %w", err)
			}
			isVersionIdMissing = len(vIdBytes) == 0
		}
		if !isVersionIdMissing {
			_, err := p.createObjVersion(*po.Bucket, *po.Key, d.Size(), acct)
			if err != nil {
				return s3response.PutObjectOutput{}, fmt.Errorf("create object version: %w", err)
			}
		}
	}
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if errors.Is(err, syscall.ENOTDIR) {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return s3response.PutObjectOutput{}, fmt.Errorf("stat object: %w", err)
	}

	f, err := p.openTmpFile(filepath.Join(*po.Bucket, metaTmpDir),
		*po.Bucket, *po.Key, contentLength, acct, doFalloc)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return s3response.PutObjectOutput{}, fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	hash := md5.New()
	rdr := io.TeeReader(po.Body, hash)
	_, err = io.Copy(f, rdr)
	if err != nil {
		if errors.Is(err, syscall.EDQUOT) {
			return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrQuotaExceeded)
		}
		return s3response.PutObjectOutput{}, fmt.Errorf("write object data: %w", err)
	}

	dir := filepath.Dir(name)
	if dir != "" {
		err = backend.MkdirAll(dir, uid, gid, doChown)
		if err != nil {
			return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
		}
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum[:])

	// if the versioning is enabled, generate a new versionID for the object
	var versionID string
	if p.versioningEnabled() && vEnabled {
		versionID = ulid.Make().String()
	}

	// Before finaliazing the object creation remove
	// null versionId object from versioning directory
	// if it exists and the versioning status is Suspended
	if p.isBucketVersioningSuspended(vStatus) {
		err = p.deleteNullVersionIdObject(*po.Bucket, *po.Key)
		if err != nil {
			return s3response.PutObjectOutput{}, err
		}
		versionID = nullVersionId
	}

	for k, v := range po.Metadata {
		err := p.meta.StoreAttribute(f.File(), *po.Bucket, *po.Key,
			fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
		if err != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	err = p.meta.StoreAttribute(f.File(), *po.Bucket, *po.Key, etagkey, []byte(etag))
	if err != nil {
		return s3response.PutObjectOutput{}, fmt.Errorf("set etag attr: %w", err)
	}

	ctype := getString(po.ContentType)
	if ctype != "" {
		err := p.meta.StoreAttribute(f.File(), *po.Bucket, *po.Key, contentTypeHdr,
			[]byte(*po.ContentType))
		if err != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("set content-type attr: %w", err)
		}
	}

	cenc := getString(po.ContentEncoding)
	if cenc != "" {
		err := p.meta.StoreAttribute(f.File(), *po.Bucket, *po.Key, contentEncHdr,
			[]byte(*po.ContentEncoding))
		if err != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("set content-encoding attr: %w", err)
		}
	}

	if versionID != "" && versionID != nullVersionId {
		err := p.meta.StoreAttribute(f.File(), *po.Bucket, *po.Key, versionIdKey, []byte(versionID))
		if err != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("set versionId attr: %w", err)
		}
	}

	err = f.link()
	if errors.Is(err, syscall.EEXIST) {
		return s3response.PutObjectOutput{
			ETag:      etag,
			VersionID: versionID,
		}, nil
	}
	if err != nil {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
	}

	// Set object tagging
	if tagsStr != "" {
		err := p.PutObjectTagging(ctx, *po.Bucket, *po.Key, tags)
		if errors.Is(err, fs.ErrNotExist) {
			return s3response.PutObjectOutput{
				ETag:      etag,
				VersionID: versionID,
			}, nil
		}
		if err != nil {
			return s3response.PutObjectOutput{}, err
		}
	}

	// Set object legal hold
	if po.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn {
		err := p.PutObjectLegalHold(ctx, *po.Bucket, *po.Key, "", true)
		if err != nil {
			return s3response.PutObjectOutput{}, err
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
			return s3response.PutObjectOutput{}, fmt.Errorf("parse object lock retention: %w", err)
		}
		err = p.PutObjectRetention(ctx, *po.Bucket, *po.Key, "", true, retParsed)
		if err != nil {
			return s3response.PutObjectOutput{}, err
		}
	}

	return s3response.PutObjectOutput{
		ETag:      etag,
		VersionID: versionID,
	}, nil
}

func (p *Posix) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	if input.Bucket == nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	if input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	bucket := *input.Bucket
	object := *input.Key
	isDir := strings.HasSuffix(object, "/")

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	objpath := filepath.Join(bucket, object)

	vStatus, err := p.getBucketVersioningStatus(ctx, bucket)
	if err != nil {
		return nil, err
	}
	vEnabled := p.isBucketVersioningEnabled(vStatus)

	// Directory objects can't have versions
	if !isDir && p.versioningEnabled() && vEnabled {
		if getString(input.VersionId) == "" {
			// if the versionId is not specified, make the current version a delete marker
			fi, err := os.Stat(objpath)
			if errors.Is(err, fs.ErrNotExist) {
				// AWS returns success if the object does not exist
				return &s3.DeleteObjectOutput{}, nil
			}
			if errors.Is(err, syscall.ENAMETOOLONG) {
				return nil, s3err.GetAPIError(s3err.ErrKeyTooLong)
			}
			if err != nil {
				return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
			}

			acct, ok := ctx.Value("account").(auth.Account)
			if !ok {
				acct = auth.Account{}
			}

			// Creates a new version in the versioning directory
			_, err = p.createObjVersion(bucket, object, fi.Size(), acct)
			if err != nil {
				return nil, err
			}

			// Mark the object as a delete marker
			err = p.meta.StoreAttribute(nil, bucket, object, deleteMarkerKey, []byte{})
			if err != nil {
				return nil, fmt.Errorf("set delete marker: %w", err)
			}
			// Generate & set a unique versionId for the delete marker
			versionId := ulid.Make().String()
			err = p.meta.StoreAttribute(nil, bucket, object, versionIdKey, []byte(versionId))
			if err != nil {
				return nil, fmt.Errorf("set versionId: %w", err)
			}

			return &s3.DeleteObjectOutput{
				DeleteMarker: getBoolPtr(true),
				VersionId:    &versionId,
			}, nil
		} else {
			versionPath := p.genObjVersionPath(bucket, object)

			vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
			if err != nil && !errors.Is(err, meta.ErrNoSuchKey) && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("get obj versionId: %w", err)
			}
			if errors.Is(err, meta.ErrNoSuchKey) {
				vId = []byte(nullVersionId)
			}

			if string(vId) == *input.VersionId {
				// if the specified VersionId is the same as in the latest version,
				// remove the latest version, find the latest version from the versioning
				// directory and move to the place of the deleted object, to make it the latest

				isDelMarker, err := p.isObjDeleteMarker(bucket, object)
				if err != nil {
					return nil, err
				}
				err = os.Remove(objpath)
				if err != nil {
					return nil, fmt.Errorf("remove obj version: %w", err)
				}

				ents, err := os.ReadDir(versionPath)
				if errors.Is(err, fs.ErrNotExist) {
					return &s3.DeleteObjectOutput{
						DeleteMarker: &isDelMarker,
						VersionId:    input.VersionId,
					}, nil
				}
				if err != nil {
					return nil, fmt.Errorf("read version dir: %w", err)
				}

				if len(ents) == 0 {
					return &s3.DeleteObjectOutput{
						DeleteMarker: &isDelMarker,
						VersionId:    input.VersionId,
					}, nil
				}

				srcObjVersion, err := ents[len(ents)-1].Info()
				if err != nil {
					return nil, fmt.Errorf("get file info: %w", err)
				}
				srcVersionId := srcObjVersion.Name()
				sf, err := os.Open(filepath.Join(versionPath, srcVersionId))
				if err != nil {
					return nil, fmt.Errorf("open obj version: %w", err)
				}
				defer sf.Close()
				acct, ok := ctx.Value("account").(auth.Account)
				if !ok {
					acct = auth.Account{}
				}

				f, err := p.openTmpFile(filepath.Join(bucket, metaTmpDir), bucket, object, srcObjVersion.Size(), acct, doFalloc)
				if err != nil {
					return nil, fmt.Errorf("open tmp file: %w", err)
				}
				defer f.cleanup()

				_, err = io.Copy(f, sf)
				if err != nil {
					return nil, fmt.Errorf("copy object %w", err)
				}

				if err := f.link(); err != nil {
					return nil, fmt.Errorf("link tmp file: %w", err)
				}

				attrs, err := p.meta.ListAttributes(versionPath, srcVersionId)
				if err != nil {
					return nil, fmt.Errorf("list object attributes: %w", err)
				}

				for _, attr := range attrs {
					data, err := p.meta.RetrieveAttribute(nil, versionPath, srcVersionId, attr)
					if err != nil {
						return nil, fmt.Errorf("load %v attribute", attr)
					}

					err = p.meta.StoreAttribute(nil, bucket, object, attr, data)
					if err != nil {
						return nil, fmt.Errorf("store %v attribute", attr)
					}
				}

				err = os.Remove(filepath.Join(versionPath, srcVersionId))
				if err != nil {
					return nil, fmt.Errorf("remove obj version %w", err)
				}

				return &s3.DeleteObjectOutput{
					DeleteMarker: &isDelMarker,
					VersionId:    input.VersionId,
				}, nil
			}

			isDelMarker, _ := p.isObjDeleteMarker(versionPath, *input.VersionId)

			err = os.Remove(filepath.Join(versionPath, *input.VersionId))
			if errors.Is(err, syscall.ENAMETOOLONG) {
				return nil, s3err.GetAPIError(s3err.ErrKeyTooLong)
			}
			if errors.Is(err, fs.ErrNotExist) {
				return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
			}
			if err != nil {
				return nil, fmt.Errorf("delete object: %w", err)
			}

			return &s3.DeleteObjectOutput{
				DeleteMarker: &isDelMarker,
				VersionId:    input.VersionId,
			}, nil
		}
	}

	fi, err := os.Stat(objpath)
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return nil, s3err.GetAPIError(s3err.ErrKeyTooLong)
	}
	if errors.Is(err, fs.ErrNotExist) {
		// AWS returns success if the object does not exist
		return &s3.DeleteObjectOutput{}, nil
	}
	if err != nil {
		return &s3.DeleteObjectOutput{}, fmt.Errorf("stat object: %w", err)
	}
	if strings.HasSuffix(object, "/") && !fi.IsDir() {
		// requested object is expecting a directory with a trailing
		// slash, but the object is not a directory. treat this as
		// a non-existent object.
		// AWS returns success if the object does not exist
		return &s3.DeleteObjectOutput{}, nil
	}
	if !strings.HasSuffix(object, "/") && fi.IsDir() {
		// requested object is expecting a file, but the object is a
		// directory. treat this as a non-existent object.
		// AWS returns success if the object does not exist
		return &s3.DeleteObjectOutput{}, nil
	}

	err = os.Remove(objpath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("delete object: %w", err)
	}

	err = p.meta.DeleteAttributes(bucket, object)
	if err != nil {
		return nil, fmt.Errorf("delete object attributes: %w", err)
	}

	err = p.removeParents(bucket, object)
	if err != nil {
		return nil, err
	}

	return &s3.DeleteObjectOutput{}, nil
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

		if parent == string(filepath.Separator) || parent == "." {
			// stop removing parents if we hit the bucket directory.
			break
		}

		_, err := p.meta.RetrieveAttribute(nil, bucket, parent, etagkey)
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
		res, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    input.Bucket,
			Key:       obj.Key,
			VersionId: obj.VersionId,
		})
		if err == nil {
			delEntity := types.DeletedObject{
				Key:          obj.Key,
				DeleteMarker: res.DeleteMarker,
				VersionId:    obj.VersionId,
			}
			if delEntity.DeleteMarker != nil && *delEntity.DeleteMarker {
				delEntity.DeleteMarkerVersionId = res.VersionId
			}

			delResult = append(delResult, delEntity)
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
					Code:    backend.GetPtrFromString("InternalError"),
					Message: backend.GetPtrFromString(err.Error()),
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
	var versionId string
	if input.VersionId != nil {
		versionId = *input.VersionId
	}

	if !p.versioningEnabled() && versionId != "" {
		//TODO: Maybe we need to return our custom error here?
		return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
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
	if versionId != "" {
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return nil, fmt.Errorf("get obj versionId: %w", err)
		}
		if errors.Is(err, meta.ErrNoSuchKey) {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), versionId)
		}

		if string(vId) != versionId {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), versionId)
		}
	}

	objPath := filepath.Join(bucket, object)

	fi, err := os.Stat(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		if versionId != "" {
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
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
	if !strings.HasSuffix(object, "/") && fi.IsDir() {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	if versionId != "" {
		isDelMarker, err := p.isObjDeleteMarker(bucket, object)
		if err != nil {
			return nil, err
		}

		// if the specified object version is a delete marker, return MethodNotAllowed
		if isDelMarker {
			return &s3.GetObjectOutput{
				DeleteMarker: getBoolPtr(true),
				LastModified: backend.GetTimePtr(fi.ModTime()),
			}, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
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

		b, err := p.meta.RetrieveAttribute(nil, bucket, object, etagkey)
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
			VersionId:       &versionId,
		}, nil
	}

	// If versioning is configured get the object versionId
	if p.versioningEnabled() && versionId == "" {
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, meta.ErrNoSuchKey) {
			versionId = nullVersionId
		} else if err != nil {
			return nil, err
		}

		versionId = string(vId)
	}

	userMetaData := make(map[string]string)

	contentType, contentEncoding := p.loadUserMetaData(bucket, object, userMetaData)

	b, err := p.meta.RetrieveAttribute(nil, bucket, object, etagkey)
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
		VersionId:       &versionId,
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

	if !p.versioningEnabled() && *input.VersionId != "" {
		//TODO: Maybe we need to return our custom error here?
		return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
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

		b, err := p.meta.RetrieveAttribute(nil, bucket, partPath, etagkey)
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

	if *input.VersionId != "" {
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return nil, fmt.Errorf("get obj versionId: %w", err)
		}
		if errors.Is(err, meta.ErrNoSuchKey) {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), *input.VersionId)
		}

		if string(vId) != *input.VersionId {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), *input.VersionId)
		}
	}

	objPath := filepath.Join(bucket, object)

	fi, err := os.Stat(objPath)
	if errors.Is(err, fs.ErrNotExist) {
		if *input.VersionId != "" {
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
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
	if !strings.HasSuffix(object, "/") && fi.IsDir() {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	if *input.VersionId != "" {
		isDelMarker, err := p.isObjDeleteMarker(bucket, object)
		if err != nil {
			return nil, err
		}

		// if the specified object version is a delete marker, return MethodNotAllowed
		if isDelMarker {
			return &s3.HeadObjectOutput{
				DeleteMarker: getBoolPtr(true),
				LastModified: backend.GetTimePtr(fi.ModTime()),
			}, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
	}

	userMetaData := make(map[string]string)
	contentType, contentEncoding := p.loadUserMetaData(bucket, object, userMetaData)

	if fi.IsDir() {
		contentType = backend.DirContentType
	}

	b, err := p.meta.RetrieveAttribute(nil, bucket, object, etagkey)
	etag := string(b)
	if err != nil {
		etag = ""
	}

	size := fi.Size()

	var objectLockLegalHoldStatus types.ObjectLockLegalHoldStatus
	status, err := p.GetObjectLegalHold(ctx, bucket, object, *input.VersionId)
	if err == nil {
		if *status {
			objectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
		} else {
			objectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOff
		}
	}

	var objectLockMode types.ObjectLockMode
	var objectLockRetainUntilDate *time.Time
	retention, err := p.GetObjectRetention(ctx, bucket, object, *input.VersionId)
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
		VersionId:                 input.VersionId,
	}, nil
}

func (p *Posix) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResult, error) {
	data, err := p.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:    input.Bucket,
		Key:       input.Key,
		VersionId: input.VersionId,
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

	srcBucket, srcObject, srcVersionId, err := backend.ParseCopySource(*input.CopySource)
	if err != nil {
		return nil, err
	}
	dstBucket := *input.Bucket
	dstObject := *input.Key

	_, err = os.Stat(srcBucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	vStatus, err := p.getBucketVersioningStatus(ctx, srcBucket)
	if err != nil {
		return nil, err
	}
	vEnabled := p.isBucketVersioningEnabled(vStatus)

	if srcVersionId != "" {
		if !p.versioningEnabled() || !vEnabled {
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		vId, err := p.meta.RetrieveAttribute(nil, srcBucket, srcObject, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return nil, fmt.Errorf("get src object version id: %w", err)
		}

		if string(vId) != srcVersionId {
			srcBucket = filepath.Join(p.versioningDir, srcBucket)
			srcObject = filepath.Join(genObjVersionKey(srcObject), srcVersionId)
		}
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
		if p.versioningEnabled() && vEnabled {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchVersion)
		}
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
	if !strings.HasSuffix(srcObject, "/") && fi.IsDir() {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	mdmap := make(map[string]string)
	p.loadUserMetaData(srcBucket, srcObject, mdmap)

	var etag string
	var version *string

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
			err := p.meta.StoreAttribute(nil, dstBucket, dstObject,
				fmt.Sprintf("%v.%v", metaHdr, k), []byte(v))
			if err != nil {
				return nil, fmt.Errorf("set user attr %q: %w", k, err)
			}
		}

		b, _ := p.meta.RetrieveAttribute(nil, dstBucket, dstObject, etagkey)
		etag = string(b)
		vId, _ := p.meta.RetrieveAttribute(nil, dstBucket, dstObject, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		version = backend.GetStringPtr(string(vId))
	} else {
		contentLength := fi.Size()
		res, err := p.PutObject(ctx,
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
		etag = res.ETag
		version = &res.VersionID
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
		VersionId:           version,
		CopySourceVersionId: &srcVersionId,
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
		Delimiter:      backend.GetPtrFromString(delim),
		Marker:         backend.GetPtrFromString(marker),
		NextMarker:     backend.GetPtrFromString(results.NextMarker),
		Prefix:         backend.GetPtrFromString(prefix),
		IsTruncated:    &results.Truncated,
		MaxKeys:        &maxkeys,
		Name:           &bucket,
	}, nil
}

func (p *Posix) fileToObj(bucket string) backend.GetObjFunc {
	return func(path string, d fs.DirEntry) (s3response.Object, error) {
		if d.IsDir() {
			// directory object only happens if directory empty
			// check to see if this is a directory object by checking etag
			etagBytes, err := p.meta.RetrieveAttribute(nil, bucket, path, etagkey)
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

		// If the object is a delete marker, skip
		isDel, _ := p.isObjDeleteMarker(bucket, path)
		if isDel {
			return s3response.Object{}, backend.ErrSkipObj
		}

		// file object, get object info and fill out object data
		etagBytes, err := p.meta.RetrieveAttribute(nil, bucket, path, etagkey)
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

func (p *Posix) PutBucketAcl(_ context.Context, bucket string, data []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	err = p.meta.StoreAttribute(nil, bucket, "", aclkey, data)
	if err != nil {
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

	b, err := p.meta.RetrieveAttribute(nil, *input.Bucket, "", aclkey)
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

	err = p.meta.StoreAttribute(nil, bucket, "", tagHdr, b)
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
	b, err := p.meta.RetrieveAttribute(nil, bucket, object, tagHdr)
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

	err = p.meta.StoreAttribute(nil, bucket, object, tagHdr, b)
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

	err = p.meta.StoreAttribute(nil, bucket, "", policykey, policy)
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

	policy, err := p.meta.RetrieveAttribute(nil, bucket, "", policykey)
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

func (p *Posix) isBucketObjectLockEnabled(bucket string) error {
	cfg, err := p.meta.RetrieveAttribute(nil, bucket, "", bucketLockKey)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
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

	return nil
}

func (p *Posix) PutObjectLockConfiguration(ctx context.Context, bucket string, config []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	cfg, err := p.meta.RetrieveAttribute(nil, bucket, "", bucketLockKey)
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

	err = p.meta.StoreAttribute(nil, bucket, "", bucketLockKey, config)
	if err != nil {
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

	cfg, err := p.meta.RetrieveAttribute(nil, bucket, "", bucketLockKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get object lock config: %w", err)
	}

	return cfg, nil
}

func (p *Posix) PutObjectLegalHold(_ context.Context, bucket, object, versionId string, status bool) error {
	err := p.doesBucketAndObjectExist(bucket, object)
	if err != nil {
		return err
	}
	err = p.isBucketObjectLockEnabled(bucket)
	if err != nil {
		return err
	}

	var statusData []byte
	if status {
		statusData = []byte{1}
	} else {
		statusData = []byte{0}
	}

	if versionId != "" {
		if !p.versioningEnabled() {
			//TODO: Maybe we need to return our custom error here?
			return s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return fmt.Errorf("get obj versionId: %w", err)
		}

		if string(vId) != versionId {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), versionId)
		}
	}

	err = p.meta.StoreAttribute(nil, bucket, object, objectLegalHoldKey, statusData)
	if errors.Is(err, fs.ErrNotExist) {
		if versionId != "" {
			return s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("set object lock config: %w", err)
	}

	return nil
}

func (p *Posix) GetObjectLegalHold(_ context.Context, bucket, object, versionId string) (*bool, error) {
	err := p.doesBucketAndObjectExist(bucket, object)
	if err != nil {
		return nil, err
	}
	err = p.isBucketObjectLockEnabled(bucket)
	if err != nil {
		return nil, err
	}

	if versionId != "" {
		if !p.versioningEnabled() {
			//TODO: Maybe we need to return our custom error here?
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return nil, fmt.Errorf("get obj versionId: %w", err)
		}

		if string(vId) != versionId {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), versionId)
		}
	}

	data, err := p.meta.RetrieveAttribute(nil, bucket, object, objectLegalHoldKey)
	if errors.Is(err, fs.ErrNotExist) {
		if versionId != "" {
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
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
	err := p.doesBucketAndObjectExist(bucket, object)
	if err != nil {
		return err
	}
	err = p.isBucketObjectLockEnabled(bucket)
	if err != nil {
		return err
	}

	if versionId != "" {
		if !p.versioningEnabled() {
			//TODO: Maybe we need to return our custom error here?
			return s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return fmt.Errorf("get obj versionId: %w", err)
		}

		if string(vId) != versionId {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), versionId)
		}
	}

	objectLockCfg, err := p.meta.RetrieveAttribute(nil, bucket, object, objectRetentionKey)
	if errors.Is(err, fs.ErrNotExist) {
		if versionId != "" {
			return s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, meta.ErrNoSuchKey) {
		err := p.meta.StoreAttribute(nil, bucket, object, objectRetentionKey, retention)
		if err != nil {
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

	err = p.meta.StoreAttribute(nil, bucket, object, objectRetentionKey, retention)
	if err != nil {
		return fmt.Errorf("set object lock config: %w", err)
	}

	return nil
}

func (p *Posix) GetObjectRetention(_ context.Context, bucket, object, versionId string) ([]byte, error) {
	err := p.doesBucketAndObjectExist(bucket, object)
	if err != nil {
		return nil, err
	}
	err = p.isBucketObjectLockEnabled(bucket)
	if err != nil {
		return nil, err
	}

	if versionId != "" {
		if !p.versioningEnabled() {
			//TODO: Maybe we need to return our custom error here?
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
		vId, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		}
		if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
			return nil, fmt.Errorf("get obj versionId: %w", err)
		}

		if string(vId) != versionId {
			bucket = filepath.Join(p.versioningDir, bucket)
			object = filepath.Join(genObjVersionKey(object), versionId)
		}
	}

	data, err := p.meta.RetrieveAttribute(nil, bucket, object, objectRetentionKey)
	if errors.Is(err, fs.ErrNotExist) {
		if versionId != "" {
			return nil, s3err.GetAPIError(s3err.ErrInvalidVersionId)
		}
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

		aclTag, err := p.meta.RetrieveAttribute(nil, entry.Name(), "", aclkey)
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
