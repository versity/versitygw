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
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/pkg/xattr"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type Posix struct {
	backend.BackendUnsupported

	rootfd  *os.File
	rootdir string

	mu        sync.RWMutex
	iamcache  []byte
	iamvalid  bool
	iamexpire time.Time
}

var _ backend.Backend = &Posix{}

var (
	cacheDuration = 5 * time.Minute
)

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
	onameAttr           = "user.objname"
	tagHdr              = "X-Amz-Tagging"
	contentTypeHdr      = "content-type"
	contentEncHdr       = "content-encoding"
	emptyMD5            = "d41d8cd98f00b204e9800998ecf8427e"
	iamFile             = "users.json"
	iamBackupFile       = "users.json.backup"
	aclkey              = "user.acl"
	etagkey             = "user.etag"
)

func New(rootdir string) (*Posix, error) {
	err := os.Chdir(rootdir)
	if err != nil {
		return nil, fmt.Errorf("chdir %v: %w", rootdir, err)
	}

	f, err := os.Open(rootdir)
	if err != nil {
		return nil, fmt.Errorf("open %v: %w", rootdir, err)
	}

	return &Posix{rootfd: f, rootdir: rootdir}, nil
}

func (p *Posix) Shutdown() {
	p.rootfd.Close()
}

func (p *Posix) String() string {
	return "Posix Gateway"
}

func (p *Posix) ListBuckets() (s3response.ListAllMyBucketsResult, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return s3response.ListAllMyBucketsResult{},
			fmt.Errorf("readdir buckets: %w", err)
	}

	var buckets []s3response.ListAllMyBucketsEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			// buckets must be a directory
			continue
		}

		fi, err := entry.Info()
		if err != nil {
			// skip entries returning errors
			continue
		}

		buckets = append(buckets, s3response.ListAllMyBucketsEntry{
			Name:         entry.Name(),
			CreationDate: fi.ModTime(),
		})
	}

	sort.Sort(backend.ByBucketName(buckets))

	return s3response.ListAllMyBucketsResult{
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: buckets,
		},
	}, nil
}

func (p *Posix) HeadBucket(bucket string) (*s3.HeadBucketOutput, error) {
	_, err := os.Lstat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	return &s3.HeadBucketOutput{}, nil
}

func (p *Posix) PutBucket(bucket string, owner string) error {
	err := os.Mkdir(bucket, 0777)
	if err != nil && os.IsExist(err) {
		return s3err.GetAPIError(s3err.ErrBucketAlreadyExists)
	}
	if err != nil {
		return fmt.Errorf("mkdir bucket: %w", err)
	}

	acl := auth.ACL{ACL: "private", Owner: owner, Grantees: []auth.Grantee{}}
	jsonACL, err := json.Marshal(acl)
	if err != nil {
		return fmt.Errorf("marshal acl: %w", err)
	}

	if err := xattr.Set(bucket, aclkey, jsonACL); err != nil {
		return fmt.Errorf("set acl: %w", err)
	}

	return nil
}

func (p *Posix) DeleteBucket(bucket string) error {
	names, err := os.ReadDir(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("readdir bucket: %w", err)
	}

	if len(names) == 1 && names[0].Name() == metaTmpDir {
		// if .sgwtmp is only item in directory
		// then clean this up before trying to remove the bucket
		err = os.RemoveAll(filepath.Join(bucket, metaTmpDir))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove temp dir: %w", err)
		}
	}

	err = os.Remove(bucket)
	if err != nil && err.(*os.PathError).Err == syscall.ENOTEMPTY {
		return s3err.GetAPIError(s3err.ErrBucketNotEmpty)
	}
	if err != nil {
		return fmt.Errorf("remove bucket: %w", err)
	}

	return nil
}

func (p *Posix) CreateMultipartUpload(mpu *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	bucket := *mpu.Bucket
	object := *mpu.Key

	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	// generate random uuid for upload id
	uploadID := uuid.New().String()
	// hash object name for multipart container
	objNameSum := sha256.Sum256([]byte(*mpu.Key))
	// multiple uploads for same object name allowed,
	// they will all go into the same hashed name directory
	objdir := filepath.Join(bucket, metaTmpMultipartDir,
		fmt.Sprintf("%x", objNameSum))
	// the unique upload id is a directory for all of the parts
	// associated with this specific multipart upload
	err = os.MkdirAll(filepath.Join(objdir, uploadID), 0755)
	if err != nil {
		return nil, fmt.Errorf("create upload temp dir: %w", err)
	}

	// set an xattr with the original object name so that we can
	// map the hashed name back to the original object name
	err = xattr.Set(objdir, onameAttr, []byte(object))
	if err != nil {
		// if we fail, cleanup the container directories
		// but ignore errors because there might still be
		// other uploads for the same object name outstanding
		os.RemoveAll(filepath.Join(objdir, uploadID))
		os.Remove(objdir)
		return nil, fmt.Errorf("set name attr for upload: %w", err)
	}

	// set user attrs
	for k, v := range mpu.Metadata {
		xattr.Set(filepath.Join(objdir, uploadID), "user."+k, []byte(v))
	}

	return &s3.CreateMultipartUploadOutput{
		Bucket:   &bucket,
		Key:      &object,
		UploadId: &uploadID,
	}, nil
}

func (p *Posix) CompleteMultipartUpload(bucket, object, uploadID string, parts []types.Part) (*s3.CompleteMultipartUploadOutput, error) {
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

	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	// check all parts ok
	last := len(parts) - 1
	partsize := int64(0)
	var totalsize int64
	for i, p := range parts {
		partPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", p.PartNumber))
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

		b, err := xattr.Get(partPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}
		parts[i].ETag = &etag
	}

	f, err := openTmpFile(filepath.Join(bucket, metaTmpDir), bucket, object, totalsize)
	if err != nil {
		return nil, fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	for _, p := range parts {
		pf, err := os.Open(filepath.Join(objdir, uploadID, fmt.Sprintf("%v", p.PartNumber)))
		if err != nil {
			return nil, fmt.Errorf("open part %v: %v", p.PartNumber, err)
		}
		_, err = io.Copy(f, pf)
		pf.Close()
		if err != nil {
			return nil, fmt.Errorf("copy part %v: %v", p.PartNumber, err)
		}
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	loadUserMetaData(upiddir, userMetaData)

	objname := filepath.Join(bucket, object)
	dir := filepath.Dir(objname)
	if dir != "" {
		if err = mkdirAll(dir, os.FileMode(0755), bucket, object); err != nil {
			if err != nil {
				return nil, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
			}
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

	err = xattr.Set(objname, etagkey, []byte(s3MD5))
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
		if err == syscall.ENODATA {
			m[strings.TrimPrefix(e, "user.")] = ""
			continue
		}
		if err != nil {
			continue
		}
		m[strings.TrimPrefix(e, "user.")] = string(b)
	}

	b, err := xattr.Get(path, "user."+contentTypeHdr)
	contentType = string(b)
	if err != nil {
		contentType = ""
	}
	if contentType != "" {
		m[contentTypeHdr] = contentType
	}

	b, err = xattr.Get(path, "user."+contentEncHdr)
	contentEncoding = string(b)
	if err != nil {
		contentEncoding = ""
	}
	if contentEncoding != "" {
		m[contentEncHdr] = contentEncoding
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

// mkdirAll is similar to os.MkdirAll but it will return ErrObjectParentIsFile
// when appropriate
func mkdirAll(path string, perm os.FileMode, bucket, object string) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = mkdirAll(path[:j-1], perm, bucket, object)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = os.Mkdir(path, perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}
	return nil
}

func (p *Posix) AbortMultipartUpload(mpu *s3.AbortMultipartUploadInput) error {
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

func (p *Posix) ListMultipartUploads(mpu *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResponse, error) {
	bucket := *mpu.Bucket
	var delimiter string
	if mpu.Delimiter != nil {
		delimiter = *mpu.Delimiter
	}
	var prefix string
	if mpu.Prefix != nil {
		prefix = *mpu.Prefix
	}

	var lmu s3response.ListMultipartUploadsResponse

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

	var keyMarker string
	if mpu.KeyMarker != nil {
		keyMarker = *mpu.KeyMarker
	}
	var uploadIDMarker string
	if mpu.UploadIdMarker != nil {
		uploadIDMarker = *mpu.UploadIdMarker
	}
	var pastMarker bool
	if keyMarker == "" && uploadIDMarker == "" {
		pastMarker = true
	}

	for i, obj := range objs {
		if !obj.IsDir() {
			continue
		}

		b, err := xattr.Get(filepath.Join(bucket, metaTmpMultipartDir, obj.Name()), onameAttr)
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

		for j, upid := range upids {
			if !upid.IsDir() {
				continue
			}

			if objectName == keyMarker || upid.Name() == uploadIDMarker {
				pastMarker = true
				continue
			}
			if keyMarker != "" && uploadIDMarker != "" && !pastMarker {
				continue
			}

			userMetaData := make(map[string]string)
			upiddir := filepath.Join(bucket, metaTmpMultipartDir, obj.Name(), upid.Name())
			loadUserMetaData(upiddir, userMetaData)

			fi, err := upid.Info()
			if err != nil {
				return lmu, fmt.Errorf("stat %q: %w", upid.Name(), err)
			}

			uploadID := upid.Name()
			uploads = append(uploads, s3response.Upload{
				Key:       objectName,
				UploadID:  uploadID,
				Initiated: fi.ModTime().Format(backend.RFC3339TimeFormat),
			})
			if len(uploads) == int(mpu.MaxUploads) {
				return s3response.ListMultipartUploadsResponse{
					Bucket:             bucket,
					Delimiter:          delimiter,
					IsTruncated:        i != len(objs) || j != len(upids),
					KeyMarker:          keyMarker,
					MaxUploads:         int(mpu.MaxUploads),
					NextKeyMarker:      objectName,
					NextUploadIDMarker: uploadID,
					Prefix:             prefix,
					UploadIDMarker:     uploadIDMarker,
					Uploads:            uploads,
				}, nil
			}
		}
	}

	return s3response.ListMultipartUploadsResponse{
		Bucket:         bucket,
		Delimiter:      delimiter,
		KeyMarker:      keyMarker,
		MaxUploads:     int(mpu.MaxUploads),
		Prefix:         prefix,
		UploadIDMarker: uploadIDMarker,
		Uploads:        uploads,
	}, nil
}

func (p *Posix) ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (s3response.ListPartsResponse, error) {
	var lpr s3response.ListPartsResponse
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

	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	ents, err := os.ReadDir(filepath.Join(objdir, uploadID))
	if errors.Is(err, fs.ErrNotExist) {
		return lpr, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if err != nil {
		return lpr, fmt.Errorf("readdir upload: %w", err)
	}

	var parts []s3response.Part
	for _, e := range ents {
		pn, _ := strconv.Atoi(e.Name())
		if pn <= partNumberMarker {
			continue
		}

		partPath := filepath.Join(objdir, uploadID, e.Name())
		b, err := xattr.Get(partPath, etagkey)
		etag := string(b)
		if err != nil {
			etag = ""
		}

		fi, err := os.Lstat(partPath)
		if err != nil {
			continue
		}

		parts = append(parts, s3response.Part{
			PartNumber:   pn,
			ETag:         etag,
			LastModified: fi.ModTime().Format(backend.RFC3339TimeFormat),
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
	loadUserMetaData(upiddir, userMetaData)

	return s3response.ListPartsResponse{
		Bucket:               bucket,
		IsTruncated:          oldLen != newLen,
		Key:                  object,
		MaxParts:             maxParts,
		NextPartNumberMarker: nextpart,
		PartNumberMarker:     partNumberMarker,
		Parts:                parts,
		UploadID:             uploadID,
	}, nil
}

// TODO: copy part
// func (p *Posix) CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*types.CopyPartResult, error) {
// }

func (p *Posix) PutObjectPart(bucket, object, uploadID string, part int, length int64, r io.Reader) (string, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return "", fmt.Errorf("stat bucket: %w", err)
	}

	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(metaTmpMultipartDir, fmt.Sprintf("%x", sum))
	partPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", part))

	f, err := openTmpFile(filepath.Join(bucket, objdir),
		bucket, partPath, length)
	if err != nil {
		return "", fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	hash := md5.New()
	tr := io.TeeReader(r, hash)
	_, err = io.Copy(f, tr)
	if err != nil {
		return "", fmt.Errorf("write part data: %w", err)
	}

	err = f.link()
	if err != nil {
		return "", fmt.Errorf("link object in namespace: %w", err)
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum)
	xattr.Set(partPath, etagkey, []byte(etag))

	return etag, nil
}

func (p *Posix) PutObject(po *s3.PutObjectInput) (string, error) {
	_, err := os.Stat(*po.Bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return "", fmt.Errorf("stat bucket: %w", err)
	}

	name := filepath.Join(*po.Bucket, *po.Key)

	if strings.HasSuffix(*po.Key, "/") {
		// object is directory
		err = mkdirAll(name, os.FileMode(0755), *po.Bucket, *po.Key)
		if err != nil {
			return "", err
		}

		for k, v := range po.Metadata {
			xattr.Set(name, "user."+k, []byte(v))
		}

		// set etag attribute to signify this dir was specifically put
		xattr.Set(name, etagkey, []byte(emptyMD5))

		return emptyMD5, nil
	}

	// object is file
	f, err := openTmpFile(filepath.Join(*po.Bucket, metaTmpDir),
		*po.Bucket, *po.Key, po.ContentLength)
	if err != nil {
		return "", fmt.Errorf("open temp file: %w", err)
	}
	defer f.cleanup()

	hash := md5.New()
	rdr := io.TeeReader(po.Body, hash)
	_, err = io.Copy(f, rdr)
	if err != nil {
		return "", fmt.Errorf("write object data: %w", err)
	}
	dir := filepath.Dir(name)
	if dir != "" {
		err = mkdirAll(dir, os.FileMode(0755), *po.Bucket, *po.Key)
		if err != nil {
			return "", s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
		}
	}

	err = f.link()
	if err != nil {
		return "", fmt.Errorf("link object in namespace: %w", err)
	}

	for k, v := range po.Metadata {
		xattr.Set(name, "user."+k, []byte(v))
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum[:])
	xattr.Set(name, etagkey, []byte(etag))

	return etag, nil
}

func (p *Posix) DeleteObject(bucket, object string) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	os.Remove(filepath.Join(bucket, object))
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("delete object: %w", err)
	}

	return p.removeParents(bucket, object)
}

func (p *Posix) removeParents(bucket, object string) error {
	// this will remove all parent directories that were not
	// specifically uploaded with a put object. we detect
	// this with a special xattr to indicate these. stop
	// at either the bucket or the first parent we encounter
	// with the xattr, whichever comes first.
	objPath := filepath.Join(bucket, object)

	for {
		parent := filepath.Dir(objPath)

		if filepath.Base(parent) == bucket {
			// stop removing parents if we hit the bucket directory.
			break
		}

		_, err := xattr.Get(parent, etagkey)
		if err == nil {
			// a directory with a valid etag means this was specifically
			// uploaded with a put object, so stop here and leave this
			// directory in place.
			break
		}

		err = os.Remove(parent)
		if err != nil {
			break
		}

		objPath = parent
	}
	return nil
}

func (p *Posix) DeleteObjects(bucket string, objects *s3.DeleteObjectsInput) error {
	// delete object already checks bucket
	for _, obj := range objects.Delete.Objects {
		err := p.DeleteObject(bucket, *obj.Key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Posix) GetObject(bucket, object, acceptRange string, writer io.Writer) (*s3.GetObjectOutput, error) {
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

	if length == -1 {
		length = fi.Size() - startOffset + 1
	}

	if startOffset+length > fi.Size()+1 {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
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

	tags, err := p.getXattrTags(bucket, object)
	if err != nil {
		return nil, fmt.Errorf("get object tags: %w", err)
	}

	return &s3.GetObjectOutput{
		AcceptRanges:    &acceptRange,
		ContentLength:   length,
		ContentEncoding: &contentEncoding,
		ContentType:     &contentType,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
		TagCount:        int32(len(tags)),
	}, nil
}

func (p *Posix) HeadObject(bucket, object string) (*s3.HeadObjectOutput, error) {
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

	return &s3.HeadObjectOutput{
		ContentLength:   fi.Size(),
		ContentType:     &contentType,
		ContentEncoding: &contentEncoding,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
	}, nil
}

func (p *Posix) CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3.CopyObjectOutput, error) {
	_, err := os.Stat(srcBucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	_, err = os.Stat(DstBucket)
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
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}
	defer f.Close()

	etag, err := p.PutObject(&s3.PutObjectInput{Bucket: &DstBucket, Key: &dstObject, Body: f})
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(filepath.Join(DstBucket, dstObject))
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

func (p *Posix) ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(fileSystem, prefix, delim, marker, maxkeys,
		fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return nil, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return &s3.ListObjectsOutput{
		CommonPrefixes: results.CommonPrefixes,
		Contents:       results.Objects,
		Delimiter:      &delim,
		IsTruncated:    results.Truncated,
		Marker:         &marker,
		MaxKeys:        int32(maxkeys),
		Name:           &bucket,
		NextMarker:     &results.NextMarker,
		Prefix:         &prefix,
	}, nil
}

func fileToObj(bucket string) backend.GetObjFunc {
	return func(path string, d fs.DirEntry) (types.Object, error) {
		if d.IsDir() {
			// directory object only happens if directory empty
			// check to see if this is a directory object by checking etag
			etagBytes, err := xattr.Get(filepath.Join(bucket, path), etagkey)
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
		etagBytes, err := xattr.Get(filepath.Join(bucket, path), etagkey)
		if errors.Is(err, fs.ErrNotExist) {
			return types.Object{}, backend.ErrSkipObj
		}
		if err != nil && !isNoAttr(err) {
			return types.Object{}, fmt.Errorf("get etag: %w", err)
		}
		// note: isNoAttr(err) will return etagBytes = []byte{}
		// so this will just set etag to "" if its not already set

		etag := string(etagBytes)

		fi, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return types.Object{}, backend.ErrSkipObj
		}
		if err != nil {
			return types.Object{}, fmt.Errorf("get fileinfo: %w", err)
		}

		return types.Object{
			ETag:         &etag,
			Key:          &path,
			LastModified: backend.GetTimePtr(fi.ModTime()),
			Size:         fi.Size(),
		}, nil
	}
}

func (p *Posix) ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(fileSystem, prefix, delim, marker, maxkeys,
		fileToObj(bucket), []string{metaTmpDir})
	if err != nil {
		return nil, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return &s3.ListObjectsV2Output{
		CommonPrefixes:        results.CommonPrefixes,
		Contents:              results.Objects,
		Delimiter:             &delim,
		IsTruncated:           results.Truncated,
		ContinuationToken:     &marker,
		MaxKeys:               int32(maxkeys),
		Name:                  &bucket,
		NextContinuationToken: &results.NextMarker,
		Prefix:                &prefix,
	}, nil
}

func (p *Posix) PutBucketAcl(bucket string, data []byte) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if err := xattr.Set(bucket, aclkey, data); err != nil {
		return fmt.Errorf("set acl: %w", err)
	}

	return nil
}

func (p *Posix) GetBucketAcl(bucket string) ([]byte, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	b, err := xattr.Get(bucket, aclkey)
	if isNoAttr(err) {
		return []byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get acl: %w", err)
	}
	return b, nil
}

func (p *Posix) GetTags(bucket, object string) (map[string]string, error) {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	return p.getXattrTags(bucket, object)
}

func (p *Posix) getXattrTags(bucket, object string) (map[string]string, error) {
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

func (p *Posix) SetTags(bucket, object string, tags map[string]string) error {
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	if tags == nil {
		err = xattr.Remove(filepath.Join(bucket, object), "user."+tagHdr)
		if errors.Is(err, fs.ErrNotExist) {
			return s3err.GetAPIError(s3err.ErrNoSuchKey)
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

	err = xattr.Set(filepath.Join(bucket, object), "user."+tagHdr, b)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("set tags: %w", err)
	}

	return nil
}

func (p *Posix) RemoveTags(bucket, object string) error {
	return p.SetTags(bucket, object, nil)
}

const (
	iamMode = 0600
)

func (p *Posix) InitIAM() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	_, err := os.ReadFile(iamFile)
	if errors.Is(err, fs.ErrNotExist) {
		b, err := json.Marshal(auth.IAMConfig{AccessAccounts: map[string]auth.Account{}})
		if err != nil {
			return fmt.Errorf("marshal default iam: %w", err)
		}
		err = os.WriteFile(iamFile, b, iamMode)
		if err != nil {
			return fmt.Errorf("write default iam: %w", err)
		}
	}

	return nil
}

func (p *Posix) GetIAM() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.iamvalid || !p.iamexpire.After(time.Now()) {
		p.mu.RUnlock()
		err := p.refreshIAM()
		p.mu.RLock()
		if err != nil {
			return nil, err
		}
	}

	return p.iamcache, nil
}

const (
	backoff  = 100 * time.Millisecond
	maxretry = 300
)

func (p *Posix) refreshIAM() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// We are going to be racing with other running gateways without any
	// coordination. So we might find the file does not exist at times.
	// For this case we need to retry for a while assuming the other gateway
	// will eventually write the file. If it doesn't after the max retries,
	// then we will return the error.

	retries := 0

	for {
		b, err := os.ReadFile(iamFile)
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}
			return fmt.Errorf("read iam file: %w", err)
		}
		if err != nil {
			return err
		}

		p.iamcache = b
		p.iamvalid = true
		p.iamexpire = time.Now().Add(cacheDuration)
		break
	}

	return nil
}

func (p *Posix) StoreIAM(update auth.UpdateAcctFunc) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// We are going to be racing with other running gateways without any
	// coordination. So the strategy here is to read the current file data.
	// If the file doesn't exist, then we assume someone else is currently
	// updating the file. So we just need to keep retrying. We also need
	// to make sure the data is consistent within a single update. So racing
	// writes to a file would possibly leave this in some invalid state.
	// We can get atomic updates with rename. If we read the data, update
	// the data, write to a temp file, then rename the tempfile back to the
	// data file. This should always result in a complete data image.

	// There is at least one unsolved failure mode here.
	// If a gateway removes the data file and then crashes, all other
	// gateways will retry forever thinking that the original will eventually
	// write the file.

	retries := 0

	for {
		b, err := os.ReadFile(iamFile)
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}

			// we have been unsuccessful trying to read the iam file
			// so this must be the case where something happened and
			// the file did not get updated successfully, and probably
			// isn't going to be. The recovery procedure would be to
			// copy the backup file into place of the original.
			return fmt.Errorf("no iam file, needs backup recovery")
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read iam file: %w", err)
		}

		// reset retries on successful read
		retries = 0

		err = os.Remove(iamFile)
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			time.Sleep(backoff)
			continue
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove old iam file: %w", err)
		}

		// save copy of data
		datacopy := make([]byte, len(b))
		copy(datacopy, b)

		// make a backup copy in case we crash before update
		// this is after remove, so there is a small window something
		// can go wrong, but the remove should barrier other gateways
		// from trying to write backup at the same time. Only one
		// gateway will successfully remove the file.
		os.WriteFile(iamBackupFile, b, iamMode)

		b, err = update(b)
		if err != nil {
			// update failed, try to write old data back out
			os.WriteFile(iamFile, datacopy, iamMode)
			return fmt.Errorf("update iam data: %w", err)
		}

		err = writeTempFile(b)
		if err != nil {
			// update failed, try to write old data back out
			os.WriteFile(iamFile, datacopy, iamMode)
			return err
		}

		p.iamcache = b
		p.iamvalid = true
		p.iamexpire = time.Now().Add(cacheDuration)
		break
	}

	return nil
}

func writeTempFile(b []byte) error {
	f, err := os.CreateTemp(".", iamFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	err = os.Rename(f.Name(), iamFile)
	if err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

func isNoAttr(err error) bool {
	if err == nil {
		return false
	}
	xerr, ok := err.(*xattr.Error)
	if ok && xerr.Err == xattr.ENOATTR {
		return true
	}
	if err == syscall.ENODATA {
		return true
	}
	return false
}
