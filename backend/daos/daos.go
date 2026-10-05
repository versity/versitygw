// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

package daos

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const (
	tmpDirName      = ".sgwtmp"
	attrETag        = "etag"
	attrContentType = "content-type"
	attrMetadata    = "metadata"
	attrEncoding    = "content-encoding"
	attrLanguage    = "content-language"
	attrDisposition = "content-disposition"
	attrCacheCtl    = "cache-control"
	attrExpires     = "expires"
	emptyMD5        = "\"d41d8cd98f00b204e9800998ecf8427e\""
)

// Daos is the DAOS backend. The default build does not connect. Tests and
// the later cgo file supply an FS.
type Daos struct {
	backend.BackendUnsupported
	fs FS
}

var _ backend.Backend = &Daos{}

// NewWithFS builds a backend on an already-open seam. It does not call
// dfs_connect. The command-line constructor stays New.
func NewWithFS(fs FS) *Daos {
	return &Daos{fs: fs}
}

func (d *Daos) String() string {
	return "DAOS Gateway"
}

func (d *Daos) Shutdown() {}

func (d *Daos) NormalizeObjectKey(bucket, object string) string {
	fullPath := filepath.Join(bucket, object)
	key, err := filepath.Rel(filepath.Clean(bucket), fullPath)
	if err != nil {
		return filepath.ToSlash(fullPath)
	}
	if key == "." {
		return ""
	}
	return filepath.ToSlash(key)
}

func (d *Daos) GetBucketAcl(_ context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	if err := d.bucketExists(awsString(input.Bucket)); err != nil {
		return nil, err
	}
	return []byte{}, nil
}

func (d *Daos) GetBucketPolicy(_ context.Context, bucket string) ([]byte, error) {
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
}

func (d *Daos) GetObjectLockConfiguration(_ context.Context, bucket string) ([]byte, error) {
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
}

func (d *Daos) PutObject(_ context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	if backend.HasSSEC(po.SSECustomerAlgorithm, po.SSECustomerKey, po.SSECustomerKeyMD5) {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if po.IfMatch != nil || po.IfNoneMatch != nil || po.ChecksumAlgorithm != "" ||
		po.ObjectLockMode != "" || po.ObjectLockLegalHoldStatus != "" ||
		(po.ObjectLockRetainUntilDate != nil && !po.ObjectLockRetainUntilDate.IsZero()) {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	bucket := awsString(po.Bucket)
	key := awsString(po.Key)
	if key == "" {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err := d.bucketExists(bucket); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	body, err := readBody(po.Body)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if strings.HasSuffix(key, "/") {
		if len(body) != 0 {
			return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
		}
		return d.putDirectory(bucket, key)
	}
	return d.putFile(bucket, key, body, po)
}

func (d *Daos) GetObject(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	if backend.HasSSEC(input.SSECustomerAlgorithm, input.SSECustomerKey, input.SSECustomerKeyMD5) {
		return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if awsString(input.VersionId) != "" {
		return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, awsString(input.VersionId))
	}
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	info, obj, err := d.openLive(bucket, key, openRead)
	if err != nil {
		return nil, err
	}
	defer d.fs.Release(obj)
	etag, meta, ctype, err := d.attrs(obj)
	if err != nil {
		return nil, err
	}
	mod := time.Unix(info.Mtime, 0).UTC()
	if err := backend.EvaluatePreconditions(etag, mod, backend.PreConditions{
		IfMatch:       input.IfMatch,
		IfNoneMatch:   input.IfNoneMatch,
		IfModSince:    input.IfModifiedSince,
		IfUnmodeSince: input.IfUnmodifiedSince,
	}); err != nil {
		return nil, err
	}
	start, length, ranged, err := objectRange(input.Range, info.Size)
	if err != nil {
		return nil, err
	}
	buf := []byte{}
	if !info.IsDir && length > 0 {
		buf = make([]byte, length)
		n, err := d.fs.Read(obj, buf, start)
		if err != nil {
			return nil, err
		}
		buf = buf[:n]
	}
	n64 := int64(len(buf))
	out := &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(buf)),
		ContentLength: &n64,
		ETag:          &etag,
		ContentType:   &ctype,
		LastModified:  &mod,
		Metadata:      meta,
	}
	if ranged {
		cr := fmt.Sprintf("bytes %d-%d/%d", start, start+int64(len(buf))-1, info.Size)
		out.ContentRange = &cr
	}
	return out, nil
}

func (d *Daos) HeadObject(_ context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	if awsString(input.VersionId) != "" {
		return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, awsString(input.VersionId))
	}
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	info, obj, err := d.openLive(bucket, key, openRead)
	if err != nil {
		return nil, err
	}
	defer d.fs.Release(obj)
	etag, meta, ctype, err := d.attrs(obj)
	if err != nil {
		return nil, err
	}
	mod := time.Unix(info.Mtime, 0).UTC()
	if err := backend.EvaluatePreconditions(etag, mod, backend.PreConditions{
		IfMatch:       input.IfMatch,
		IfNoneMatch:   input.IfNoneMatch,
		IfModSince:    input.IfModifiedSince,
		IfUnmodeSince: input.IfUnmodifiedSince,
	}); err != nil {
		return nil, err
	}
	return &s3.HeadObjectOutput{
		ContentLength: &info.Size,
		ETag:          &etag,
		ContentType:   &ctype,
		LastModified:  &mod,
		Metadata:      meta,
	}, nil
}

func (d *Daos) DeleteObject(_ context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	if input.IfMatch != nil || input.IfMatchLastModifiedTime != nil || input.IfMatchSize != nil {
		return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if awsString(input.VersionId) != "" {
		return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, awsString(input.VersionId))
	}
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	if key == "" {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	if err := d.fs.Remove(objectPath(bucket, key), false); err != nil {
		return nil, d.mapKeyErr(err, key)
	}
	return &s3.DeleteObjectOutput{}, nil
}

func (d *Daos) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	if err := d.bucketExists(awsString(input.Bucket)); err != nil {
		return s3response.DeleteResult{}, err
	}
	var result s3response.DeleteResult
	for _, obj := range input.Delete.Objects {
		_, err := d.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                  input.Bucket,
			Key:                     obj.Key,
			VersionId:               obj.VersionId,
			IfMatch:                 obj.ETag,
			IfMatchLastModifiedTime: obj.LastModifiedTime,
			IfMatchSize:             obj.Size,
		})
		if err != nil {
			result.Error = append(result.Error, s3err.ObjectDeleteError(obj.Key, obj.VersionId, err))
			continue
		}
		result.Deleted = append(result.Deleted, types.DeletedObject{Key: obj.Key, VersionId: obj.VersionId})
	}
	return result, nil
}

func (d *Daos) putFile(bucket, key string, body []byte, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	sum := md5.Sum(body)
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""
	tmp := objectPath(bucket, tmpDirName+"/put-"+uuid.NewString())
	if err := d.mkdirParents(tmp); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	obj, err := d.fs.Open(tmp, openWrite|openCreate|openExcl)
	if err != nil {
		return s3response.PutObjectOutput{}, mapFS(err)
	}
	moved := false
	defer func() {
		d.fs.Release(obj)
		if !moved {
			d.fs.Remove(tmp, false)
		}
	}()
	if len(body) > 0 {
		if _, err := d.fs.Write(obj, body, 0); err != nil {
			return s3response.PutObjectOutput{}, mapFS(err)
		}
	}
	if err := d.storeAttrs(obj, etag, po, false); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	dst := objectPath(bucket, key)
	if err := d.mkdirParents(dst); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := d.fs.Move(tmp, dst); err != nil {
		return s3response.PutObjectOutput{}, mapFS(err)
	}
	moved = true
	return s3response.PutObjectOutput{ETag: etag}, nil
}

func (d *Daos) putDirectory(bucket, key string) (s3response.PutObjectOutput, error) {
	p := objectPath(bucket, key)
	if err := d.mkdirParents(p); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := d.fs.Mkdir(p); err != nil && !errors.Is(err, errExist) {
		return s3response.PutObjectOutput{}, mapFS(err)
	}
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return s3response.PutObjectOutput{}, mapFS(err)
	}
	defer d.fs.Release(obj)
	if err := d.fs.SetXattr(obj, attrETag, []byte(emptyMD5)); err != nil {
		return s3response.PutObjectOutput{}, mapFS(err)
	}
	if err := d.fs.SetXattr(obj, attrContentType, []byte(backend.DirContentType)); err != nil {
		return s3response.PutObjectOutput{}, mapFS(err)
	}
	return s3response.PutObjectOutput{ETag: emptyMD5}, nil
}

func (d *Daos) storeAttrs(obj Object, etag string, po s3response.PutObjectInput, dir bool) error {
	pairs := [][2]string{{attrETag, etag}}
	if dir {
		pairs = append(pairs, [2]string{attrContentType, backend.DirContentType})
	} else if awsString(po.ContentType) != "" {
		pairs = append(pairs, [2]string{attrContentType, awsString(po.ContentType)})
	}
	for _, pair := range []struct{ name, val string }{
		{attrEncoding, awsString(po.ContentEncoding)},
		{attrLanguage, awsString(po.ContentLanguage)},
		{attrDisposition, awsString(po.ContentDisposition)},
		{attrCacheCtl, awsString(po.CacheControl)},
		{attrExpires, awsString(po.Expires)},
	} {
		if pair.val != "" {
			pairs = append(pairs, [2]string{pair.name, pair.val})
		}
	}
	if len(po.Metadata) > 0 {
		raw, err := json.Marshal(po.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		if err := d.fs.SetXattr(obj, attrMetadata, raw); err != nil {
			return mapFS(err)
		}
	}
	for _, pair := range pairs {
		if err := d.fs.SetXattr(obj, pair[0], []byte(pair[1])); err != nil {
			return mapFS(err)
		}
	}
	return nil
}

func (d *Daos) attrs(obj Object) (string, map[string]string, string, error) {
	etagb, err := d.fs.GetXattr(obj, attrETag)
	if err != nil && !errors.Is(err, errNotExist) {
		return "", nil, "", mapFS(err)
	}
	ctype, err := d.fs.GetXattr(obj, attrContentType)
	if err != nil && !errors.Is(err, errNotExist) {
		return "", nil, "", mapFS(err)
	}
	var meta map[string]string
	raw, err := d.fs.GetXattr(obj, attrMetadata)
	if err != nil && !errors.Is(err, errNotExist) {
		return "", nil, "", mapFS(err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return "", nil, "", fmt.Errorf("parse metadata: %w", err)
		}
	}
	return string(etagb), meta, string(ctype), nil
}

func (d *Daos) openLive(bucket, key string, flags int) (Info, Object, error) {
	p := objectPath(bucket, key)
	info, err := d.fs.Stat(p)
	if err != nil {
		return Info{}, nil, d.mapKeyErr(err, key)
	}
	wantDir := strings.HasSuffix(key, "/")
	if wantDir != info.IsDir {
		return Info{}, nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	obj, err := d.fs.Open(p, flags)
	if err != nil {
		return Info{}, nil, d.mapKeyErr(err, key)
	}
	return info, obj, nil
}

func (d *Daos) bucketExists(bucket string) error {
	if bucket == "" || bucket == "." || bucket == ".." || strings.ContainsRune(bucket, '/') {
		return s3err.GetBucketErr(s3err.ErrInvalidBucketName, bucket)
	}
	info, err := d.fs.Stat(bucket)
	if errors.Is(err, errNotExist) || (err == nil && !info.IsDir) {
		return s3err.GetBucketErr(s3err.ErrNoSuchBucket, bucket)
	}
	if err != nil {
		return mapFS(err)
	}
	return nil
}

func (d *Daos) mkdirParents(p string) error {
	dir := pathDir(p)
	if dir == "" || dir == "." {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		if part == "" {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur += "/" + part
		}
		err := d.fs.Mkdir(cur)
		if err == nil || errors.Is(err, errExist) {
			continue
		}
		return mapFS(err)
	}
	return nil
}

func (d *Daos) mapKeyErr(err error, key string) error {
	if errors.Is(err, errNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if errors.Is(err, errNotEmpty) {
		return s3err.GetAPIError(s3err.ErrDirectoryNotEmpty)
	}
	if errors.Is(err, errNameLong) {
		return s3err.GetKeyTooLongErr(int64(len(key)), 1024)
	}
	if errors.Is(err, errNotDir) {
		return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}
	return mapFS(err)
}

func mapFS(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("dfs: %w", err)
}

func objectPath(bucket, key string) string {
	return bucket + "/" + strings.TrimPrefix(key, "/")
}

func pathDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}

func awsString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func readBody(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}

func objectRange(spec *string, size int64) (int64, int64, bool, error) {
	if spec == nil || *spec == "" {
		return 0, size, false, nil
	}
	raw := strings.TrimPrefix(*spec, "bytes=")
	startText, endText, ok := strings.Cut(raw, "-")
	if !ok {
		return 0, 0, false, s3err.GetAPIError(s3err.ErrInvalidRange)
	}
	var start, end int64
	if startText == "" {
		n, err := parseInt(endText)
		if err != nil || n <= 0 {
			return 0, 0, false, s3err.GetAPIError(s3err.ErrInvalidRange)
		}
		if n > size {
			n = size
		}
		return size - n, n, true, nil
	}
	var err error
	start, err = parseInt(startText)
	if err != nil || start < 0 || start >= size {
		return 0, 0, false, s3err.GetAPIError(s3err.ErrInvalidRange)
	}
	end = size - 1
	if endText != "" {
		end, err = parseInt(endText)
		if err != nil || end < start {
			return 0, 0, false, s3err.GetAPIError(s3err.ErrInvalidRange)
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end - start + 1, true, nil
}

func parseInt(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad int")
		}
		n = n*10 + int64(c-'0')
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}
