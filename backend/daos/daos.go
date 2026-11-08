// Copyright 2026 Versity Software
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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
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
	attrPacked      = "meta.v1"
	emptyMD5        = "\"d41d8cd98f00b204e9800998ecf8427e\""
)

// Daos is the DAOS backend. The default build does not connect. Tests and
// the later cgo file supply an FS.
type Daos struct {
	backend.BackendUnsupported
	fs FS
	// bucket defaults applied to new bucket directories; empty values
	// keep the library defaults.
	oclass    string
	chunkSize int64
}

var _ backend.Backend = &Daos{}

// NewWithFS builds a backend on an already-open seam. It does not call
// dfs_connect. The command-line constructor stays New.
func NewWithFS(fs FS) *Daos {
	return &Daos{fs: fs}
}

// SetBucketDefaults configures the object class and chunk size applied to
// bucket directories created after this call. Empty values change nothing.
func (d *Daos) SetBucketDefaults(oclass string, chunkSize int64) {
	d.oclass = oclass
	d.chunkSize = chunkSize
}

func (d *Daos) String() string {
	return "DAOS Gateway"
}

func (d *Daos) Shutdown() {
	if d.fs == nil {
		return
	}
	_ = d.fs.Close()
}

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
	raw, err := d.getBucketBytes(awsString(input.Bucket), attrACL)
	if errors.Is(err, errNotExist) {
		return []byte{}, nil
	}
	return raw, err
}

func (d *Daos) GetBucketPolicy(_ context.Context, bucket string) ([]byte, error) {
	raw, err := d.getBucketBytes(bucket, attrPolicy)
	if errors.Is(err, errNotExist) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
	}
	return raw, err
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
	if po.IfMatch != nil || po.IfNoneMatch != nil ||
		po.ObjectLockMode != "" || po.ObjectLockLegalHoldStatus != "" ||
		(po.ObjectLockRetainUntilDate != nil && !po.ObjectLockRetainUntilDate.IsZero()) {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	bucket := awsString(po.Bucket)
	key := awsString(po.Key)
	if key == "" {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err := reservedKey(key); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := d.bucketExists(bucket); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if strings.HasSuffix(key, "/") {
		if err := emptyBody(po.Body); err != nil {
			return s3response.PutObjectOutput{}, err
		}
		return d.putDirectory(bucket, key, po)
	}
	return d.putFile(bucket, key, po.Body, po)
}

// emptyBody reports whether the body carries no bytes. A nil body is
// empty. A directory object must not carry data, so one byte is enough
// to reject it; the caller never consumes the stream in that case.
// Read errors other than EOF fail the request: a truncated body must
// not publish a directory object.
func emptyBody(r io.Reader) error {
	if r == nil {
		return nil
	}
	var probe [1]byte
	for {
		n, err := r.Read(probe[:])
		if n > 0 {
			return s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
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
	if err := validBucketName(bucket); err != nil {
		return nil, err
	}
	info, obj, err := d.openLive(bucket, key, openRead)
	if err != nil {
		return nil, err
	}
	etag, meta, headers, err := d.attrs(obj)
	if err != nil {
		d.fs.Release(obj)
		return nil, err
	}
	mod := time.Unix(info.Mtime, 0).UTC()
	if err := backend.EvaluatePreconditions(etag, mod, backend.PreConditions{
		IfMatch:       input.IfMatch,
		IfNoneMatch:   input.IfNoneMatch,
		IfModSince:    input.IfModifiedSince,
		IfUnmodeSince: input.IfUnmodifiedSince,
	}); err != nil {
		d.fs.Release(obj)
		return nil, err
	}
	start, length, ranged, err := objectRange(input.Range, info.Size)
	if err != nil {
		d.fs.Release(obj)
		return nil, err
	}
	body := io.ReadCloser(&dfsBodyReader{fs: d.fs, obj: obj, rem: length, off: start})
	if info.IsDir {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	ch, err := d.loadChecksums(obj)
	if err != nil {
		d.fs.Release(obj)
		return nil, err
	}
	if info.IsDir {
		d.fs.Release(obj)
	}
	n64 := length
	out := &s3.GetObjectOutput{
		Body:                    body,
		ContentLength:           &n64,
		ETag:                    &etag,
		ContentType:             strPtr(headers.ctype),
		ContentEncoding:         strPtr(headers.encoding),
		ContentLanguage:         strPtr(headers.language),
		ContentDisposition:      strPtr(headers.disposition),
		CacheControl:            strPtr(headers.cache),
		ExpiresString:           strPtr(headers.expires),
		LastModified:            &mod,
		Metadata:                meta,
		WebsiteRedirectLocation: strPtr(headers.redirect),
	}
	if ranged {
		cr := fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, info.Size)
		out.ContentRange = &cr
	}
	fillGetChecksum(out, ch)
	return out, nil
}

// dfsBodyReader streams object bytes from an open handle and releases the
// handle when the response body closes. A zero read while bytes are still
// owed latches ErrUnexpectedEOF, the same condition readFull detects.
type dfsBodyReader struct {
	fs  FS
	obj Object
	off int64
	rem int64
	err error
}

func (r *dfsBodyReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.rem <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.rem {
		p = p[:r.rem]
	}
	n, err := r.fs.Read(r.obj, p, r.off)
	if n > 0 {
		r.off += int64(n)
		r.rem -= int64(n)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		r.err = err
		return n, err
	}
	if n == 0 && r.rem > 0 {
		r.err = io.ErrUnexpectedEOF
		return 0, r.err
	}
	if r.rem == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (r *dfsBodyReader) Close() error {
	return r.fs.Release(r.obj)
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
	etag, meta, headers, err := d.attrs(obj)
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
	out := &s3.HeadObjectOutput{
		ContentLength:           &info.Size,
		ETag:                    &etag,
		ContentType:             strPtr(headers.ctype),
		ContentEncoding:         strPtr(headers.encoding),
		ContentLanguage:         strPtr(headers.language),
		ContentDisposition:      strPtr(headers.disposition),
		CacheControl:            strPtr(headers.cache),
		ExpiresString:           strPtr(headers.expires),
		LastModified:            &mod,
		Metadata:                meta,
		WebsiteRedirectLocation: strPtr(headers.redirect),
	}
	if ch, err := d.loadChecksums(obj); err != nil {
		return nil, err
	} else {
		fillHeadChecksum(out, ch)
	}
	return out, nil
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
	info, err := d.fs.Stat(objectPath(bucket, key))
	if errors.Is(err, errNotExist) {
		return &s3.DeleteObjectOutput{}, nil
	}
	if err != nil {
		return nil, d.mapKeyErr(err, key)
	}
	if strings.HasSuffix(key, "/") != info.IsDir {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err := d.fs.Remove(objectPath(bucket, key), false); err != nil {
		if errors.Is(err, errNotExist) {
			return &s3.DeleteObjectOutput{}, nil
		}
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

func (d *Daos) putFile(bucket, key string, body io.Reader, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
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
	sink, err := newChecksumSink(po)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if body == nil {
		body = bytes.NewReader(nil)
	}
	wrapped := io.TeeReader(body, sink)
	sum, _, err := d.writeBody(obj, wrapped, nil)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""
	if err := d.storeAttrs(obj, etag, po, false); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := d.storeTagHeader(obj, po.Tagging); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	out := s3response.PutObjectOutput{ETag: etag}
	if ch, ok, err := sink.checksum(po); err != nil {
		return s3response.PutObjectOutput{}, err
	} else if ok {
		if err := d.storeChecksums(obj, ch); err != nil {
			return s3response.PutObjectOutput{}, err
		}
		fillPutChecksum(&out, ch)
	}
	dst := objectPath(bucket, key)
	if err := d.mkdirParents(dst); err != nil {
		return s3response.PutObjectOutput{}, d.mapKeyErr(err, key)
	}
	if err := d.fs.Move(tmp, dst); err != nil {
		return s3response.PutObjectOutput{}, d.mapKeyErr(err, key)
	}
	moved = true
	return out, nil
}

func (d *Daos) putDirectory(bucket, key string, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	ch, ok, err := checksumForPut(po, nil)
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}
	p := objectPath(bucket, key)
	if err := d.mkdirParents(p); err != nil {
		return s3response.PutObjectOutput{}, d.mapKeyErr(err, key)
	}
	if err := d.fs.Mkdir(p); err != nil && !errors.Is(err, errExist) {
		return s3response.PutObjectOutput{}, d.mapKeyErr(err, key)
	}
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return s3response.PutObjectOutput{}, d.mapKeyErr(err, key)
	}
	defer d.fs.Release(obj)
	if err := d.storeAttrs(obj, emptyMD5, po, true); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	if err := d.storeTagHeader(obj, po.Tagging); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	out := s3response.PutObjectOutput{ETag: emptyMD5}
	if ok {
		if err := d.storeChecksums(obj, ch); err != nil {
			return s3response.PutObjectOutput{}, err
		}
		fillPutChecksum(&out, ch)
	}
	return out, nil
}

func (d *Daos) storeAttrs(obj Object, etag string, po s3response.PutObjectInput, dir bool) error {
	packed := attrMap{attrETag: etag}
	if dir {
		packed[attrContentType] = backend.DirContentType
	} else if awsString(po.ContentType) != "" {
		packed[attrContentType] = awsString(po.ContentType)
	}
	for _, pair := range []struct{ name, val string }{
		{attrEncoding, awsString(po.ContentEncoding)},
		{attrLanguage, awsString(po.ContentLanguage)},
		{attrDisposition, awsString(po.ContentDisposition)},
		{attrCacheCtl, awsString(po.CacheControl)},
		{attrExpires, awsString(po.Expires)},
		{attrRedirect, awsString(po.WebsiteRedirectLocation)},
	} {
		if dir || pair.val != "" {
			packed[pair.name] = pair.val
		}
	}
	if dir || len(po.Metadata) > 0 {
		meta := po.Metadata
		if meta == nil {
			meta = map[string]string{}
		}
		raw, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		packed[attrMetadata] = string(raw)
	}
	raw, err := marshalAttrs(packed)
	if err != nil {
		return err
	}
	return mapFS(d.fs.SetXattr(obj, attrPacked, raw))
}

// attrMap is the nine object attributes, packed into one xattr.
type attrMap map[string]string

func marshalAttrs(m attrMap) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(1)
	if len(m) > 255 {
		return nil, fmt.Errorf("too many attributes")
	}
	buf.WriteByte(byte(len(m)))
	for _, name := range sortedAttrNames(m) {
		val := m[name]
		if len(name) > 0xFFFF || len(val) > 0xFFFFFFFF {
			return nil, fmt.Errorf("attribute too large")
		}
		var hdr [6]byte
		binary.BigEndian.PutUint16(hdr[:2], uint16(len(name)))
		binary.BigEndian.PutUint32(hdr[2:], uint32(len(val)))
		buf.Write(hdr[:])
		buf.WriteString(name)
		buf.WriteString(val)
	}
	return buf.Bytes(), nil
}

func unmarshalAttrs(raw []byte) (attrMap, error) {
	m := attrMap{}
	if len(raw) < 2 {
		return nil, fmt.Errorf("short packed attributes")
	}
	if raw[0] != 1 {
		return nil, fmt.Errorf("unknown packed attributes version %d", raw[0])
	}
	count := int(raw[1])
	pos := 2
	for i := 0; i < count; i++ {
		if pos+6 > len(raw) {
			return nil, fmt.Errorf("truncated packed attributes")
		}
		nameLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		valLen := int(binary.BigEndian.Uint32(raw[pos+2 : pos+6]))
		pos += 6
		if pos+nameLen+valLen > len(raw) {
			return nil, fmt.Errorf("truncated packed attributes")
		}
		m[string(raw[pos:pos+nameLen])] = string(raw[pos+nameLen : pos+nameLen+valLen])
		pos += nameLen + valLen
	}
	return m, nil
}

func sortedAttrNames(m attrMap) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type objHeaders struct {
	ctype, encoding, language, disposition, cache, expires, redirect string
}

func (d *Daos) attrs(obj Object) (string, map[string]string, objHeaders, error) {
	var headers objHeaders
	m, err := d.loadAttrs(obj)
	if err != nil {
		return "", nil, headers, err
	}
	var meta map[string]string
	if raw, ok := m[attrMetadata]; ok && len(raw) > 0 {
		if err := json.Unmarshal([]byte(raw), &meta); err != nil {
			return "", nil, headers, fmt.Errorf("parse metadata: %w", err)
		}
	}
	headers.ctype = m[attrContentType]
	headers.encoding = m[attrEncoding]
	headers.language = m[attrLanguage]
	headers.disposition = m[attrDisposition]
	headers.cache = m[attrCacheCtl]
	headers.expires = m[attrExpires]
	headers.redirect = m[attrRedirect]
	return m[attrETag], meta, headers, nil
}

// loadAttrs reads the packed attribute blob, falling back to the
// per-attribute xattrs written before the packed format existed.
func (d *Daos) loadAttrs(obj Object) (attrMap, error) {
	raw, err := d.fs.GetXattr(obj, attrPacked)
	if err == nil {
		return unmarshalAttrs(raw)
	}
	if !errors.Is(err, errNotExist) {
		return nil, mapFS(err)
	}
	m := attrMap{}
	for _, name := range attrNames {
		b, gerr := d.fs.GetXattr(obj, name)
		if gerr != nil && !errors.Is(gerr, errNotExist) {
			return nil, mapFS(gerr)
		}
		if len(b) > 0 {
			m[name] = string(b)
		}
	}
	return m, nil
}

var attrNames = []string{
	attrETag,
	attrContentType,
	attrEncoding,
	attrLanguage,
	attrDisposition,
	attrCacheCtl,
	attrExpires,
	attrRedirect,
	attrMetadata,
}

func strPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func (d *Daos) openLive(bucket, key string, flags int) (Info, Object, error) {
	p := objectPath(bucket, key)
	obj, err := d.fs.Open(p, flags)
	if err != nil {
		return Info{}, nil, d.mapOpenErr(err, bucket, key)
	}
	info, err := d.fs.StatObj(obj)
	if err != nil {
		d.fs.Release(obj)
		return Info{}, nil, mapFS(err)
	}
	wantDir := strings.HasSuffix(key, "/")
	if wantDir != info.IsDir {
		d.fs.Release(obj)
		return Info{}, nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	return info, obj, nil
}

// mapOpenErr classifies an open failure: a missing or non-directory
// bucket is NoSuchBucket; with the bucket present, errNotExist is
// NoSuchKey and errNotDir keeps mapKeyErr's parent-is-file mapping.
func (d *Daos) mapOpenErr(err error, bucket, key string) error {
	if !errors.Is(err, errNotExist) && !errors.Is(err, errNotDir) {
		return d.mapKeyErr(err, key)
	}
	if berr := validBucketName(bucket); berr != nil {
		return berr
	}
	binfo, serr := d.fs.Stat(bucket)
	if serr != nil || !binfo.IsDir {
		return s3err.GetBucketErr(s3err.ErrNoSuchBucket, bucket)
	}
	return d.mapKeyErr(err, key)
}

func (d *Daos) bucketExists(bucket string) error {
	if err := validBucketName(bucket); err != nil {
		return err
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
	var open []Object
	defer func() {
		for _, obj := range open {
			d.fs.Release(obj)
		}
	}()
	// Parents are opened for write: dfs_mkdir updates the parent
	// directory, and a read-only handle rejects the update server-side.
	cur, err := d.fs.Open("", openWrite)
	if err != nil {
		return mapFS(err)
	}
	open = append(open, cur)
	for _, part := range strings.Split(clean(dir), "/") {
		if part == "" {
			continue
		}
		next, oerr := d.fs.OpenRel(cur, part, openWrite)
		if errors.Is(oerr, errNotExist) {
			if mkerr := d.fs.MkdirRel(cur, part); mkerr != nil && !errors.Is(mkerr, errExist) {
				return mapFS(mkerr)
			}
			next, oerr = d.fs.OpenRel(cur, part, openWrite)
		}
		if oerr != nil {
			return mapFS(oerr)
		}
		open = append(open, next)
		info, serr := d.fs.StatObj(next)
		if serr != nil {
			return mapFS(serr)
		}
		if !info.IsDir {
			return errNotDir
		}
		cur = next
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
	var long componentTooLong
	if errors.As(err, &long) {
		return s3err.GetKeyTooLongErr(long.size, long.max)
	}
	if errors.Is(err, errFileOverDir) {
		return s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)
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

func readFull(fs FS, obj Object, buf []byte, off int64) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := fs.Read(obj, buf[total:], off+int64(total))
		if n > 0 {
			total += n
		}
		if err != nil {
			if errors.Is(err, io.EOF) && total == len(buf) {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrUnexpectedEOF
		}
	}
	return total, nil
}

func writeFull(fs FS, obj Object, buf []byte, off int64) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := fs.Write(obj, buf[total:], off+int64(total))
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func objectPath(bucket, key string) string {
	return bucket + "/" + strings.TrimPrefix(key, "/")
}

func reservedKey(key string) error {
	for _, part := range strings.Split(clean(key), "/") {
		if part == tmpDirName {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
	}
	return nil
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
	if size == 0 {
		return 0, 0, false, s3err.GetAPIError(s3err.ErrInvalidRange)
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
