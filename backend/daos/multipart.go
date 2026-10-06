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
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
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
	mpDirName        = tmpDirName + "/multipart"
	attrObjName      = "objname"
	inProgressSuffix = ".inprogress"
	maxPartNumber    = 10000
)

func (d *Daos) CreateMultipartUpload(_ context.Context, input s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	var out s3response.InitiateMultipartUploadResult
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	if err := d.bucketExists(bucket); err != nil {
		return out, err
	}
	if key == "" {
		return out, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if strings.HasSuffix(key, "/") {
		return out, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
	}
	if unsupportedCreate(input) {
		return out, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	uploadID := uuid.NewString()
	uploadDir := path.Join(mpHashDir(bucket, key), uploadID)
	if err := d.mkdirParents(uploadDir); err != nil {
		return out, err
	}
	if err := d.fs.Mkdir(uploadDir); err != nil {
		return out, mapFS(err)
	}
	if err := d.setXattr(path.Dir(uploadDir), attrObjName, []byte(key)); err != nil {
		_ = d.fs.Remove(uploadDir, true)
		return out, err
	}
	obj, err := d.fs.Open(uploadDir, openRead)
	if err != nil {
		_ = d.fs.Remove(uploadDir, true)
		return out, mapFS(err)
	}
	err = d.storeAttrs(obj, "", putInputFromCreate(input), false)
	d.fs.Release(obj)
	if err != nil {
		_ = d.fs.Remove(uploadDir, true)
		return out, err
	}
	return s3response.InitiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}, nil
}

func (d *Daos) UploadPart(_ context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	uploadID := awsString(input.UploadId)
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	if strings.HasSuffix(key, "/") {
		return nil, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
	}
	if err := validUploadID(uploadID); err != nil {
		return nil, err
	}
	if input.PartNumber == nil || *input.PartNumber < 1 || *input.PartNumber > maxPartNumber {
		return nil, s3err.GetAPIError(s3err.ErrInvalidPartNumberRange)
	}
	if backend.HasSSEC(input.SSECustomerAlgorithm, input.SSECustomerKey, input.SSECustomerKeyMD5) || input.ChecksumAlgorithm != "" {
		return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	uploadDir := path.Join(mpHashDir(bucket, key), uploadID)
	if _, err := d.fs.Stat(uploadDir); err != nil {
		if errors.Is(err, errNotExist) {
			return nil, s3err.GetNoSuchUploadErr(uploadID)
		}
		return nil, mapFS(err)
	}
	tmp := path.Join(uploadDir, ".part-"+uuid.NewString())
	obj, err := d.fs.Open(tmp, openWrite|openCreate|openExcl)
	if err != nil {
		return nil, mapFS(err)
	}
	moved := false
	defer func() {
		d.fs.Release(obj)
		if !moved {
			_ = d.fs.Remove(tmp, false)
		}
	}()
	sum, n, err := d.writeBody(obj, input.Body, input.ContentLength)
	if err != nil {
		return nil, err
	}
	etag := "\"" + hex.EncodeToString(sum) + "\""
	if err := d.fs.SetXattr(obj, attrETag, []byte(etag)); err != nil {
		return nil, mapFS(err)
	}
	_ = n
	partPath := path.Join(uploadDir, strconv.FormatInt(int64(*input.PartNumber), 10))
	if err := d.fs.Move(tmp, partPath); err != nil {
		return nil, mapFS(err)
	}
	moved = true
	return &s3.UploadPartOutput{ETag: &etag}, nil
}

func (d *Daos) CompleteMultipartUpload(_ context.Context, input *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	var out s3response.CompleteMultipartUploadResult
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	uploadID := awsString(input.UploadId)
	if err := d.bucketExists(bucket); err != nil {
		return out, "", err
	}
	if key == "" || strings.HasSuffix(key, "/") {
		return out, "", s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err := validUploadID(uploadID); err != nil {
		return out, "", err
	}
	if unsupportedComplete(input) {
		return out, "", s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if input.MultipartUpload == nil || len(input.MultipartUpload.Parts) == 0 {
		return out, "", s3err.GetAPIError(s3err.ErrMalformedXML)
	}
	parts := input.MultipartUpload.Parts
	etag, err := backend.ComputeMultipartETagFromPartETags(parts)
	if err != nil {
		return out, "", err
	}
	if err := partOrder(parts); err != nil {
		return out, "", err
	}
	hashDir := mpHashDir(bucket, key)
	uploadDir := path.Join(hashDir, uploadID)
	claim := path.Join(hashDir, uploadID+"."+strings.Trim(etag, `"`)+inProgressSuffix)
	if _, err := d.fs.Stat(uploadDir); err == nil {
		if err := d.verifyParts(uploadDir, uploadID, parts); err != nil {
			return out, "", err
		}
		if err := d.fs.Move(uploadDir, claim); err != nil {
			if _, statErr := d.fs.Stat(claim); statErr != nil {
				return out, "", s3err.GetNoSuchUploadErr(uploadID)
			}
		}
	} else if !errors.Is(err, errNotExist) {
		return out, "", mapFS(err)
	} else if _, statErr := d.fs.Stat(claim); statErr != nil {
		return out, "", s3err.GetNoSuchUploadErr(uploadID)
	} else if err := d.verifyParts(claim, uploadID, parts); err != nil {
		return out, "", err
	}
	tmp := objectPath(bucket, tmpDirName+"/put-"+uuid.NewString())
	if err := d.mkdirParents(tmp); err != nil {
		return out, "", err
	}
	obj, err := d.fs.Open(tmp, openWrite|openCreate|openExcl)
	if err != nil {
		return out, "", mapFS(err)
	}
	published := false
	defer func() {
		d.fs.Release(obj)
		if !published {
			_ = d.fs.Remove(tmp, false)
		}
	}()
	if err := d.copyParts(obj, claim, parts); err != nil {
		return out, "", err
	}
	po, err := d.loadUserAttrs(claim)
	if err != nil {
		return out, "", err
	}
	if err := d.storeAttrs(obj, etag, po, false); err != nil {
		return out, "", err
	}
	if _, err := d.fs.Stat(claim); err != nil {
		return out, "", s3err.GetNoSuchUploadErr(uploadID)
	}
	dst := objectPath(bucket, key)
	if err := d.mkdirParents(dst); err != nil {
		return out, "", d.mapKeyErr(err, key)
	}
	if err := d.fs.Move(tmp, dst); err != nil {
		return out, "", d.mapKeyErr(err, key)
	}
	published = true
	_ = d.fs.Remove(claim, true)
	return s3response.CompleteMultipartUploadResult{
		Bucket: &bucket,
		Key:    &key,
		ETag:   &etag,
	}, "", nil
}

func (d *Daos) AbortMultipartUpload(_ context.Context, input *s3.AbortMultipartUploadInput) error {
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	uploadID := awsString(input.UploadId)
	if err := d.bucketExists(bucket); err != nil {
		return err
	}
	if err := validUploadID(uploadID); err != nil {
		return err
	}
	hashDir := mpHashDir(bucket, key)
	removed := false
	if err := d.fs.Remove(path.Join(hashDir, uploadID), true); err == nil {
		removed = true
	} else if !errors.Is(err, errNotExist) {
		return mapFS(err)
	}
	ents, err := d.fs.ReadDir(hashDir)
	if errors.Is(err, errNotExist) {
		if removed {
			return nil
		}
		return s3err.GetNoSuchUploadErr(uploadID)
	}
	if err != nil {
		return mapFS(err)
	}
	prefix := uploadID + "."
	for _, ent := range ents {
		if ent.IsDir && strings.HasPrefix(ent.Name, prefix) && strings.HasSuffix(ent.Name, inProgressSuffix) {
			if err := d.fs.Remove(path.Join(hashDir, ent.Name), true); err != nil && !errors.Is(err, errNotExist) {
				return mapFS(err)
			}
			removed = true
		}
	}
	if !removed {
		return s3err.GetNoSuchUploadErr(uploadID)
	}
	return nil
}

func (d *Daos) ListParts(_ context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	var out s3response.ListPartsResult
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	uploadID := awsString(input.UploadId)
	if err := d.bucketExists(bucket); err != nil {
		return out, err
	}
	if err := validUploadID(uploadID); err != nil {
		return out, err
	}
	dir, err := d.uploadDir(bucket, key, uploadID)
	if err != nil {
		return out, err
	}
	marker := 0
	if awsString(input.PartNumberMarker) != "" {
		marker, err = strconv.Atoi(*input.PartNumberMarker)
		if err != nil {
			return out, s3err.GetInvalidArgMaxLimiter("part-number-marker", *input.PartNumberMarker)
		}
	}
	maxParts := 1000
	if input.MaxParts != nil {
		maxParts = int(*input.MaxParts)
	}
	ents, err := d.fs.ReadDir(dir)
	if err != nil {
		return out, mapFS(err)
	}
	var parts []s3response.Part
	for _, ent := range ents {
		if ent.IsDir {
			continue
		}
		pn, err := strconv.Atoi(ent.Name)
		if err != nil || pn <= marker {
			continue
		}
		etagb, err := d.xattr(path.Join(dir, ent.Name), attrETag)
		if err != nil && !errors.Is(err, errNotExist) {
			return out, mapFS(err)
		}
		parts = append(parts, s3response.Part{
			PartNumber:   pn,
			ETag:         string(etagb),
			Size:         ent.Size,
			LastModified: time.Unix(ent.Mtime, 0).UTC(),
		})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
	truncated := false
	if maxParts > 0 && len(parts) > maxParts {
		parts = parts[:maxParts]
		truncated = true
	}
	next := 0
	if len(parts) > 0 {
		next = parts[len(parts)-1].PartNumber
	}
	return s3response.ListPartsResult{
		Bucket:               bucket,
		Key:                  key,
		UploadID:             uploadID,
		PartNumberMarker:     marker,
		NextPartNumberMarker: next,
		MaxParts:             maxParts,
		IsTruncated:          truncated,
		Parts:                parts,
		StorageClass:         types.StorageClassStandard,
	}, nil
}

func (d *Daos) ListMultipartUploads(_ context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	var out s3response.ListMultipartUploadsResult
	bucket := awsString(input.Bucket)
	if err := d.bucketExists(bucket); err != nil {
		return out, err
	}
	prefix := awsString(input.Prefix)
	delimiter := awsString(input.Delimiter)
	keyMarker := awsString(input.KeyMarker)
	uploadMarker := awsString(input.UploadIdMarker)
	maxUploads := 1000
	if input.MaxUploads != nil {
		maxUploads = int(*input.MaxUploads)
	}
	ents, err := d.fs.ReadDir(objectPath(bucket, mpDirName))
	if err != nil && !errors.Is(err, errNotExist) {
		return out, mapFS(err)
	}
	var uploads []s3response.Upload
	for _, ent := range ents {
		if !ent.IsDir {
			continue
		}
		hashDir := objectPath(bucket, mpDirName+"/"+ent.Name)
		nameb, err := d.xattr(hashDir, attrObjName)
		if err != nil {
			continue
		}
		objectName := string(nameb)
		if prefix != "" && !strings.HasPrefix(objectName, prefix) {
			continue
		}
		if keyMarker != "" && uploadMarker == "" && objectName <= keyMarker {
			continue
		}
		if keyMarker != "" && uploadMarker != "" && objectName < keyMarker {
			continue
		}
		kids, err := d.fs.ReadDir(hashDir)
		if err != nil {
			continue
		}
		for _, kid := range kids {
			if !kid.IsDir || strings.HasSuffix(kid.Name, inProgressSuffix) {
				continue
			}
			uploads = append(uploads, s3response.Upload{
				Key:          objectName,
				UploadID:     kid.Name,
				StorageClass: types.StorageClassStandard,
				Initiated:    time.Unix(kid.Mtime, 0).UTC(),
			})
		}
	}
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key != uploads[j].Key {
			return uploads[i].Key < uploads[j].Key
		}
		if !uploads[i].Initiated.Equal(uploads[j].Initiated) {
			return uploads[i].Initiated.Before(uploads[j].Initiated)
		}
		return uploads[i].UploadID < uploads[j].UploadID
	})
	page, err := backend.ListMultipartUploads(uploads, prefix, delimiter, keyMarker, uploadMarker, maxUploads)
	if err != nil {
		return out, err
	}
	return s3response.ListMultipartUploadsResult{
		Bucket:             bucket,
		Prefix:             prefix,
		Delimiter:          delimiter,
		KeyMarker:          keyMarker,
		UploadIDMarker:     uploadMarker,
		NextKeyMarker:      page.NextKeyMarker,
		NextUploadIDMarker: page.NextUploadIDMarker,
		MaxUploads:         maxUploads,
		IsTruncated:        page.IsTruncated,
		Uploads:            page.Uploads,
		CommonPrefixes:     page.CommonPrefixes,
	}, nil
}

func (d *Daos) copyParts(dst Object, dir string, parts []types.CompletedPart) error {
	var destOff int64
	buf := make([]byte, 32*1024)
	for _, part := range parts {
		pp := path.Join(dir, strconv.FormatInt(int64(*part.PartNumber), 10))
		info, err := d.fs.Stat(pp)
		if err != nil {
			return mapFS(err)
		}
		src, err := d.fs.Open(pp, openRead)
		if err != nil {
			return mapFS(err)
		}
		var srcOff int64
		for srcOff < info.Size {
			n, err := d.fs.Read(src, buf, srcOff)
			if n > 0 {
				if _, werr := d.fs.Write(dst, buf[:n], destOff); werr != nil {
					d.fs.Release(src)
					return mapFS(werr)
				}
				srcOff += int64(n)
				destOff += int64(n)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				d.fs.Release(src)
				return mapFS(err)
			}
			if n == 0 {
				break
			}
		}
		d.fs.Release(src)
		if srcOff != info.Size {
			return fmt.Errorf("short part copy: %d of %d", srcOff, info.Size)
		}
	}
	return nil
}

func (d *Daos) verifyParts(dir, uploadID string, parts []types.CompletedPart) error {
	for _, part := range parts {
		if partHasChecksum(part) {
			return s3err.GetAPIError(s3err.ErrNotImplemented)
		}
		pp := path.Join(dir, strconv.FormatInt(int64(*part.PartNumber), 10))
		got, err := d.xattr(pp, attrETag)
		if errors.Is(err, errNotExist) {
			return s3err.GetInvalidPartErr(uploadID, *part.PartNumber, awsString(part.ETag))
		}
		if err != nil {
			return mapFS(err)
		}
		if !backend.AreEtagsSame(string(got), awsString(part.ETag)) {
			return s3err.GetInvalidPartErr(uploadID, *part.PartNumber, awsString(part.ETag))
		}
	}
	return nil
}

func (d *Daos) uploadDir(bucket, key, uploadID string) (string, error) {
	hashDir := mpHashDir(bucket, key)
	dir := path.Join(hashDir, uploadID)
	if _, err := d.fs.Stat(dir); err == nil {
		return dir, nil
	} else if !errors.Is(err, errNotExist) {
		return "", mapFS(err)
	}
	ents, err := d.fs.ReadDir(hashDir)
	if errors.Is(err, errNotExist) {
		return "", s3err.GetNoSuchUploadErr(uploadID)
	}
	if err != nil {
		return "", mapFS(err)
	}
	prefix := uploadID + "."
	for _, ent := range ents {
		if ent.IsDir && strings.HasPrefix(ent.Name, prefix) && strings.HasSuffix(ent.Name, inProgressSuffix) {
			return path.Join(hashDir, ent.Name), nil
		}
	}
	return "", s3err.GetNoSuchUploadErr(uploadID)
}

func (d *Daos) writeBody(obj Object, r io.Reader, length *int64) ([]byte, int64, error) {
	if r == nil {
		sum := md5.Sum(nil)
		return sum[:], 0, nil
	}
	h := md5.New()
	buf := make([]byte, 32*1024)
	var off int64
	want := int64(-1)
	if length != nil {
		want = *length
	}
	for want < 0 || off < want {
		chunk := buf
		if want >= 0 && int64(len(chunk)) > want-off {
			chunk = chunk[:want-off]
		}
		n, err := r.Read(chunk)
		if n > 0 {
			if _, werr := h.Write(chunk[:n]); werr != nil {
				return nil, off, werr
			}
			if _, werr := d.fs.Write(obj, chunk[:n], off); werr != nil {
				return nil, off, mapFS(werr)
			}
			off += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, off, err
		}
		if n == 0 {
			break
		}
	}
	if want >= 0 && off != want {
		return nil, off, io.ErrUnexpectedEOF
	}
	return h.Sum(nil), off, nil
}

func (d *Daos) loadUserAttrs(p string) (s3response.PutObjectInput, error) {
	var po s3response.PutObjectInput
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return po, mapFS(err)
	}
	defer d.fs.Release(obj)
	po.ContentType = optionalString(d.fs, obj, attrContentType)
	po.ContentEncoding = optionalString(d.fs, obj, attrEncoding)
	po.ContentLanguage = optionalString(d.fs, obj, attrLanguage)
	po.ContentDisposition = optionalString(d.fs, obj, attrDisposition)
	po.CacheControl = optionalString(d.fs, obj, attrCacheCtl)
	po.Expires = optionalString(d.fs, obj, attrExpires)
	raw, err := d.fs.GetXattr(obj, attrMetadata)
	if err != nil && !errors.Is(err, errNotExist) {
		return po, mapFS(err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &po.Metadata); err != nil {
			return po, fmt.Errorf("parse metadata: %w", err)
		}
	}
	return po, nil
}

func (d *Daos) setXattr(p, name string, value []byte) error {
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return mapFS(err)
	}
	defer d.fs.Release(obj)
	return mapFS(d.fs.SetXattr(obj, name, value))
}

func (d *Daos) xattr(p, name string) ([]byte, error) {
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return nil, err
	}
	defer d.fs.Release(obj)
	return d.fs.GetXattr(obj, name)
}

func mpHashDir(bucket, key string) string {
	sum := sha256.Sum256([]byte(key))
	return objectPath(bucket, mpDirName+"/"+hex.EncodeToString(sum[:]))
}

func validUploadID(uploadID string) error {
	id, err := uuid.Parse(uploadID)
	if err != nil || id.String() != uploadID {
		return s3err.GetNoSuchUploadErr(uploadID)
	}
	return nil
}

func partOrder(parts []types.CompletedPart) error {
	var prev int32
	for i, part := range parts {
		if part.PartNumber == nil || *part.PartNumber < 1 || *part.PartNumber > maxPartNumber {
			return s3err.GetAPIError(s3err.ErrInvalidPartNumberRange)
		}
		if i > 0 && *part.PartNumber <= prev {
			return s3err.GetAPIError(s3err.ErrInvalidPartOrder)
		}
		prev = *part.PartNumber
	}
	return nil
}

func unsupportedCreate(in s3response.CreateMultipartUploadInput) bool {
	if backend.HasSSEC(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5) {
		return true
	}
	if in.ChecksumAlgorithm != "" || in.ChecksumType != "" || in.ObjectLockMode != "" || in.ObjectLockLegalHoldStatus != "" || lockDateSet(in.ObjectLockRetainUntilDate) {
		return true
	}
	if in.ACL != "" || in.ServerSideEncryption != "" || (in.StorageClass != "" && in.StorageClass != types.StorageClassStandard) {
		return true
	}
	if in.BucketKeyEnabled != nil && *in.BucketKeyEnabled {
		return true
	}
	return anyString(in.Tagging, in.GrantFullControl, in.GrantRead, in.GrantReadACP, in.GrantWriteACP, in.SSEKMSKeyId, in.SSEKMSEncryptionContext, in.WebsiteRedirectLocation)
}

func lockDateSet(t *time.Time) bool {
	return t != nil && !t.IsZero()
}

func unsupportedComplete(in *s3.CompleteMultipartUploadInput) bool {
	if in.ChecksumType != "" || in.MpuObjectSize != nil {
		return true
	}
	if backend.HasSSEC(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5) {
		return true
	}
	return anyString(in.IfMatch, in.IfNoneMatch, in.ChecksumCRC32, in.ChecksumCRC32C, in.ChecksumCRC64NVME, in.ChecksumMD5, in.ChecksumSHA1, in.ChecksumSHA256, in.ChecksumSHA512, in.ChecksumXXHASH64, in.ChecksumXXHASH3, in.ChecksumXXHASH128)
}

func partHasChecksum(p types.CompletedPart) bool {
	return anyString(p.ChecksumCRC32, p.ChecksumCRC32C, p.ChecksumCRC64NVME, p.ChecksumMD5, p.ChecksumSHA1, p.ChecksumSHA256, p.ChecksumSHA512, p.ChecksumXXHASH64, p.ChecksumXXHASH3, p.ChecksumXXHASH128)
}

func putInputFromCreate(in s3response.CreateMultipartUploadInput) s3response.PutObjectInput {
	return s3response.PutObjectInput{
		ContentType:        in.ContentType,
		ContentEncoding:    in.ContentEncoding,
		ContentDisposition: in.ContentDisposition,
		ContentLanguage:    in.ContentLanguage,
		CacheControl:       in.CacheControl,
		Expires:            in.Expires,
		Metadata:           in.Metadata,
	}
}

func anyString(vals ...*string) bool {
	for _, v := range vals {
		if v != nil && *v != "" {
			return true
		}
	}
	return false
}

func optionalString(fs FS, obj Object, name string) *string {
	b, err := fs.GetXattr(obj, name)
	if err != nil || len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}
