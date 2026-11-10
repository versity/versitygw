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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func (d *Daos) CopyObject(_ context.Context, input s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
	var out s3response.CopyObjectOutput
	if backend.HasSSEC(input.SSECustomerAlgorithm, input.SSECustomerKey, input.SSECustomerKeyMD5,
		input.CopySourceSSECustomerAlgorithm, input.CopySourceSSECustomerKey, input.CopySourceSSECustomerKeyMD5) {
		return out, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if unsupportedCopy(input) {
		return out, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if input.Key == nil {
		return out, s3err.GetAPIError(s3err.ErrInvalidCopyDest)
	}
	if input.CopySource == nil {
		return out, s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceBucket, "")
	}
	srcBucket, srcKey, versionID, err := backend.ParseCopySource(*input.CopySource)
	if err != nil {
		return out, err
	}
	if versionID != "" {
		return out, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, versionID)
	}
	dstBucket := awsString(input.Bucket)
	dstKey := awsString(input.Key)
	if err := reservedKey(dstKey); err != nil {
		return out, err
	}
	if err := d.bucketExists(srcBucket); err != nil {
		return out, err
	}
	if err := d.bucketExists(dstBucket); err != nil {
		return out, err
	}
	// Destination conditions are evaluated inside the guarded
	// publish, against the destination as observed there.
	info, obj, srcLease, err := d.openLive(srcBucket, srcKey, openRead)
	if err != nil {
		return out, err
	}
	defer func() {
		srcLease.release(d.fs)
		d.fs.Release(obj)
	}()
	srcETag, meta, headers, err := d.attrs(obj)
	if err != nil {
		return out, err
	}
	if err := backend.EvaluatePreconditions(srcETag, time.Unix(info.Mtime, 0).UTC(), backend.PreConditions{
		IfMatch:       input.CopySourceIfMatch,
		IfNoneMatch:   input.CopySourceIfNoneMatch,
		IfModSince:    input.CopySourceIfModifiedSince,
		IfUnmodeSince: input.CopySourceIfUnmodifiedSince,
	}); err != nil {
		return out, err
	}
	if objectPath(srcBucket, srcKey) == objectPath(dstBucket, dstKey) &&
		input.MetadataDirective != types.MetadataDirectiveReplace {
		return out, s3err.GetAPIError(s3err.ErrInvalidCopyDest)
	}
	tagging, err := d.copyTagging(input, obj)
	if err != nil {
		return out, err
	}
	po := putInputFromCopy(input, meta, headers)
	po.Tagging = tagging
	var putOut s3response.PutObjectOutput
	if strings.HasSuffix(dstKey, "/") {
		// A directory source copies as an empty directory marker, the
		// same as the POSIX backend; only a non-empty regular object
		// cannot land on a directory key.
		if !info.IsDir && info.Size > 0 {
			return out, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
		}
		putOut, err = d.putDirectory(dstBucket, dstKey, po)
	} else {
		if info.IsDir || info.Size <= 0 {
			putOut, err = d.putFileConds(dstBucket, dstKey, bytes.NewReader(nil), po, input.IfMatch, input.IfNoneMatch)
		} else {
			src := &dfsBodyReader{fs: d.fs, obj: obj, lease: srcLease, rem: info.Size, off: 0}
			putOut, err = d.putFileConds(dstBucket, dstKey, src, po, input.IfMatch, input.IfNoneMatch)
		}
	}
	if err != nil {
		return out, err
	}
	dstInfo, err := d.fs.Stat(objectPath(dstBucket, dstKey))
	if err != nil {
		return out, mapFS(err)
	}
	etag := putOut.ETag
	written := time.Unix(dstInfo.Mtime, 0).UTC()
	res := s3response.CopyObjectResult{
		ETag:         &etag,
		LastModified: &written,
	}
	// The copy response carries the same checksum the destination put
	// computed; without it a client that asked for one cannot confirm
	// it from the result alone.
	fillCopyResultChecksum(&res, putOut)
	return s3response.CopyObjectOutput{
		CopyObjectResult: &res,
	}, nil
}

func (d *Daos) UploadPartCopy(_ context.Context, input *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	var out s3response.CopyPartResult
	if input == nil {
		return out, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if backend.HasSSEC(input.SSECustomerAlgorithm, input.SSECustomerKey, input.SSECustomerKeyMD5,
		input.CopySourceSSECustomerAlgorithm, input.CopySourceSSECustomerKey, input.CopySourceSSECustomerKeyMD5) {
		return out, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	bucket := awsString(input.Bucket)
	key := awsString(input.Key)
	uploadID := awsString(input.UploadId)
	if err := d.bucketExists(bucket); err != nil {
		return out, err
	}
	if strings.HasSuffix(key, "/") {
		return out, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
	}
	if err := validUploadID(uploadID); err != nil {
		return out, err
	}
	if input.PartNumber == nil || *input.PartNumber < 1 || *input.PartNumber > maxPartNumber {
		return out, s3err.GetAPIError(s3err.ErrInvalidPartNumberRange)
	}
	if input.CopySource == nil {
		return out, s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceBucket, "")
	}
	srcBucket, srcKey, versionID, err := backend.ParseCopySource(*input.CopySource)
	if err != nil {
		return out, err
	}
	if versionID != "" {
		return out, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, versionID)
	}
	uploadDir, err := d.uploadDirReady(bucket, key, uploadID)
	if err != nil {
		return out, err
	}
	// Part-copy participates in the session guard through the same
	// stripe as UploadPart: writePart's publishing Move and the
	// readiness checks run under it.
	unlock := d.coord.uploads.lock(uploadID)
	defer unlock()
	if err := d.bucketExists(srcBucket); err != nil {
		return out, err
	}
	info, obj, srcLease, err := d.openLive(srcBucket, srcKey, openRead)
	if err != nil {
		return out, err
	}
	defer func() {
		srcLease.release(d.fs)
		d.fs.Release(obj)
	}()
	srcETag, _, _, err := d.attrs(obj)
	if err != nil {
		return out, err
	}
	if err := backend.EvaluatePreconditions(srcETag, time.Unix(info.Mtime, 0).UTC(), backend.PreConditions{
		IfMatch:       input.CopySourceIfMatch,
		IfNoneMatch:   input.CopySourceIfNoneMatch,
		IfModSince:    input.CopySourceIfModifiedSince,
		IfUnmodeSince: input.CopySourceIfUnmodifiedSince,
	}); err != nil {
		return out, err
	}
	start, length, _, err := objectRange(input.CopySourceRange, info.Size)
	if err != nil {
		return out, err
	}
	stored, err := d.loadChecksumsAt(uploadDir)
	if err != nil {
		return out, err
	}
	var buffered []byte
	if !info.IsDir && length > 0 {
		buffered = make([]byte, length)
		if _, err := readFull(d.fs, obj, buffered, start); err != nil {
			return out, err
		}
	}
	reader := bytes.NewReader(buffered)
	var hashed partHash
	hashed.body = reader
	if stored.Type != "" {
		sum, err := hashReader(stored.Algorithm, reader, "")
		if err != nil {
			return out, err
		}
		hashed.sum = sum
		hashed.userAlg = utils.HashType(strings.ToLower(string(stored.Algorithm)))
		hashed.expose = true
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			return out, err
		}
	}
	nlen := int64(len(buffered))
	etag, err := d.writePart(uploadDir, *input.PartNumber, reader, &nlen, stored, hashed)
	if err != nil {
		return out, err
	}
	partPath := path.Join(uploadDir, strconv.FormatInt(int64(*input.PartNumber), 10))
	partInfo, err := d.fs.Stat(partPath)
	if err != nil {
		return out, mapFS(err)
	}
	res := s3response.CopyPartResult{
		ETag:         &etag,
		LastModified: time.Unix(partInfo.Mtime, 0).UTC(),
	}
	if hashed.expose {
		setCopyPartChecksum(&res, hashed.userAlg, hashed.userSum())
	}
	return res, nil
}

func putInputFromCopy(input s3response.CopyObjectInput, meta map[string]string, headers objHeaders) s3response.PutObjectInput {
	if input.MetadataDirective == types.MetadataDirectiveReplace {
		return s3response.PutObjectInput{
			ContentType:             input.ContentType,
			ContentEncoding:         input.ContentEncoding,
			ContentLanguage:         input.ContentLanguage,
			ContentDisposition:      input.ContentDisposition,
			CacheControl:            input.CacheControl,
			Expires:                 input.Expires,
			Metadata:                input.Metadata,
			WebsiteRedirectLocation: input.WebsiteRedirectLocation,
			ChecksumAlgorithm:       input.ChecksumAlgorithm,
		}
	}
	return s3response.PutObjectInput{
		ContentType:             strPtr(headers.ctype),
		ContentEncoding:         strPtr(headers.encoding),
		ContentLanguage:         strPtr(headers.language),
		ContentDisposition:      strPtr(headers.disposition),
		CacheControl:            strPtr(headers.cache),
		Expires:                 strPtr(headers.expires),
		WebsiteRedirectLocation: strPtr(headers.redirect),
		Metadata:                meta,
		ChecksumAlgorithm:       input.ChecksumAlgorithm,
	}
}

func (d *Daos) copyTagging(input s3response.CopyObjectInput, src Object) (*string, error) {
	if input.TaggingDirective == types.TaggingDirectiveReplace {
		return input.Tagging, nil
	}
	raw, err := d.fs.GetXattr(src, attrTags)
	if errors.Is(err, errNotExist) || len(raw) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, mapFS(err)
	}
	var tags map[string]string
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil, fmt.Errorf("parse source tags: %w", err)
	}
	if len(tags) == 0 {
		return nil, nil
	}
	parts := make([]string, 0, len(tags))
	for key, value := range tags {
		parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(value))
	}
	sort.Strings(parts)
	encoded := strings.Join(parts, "&")
	return &encoded, nil
}

func unsupportedCopy(in s3response.CopyObjectInput) bool {
	if in.ObjectLockMode != "" || in.ObjectLockLegalHoldStatus != "" || lockDateSet(in.ObjectLockRetainUntilDate) {
		return true
	}
	// Destination write conditions need the object at the destination
	// key; they are evaluated rather than rejected, so they do not
	// belong here.
	if in.ACL != "" || in.ServerSideEncryption != "" || (in.StorageClass != "" && in.StorageClass != types.StorageClassStandard) {
		return true
	}
	if in.BucketKeyEnabled != nil && *in.BucketKeyEnabled {
		return true
	}
	return anyString(in.GrantFullControl, in.GrantRead, in.GrantReadACP, in.GrantWriteACP, in.SSEKMSKeyId, in.SSEKMSEncryptionContext)
}
