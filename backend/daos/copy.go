// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
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
	"io"
	"path"
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
	if err := d.bucketExists(srcBucket); err != nil {
		return out, err
	}
	if err := d.bucketExists(dstBucket); err != nil {
		return out, err
	}
	info, obj, err := d.openLive(srcBucket, srcKey, openRead)
	if err != nil {
		return out, err
	}
	defer d.fs.Release(obj)
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
	body, err := readObjectBytes(d.fs, obj, info)
	if err != nil {
		return out, err
	}
	po := putInputFromCopy(input, meta, headers)
	var putOut s3response.PutObjectOutput
	if strings.HasSuffix(dstKey, "/") {
		if len(body) != 0 {
			return out, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)
		}
		putOut, err = d.putDirectory(dstBucket, dstKey, po)
	} else {
		putOut, err = d.putFile(dstBucket, dstKey, body, po)
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
	return s3response.CopyObjectOutput{
		CopyObjectResult: &s3response.CopyObjectResult{
			ETag:         &etag,
			LastModified: &written,
		},
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
	if err := d.bucketExists(srcBucket); err != nil {
		return out, err
	}
	info, obj, err := d.openLive(srcBucket, srcKey, openRead)
	if err != nil {
		return out, err
	}
	defer d.fs.Release(obj)
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
	body := []byte{}
	if !info.IsDir && length > 0 {
		body = make([]byte, length)
		n, err := d.fs.Read(obj, body, start)
		if err != nil {
			return out, err
		}
		body = body[:n]
	}
	stored, err := d.loadChecksumsAt(uploadDir)
	if err != nil {
		return out, err
	}
	reader := bytes.NewReader(body)
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
	nlen := int64(len(body))
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

func readObjectBytes(fs FS, obj Object, info Info) ([]byte, error) {
	if info.IsDir || info.Size <= 0 {
		return []byte{}, nil
	}
	body := make([]byte, info.Size)
	n, err := fs.Read(obj, body, 0)
	if err != nil {
		return nil, err
	}
	return body[:n], nil
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

func unsupportedCopy(in s3response.CopyObjectInput) bool {
	if in.ObjectLockMode != "" || in.ObjectLockLegalHoldStatus != "" || lockDateSet(in.ObjectLockRetainUntilDate) {
		return true
	}
	if in.ACL != "" || in.ServerSideEncryption != "" || (in.StorageClass != "" && in.StorageClass != types.StorageClassStandard) {
		return true
	}
	if in.BucketKeyEnabled != nil && *in.BucketKeyEnabled {
		return true
	}
	return anyString(in.GrantFullControl, in.GrantRead, in.GrantReadACP, in.GrantWriteACP, in.SSEKMSKeyId, in.SSEKMSEncryptionContext)
}
