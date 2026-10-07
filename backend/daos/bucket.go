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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const (
	attrACL       = "acl"
	attrPolicy    = "policy"
	attrOwnership = "ownership"
	attrCORS      = "cors"
	attrWebsite   = "website"
	attrTags      = "X-Amz-Tagging"
	attrRedirect  = "website-redirect-location"
	lockDirName   = ".vgwlocks"
	versDirName   = ".vgwvers"
)

func validBucketName(bucket string) error {
	if bucket == "" || bucket == "." || bucket == ".." || bucket == lockDirName || bucket == versDirName || strings.ContainsRune(bucket, '/') {
		return s3err.GetBucketErr(s3err.ErrInvalidBucketName, bucket)
	}
	return nil
}

func (d *Daos) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, acl []byte) error {
	if input == nil || input.Bucket == nil {
		return s3err.GetBucketErr(s3err.ErrInvalidBucketName, "")
	}
	bucket := *input.Bucket
	if err := validBucketName(bucket); err != nil {
		return err
	}
	if input.ObjectLockEnabledForBucket != nil && *input.ObjectLockEnabledForBucket {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	var tags []types.Tag
	if input.CreateBucketConfiguration != nil {
		tags = input.CreateBucketConfiguration.Tags
	}
	parsed, err := backend.ParseCreateBucketTags(tags)
	if err != nil {
		return err
	}
	if err := d.fs.Mkdir(bucket); err != nil {
		if errors.Is(err, errExist) {
			return d.bucketAlreadyExists(ctx, bucket)
		}
		return mapFS(err)
	}
	if err := d.finishCreate(bucket, acl, input.ObjectOwnership, parsed); err != nil {
		_ = d.fs.Remove(bucket, true)
		return err
	}
	return nil
}

func (d *Daos) finishCreate(bucket string, acl []byte, ownership types.ObjectOwnership, tags map[string]string) error {
	obj, err := d.fs.Open(bucket, openRead)
	if err != nil {
		return mapFS(err)
	}
	defer d.fs.Release(obj)
	if err := d.fs.SetXattr(obj, attrACL, acl); err != nil {
		return mapFS(err)
	}
	if err := d.fs.SetXattr(obj, attrOwnership, []byte(ownership)); err != nil {
		return mapFS(err)
	}
	if tags == nil {
		return nil
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	return mapFS(d.fs.SetXattr(obj, attrTags, raw))
}

func (d *Daos) bucketAlreadyExists(ctx context.Context, bucket string) error {
	info, err := d.fs.Stat(bucket)
	if err != nil || !info.IsDir {
		return s3err.GetBucketErr(s3err.ErrBucketAlreadyExists, bucket)
	}
	raw, err := d.xattr(bucket, attrACL)
	if errors.Is(err, errNotExist) || len(raw) == 0 {
		return s3err.GetBucketErr(s3err.ErrBucketAlreadyExists, bucket)
	}
	if err != nil {
		return mapFS(err)
	}
	acl, err := auth.ParseACL(raw)
	if err != nil {
		return err
	}
	acct, _ := ctx.Value("bucket-owner").(auth.Account)
	if acct.Access != "" && acl.Owner == acct.Access {
		return s3err.GetBucketErr(s3err.ErrBucketAlreadyOwnedByYou, bucket)
	}
	return s3err.GetBucketErr(s3err.ErrBucketAlreadyExists, bucket)
}

func (d *Daos) DeleteBucket(_ context.Context, bucket string) error {
	if err := d.bucketExists(bucket); err != nil {
		return err
	}
	ents, err := d.fs.ReadDir(bucket)
	if err != nil {
		return mapFS(err)
	}
	for _, ent := range ents {
		if ent.Name == tmpDirName {
			continue
		}
		return s3err.GetBucketErr(s3err.ErrBucketNotEmpty, bucket)
	}
	if err := d.fs.Remove(bucket, true); err != nil {
		return mapFS(err)
	}
	return nil
}

func (d *Daos) HeadBucket(_ context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	if input == nil || input.Bucket == nil {
		return nil, s3err.GetBucketErr(s3err.ErrInvalidBucketName, "")
	}
	if err := d.bucketExists(*input.Bucket); err != nil {
		return nil, err
	}
	return &s3.HeadBucketOutput{}, nil
}

func (d *Daos) ListBuckets(_ context.Context, input s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
	ents, err := d.fs.ReadDir("")
	if err != nil {
		return s3response.ListAllMyBucketsResult{}, mapFS(err)
	}
	names := make([]string, 0, len(ents))
	mtime := map[string]int64{}
	for _, ent := range ents {
		if !ent.IsDir || ent.Name == lockDirName || ent.Name == versDirName || !utils.IsValidBucketName(ent.Name) {
			continue
		}
		names = append(names, ent.Name)
		mtime[ent.Name] = ent.Mtime
	}
	sort.Strings(names)
	var buckets []s3response.ListAllMyBucketsEntry
	var token string
	for _, name := range names {
		if !strings.HasPrefix(name, input.Prefix) || name <= input.ContinuationToken {
			continue
		}
		if input.MaxBuckets > 0 && len(buckets) == int(input.MaxBuckets) {
			token = buckets[len(buckets)-1].Name
			break
		}
		if !input.IsAdmin {
			raw, err := d.xattr(name, attrACL)
			if errors.Is(err, errNotExist) || len(raw) == 0 {
				continue
			}
			if err != nil {
				return s3response.ListAllMyBucketsResult{}, mapFS(err)
			}
			acl, err := auth.ParseACL(raw)
			if err != nil {
				return s3response.ListAllMyBucketsResult{}, err
			}
			if acl.Owner != input.Owner {
				continue
			}
		}
		buckets = append(buckets, s3response.ListAllMyBucketsEntry{
			Name:         name,
			CreationDate: time.Unix(mtime[name], 0).UTC(),
		})
	}
	return s3response.ListAllMyBucketsResult{
		Buckets:           s3response.ListAllMyBucketsList{Bucket: buckets},
		Owner:             s3response.CanonicalUser{ID: input.Owner},
		Prefix:            input.Prefix,
		ContinuationToken: token,
	}, nil
}

func (d *Daos) ListBucketsAndOwners(context.Context) ([]s3response.Bucket, error) {
	ents, err := d.fs.ReadDir("")
	if err != nil {
		return nil, mapFS(err)
	}
	var buckets []s3response.Bucket
	for _, ent := range ents {
		if !ent.IsDir || ent.Name == lockDirName || ent.Name == versDirName || !utils.IsValidBucketName(ent.Name) {
			continue
		}
		raw, err := d.xattr(ent.Name, attrACL)
		if err != nil && !errors.Is(err, errNotExist) {
			return nil, mapFS(err)
		}
		acl, err := auth.ParseACL(raw)
		if err != nil {
			return nil, err
		}
		buckets = append(buckets, s3response.Bucket{Name: ent.Name, Owner: acl.Owner})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
	return buckets, nil
}

func (d *Daos) ChangeBucketOwner(ctx context.Context, bucket, owner string) error {
	if err := d.bucketExists(bucket); err != nil {
		return err
	}
	return auth.UpdateBucketACLOwner(ctx, d, bucket, owner)
}

func (d *Daos) PutBucketAcl(_ context.Context, bucket string, data []byte) error {
	return d.putBucketBytes(bucket, attrACL, data)
}

func (d *Daos) PutBucketPolicy(_ context.Context, bucket string, policy []byte) error {
	return d.putBucketBytes(bucket, attrPolicy, policy)
}

func (d *Daos) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return d.PutBucketPolicy(ctx, bucket, nil)
}

func (d *Daos) PutBucketOwnershipControls(_ context.Context, bucket string, ownership types.ObjectOwnership) error {
	return d.putBucketBytes(bucket, attrOwnership, []byte(ownership))
}

func (d *Daos) GetBucketOwnershipControls(_ context.Context, bucket string) (types.ObjectOwnership, error) {
	raw, err := d.getBucketBytes(bucket, attrOwnership)
	if errors.Is(err, errNotExist) {
		return "", s3err.GetBucketErr(s3err.ErrOwnershipControlsNotFound, bucket)
	}
	if err != nil {
		return "", err
	}
	return types.ObjectOwnership(raw), nil
}

func (d *Daos) DeleteBucketOwnershipControls(ctx context.Context, bucket string) error {
	return d.putBucketBytes(bucket, attrOwnership, nil)
}

func (d *Daos) PutBucketCors(_ context.Context, bucket string, cors []byte) error {
	return d.putBucketBytes(bucket, attrCORS, cors)
}

func (d *Daos) GetBucketCors(_ context.Context, bucket string) ([]byte, error) {
	raw, err := d.getBucketBytes(bucket, attrCORS)
	if errors.Is(err, errNotExist) {
		return nil, s3err.GetBucketErr(s3err.ErrNoSuchCORSConfiguration, bucket)
	}
	return raw, err
}

func (d *Daos) DeleteBucketCors(ctx context.Context, bucket string) error {
	return d.PutBucketCors(ctx, bucket, nil)
}

func (d *Daos) PutBucketWebsite(_ context.Context, bucket string, website []byte) error {
	if website == nil {
		return d.putBucketBytes(bucket, attrWebsite, nil)
	}
	encoded, err := backend.MarshalWebsiteConfig(website, false)
	if err != nil {
		return err
	}
	return d.putBucketBytes(bucket, attrWebsite, encoded)
}

func (d *Daos) GetBucketWebsite(_ context.Context, bucket string) ([]byte, error) {
	raw, err := d.getBucketBytes(bucket, attrWebsite)
	if errors.Is(err, errNotExist) {
		return nil, s3err.GetBucketErr(s3err.ErrNoSuchWebsiteConfiguration, bucket)
	}
	if err != nil {
		return nil, err
	}
	return backend.UnmarshalWebsiteConfig(raw, false)
}

func (d *Daos) DeleteBucketWebsite(ctx context.Context, bucket string) error {
	return d.PutBucketWebsite(ctx, bucket, nil)
}

func (d *Daos) PutBucketTagging(_ context.Context, bucket string, tags map[string]string) error {
	if tags == nil {
		return d.putBucketBytes(bucket, attrTags, nil)
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	return d.putBucketBytes(bucket, attrTags, raw)
}

func (d *Daos) GetBucketTagging(_ context.Context, bucket string) (map[string]string, error) {
	raw, err := d.getBucketBytes(bucket, attrTags)
	if errors.Is(err, errNotExist) {
		return nil, s3err.GetBucketErr(s3err.ErrBucketTaggingNotFound, bucket)
	}
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil, fmt.Errorf("unmarshal tags: %w", err)
	}
	return tags, nil
}

func (d *Daos) DeleteBucketTagging(ctx context.Context, bucket string) error {
	return d.PutBucketTagging(ctx, bucket, nil)
}

func (d *Daos) PutObjectTagging(_ context.Context, bucket, object, versionID string, tags map[string]string) error {
	if versionID != "" {
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, versionID)
	}
	p, err := d.objectAttrPath(bucket, object)
	if err != nil {
		return err
	}
	if tags == nil {
		return d.removeXattr(p, attrTags)
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	return d.setXattr(p, attrTags, raw)
}

func (d *Daos) GetObjectTagging(_ context.Context, bucket, object, versionID string) (map[string]string, error) {
	if versionID != "" {
		return nil, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, versionID)
	}
	p, err := d.objectAttrPath(bucket, object)
	if err != nil {
		return nil, err
	}
	raw, err := d.xattr(p, attrTags)
	if errors.Is(err, errNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, mapFS(err)
	}
	tags := map[string]string{}
	if len(raw) == 0 {
		return tags, nil
	}
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil, fmt.Errorf("unmarshal tags: %w", err)
	}
	return tags, nil
}

func (d *Daos) DeleteObjectTagging(ctx context.Context, bucket, object, versionID string) error {
	return d.PutObjectTagging(ctx, bucket, object, versionID, nil)
}

func (d *Daos) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
	if input == nil {
		return s3response.GetObjectAttributesResponse{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if backend.HasSSEC(input.SSECustomerAlgorithm, input.SSECustomerKey, input.SSECustomerKeyMD5) {
		return s3response.GetObjectAttributesResponse{}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	data, err := d.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:       input.Bucket,
		Key:          input.Key,
		VersionId:    input.VersionId,
		ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return s3response.GetObjectAttributesResponse{}, err
	}
	return s3response.GetObjectAttributesResponse{
		ETag:         backend.TrimEtag(data.ETag),
		ObjectSize:   data.ContentLength,
		LastModified: data.LastModified,
		Checksum: &types.Checksum{
			ChecksumCRC32:     data.ChecksumCRC32,
			ChecksumCRC32C:    data.ChecksumCRC32C,
			ChecksumSHA1:      data.ChecksumSHA1,
			ChecksumSHA256:    data.ChecksumSHA256,
			ChecksumCRC64NVME: data.ChecksumCRC64NVME,
			ChecksumSHA512:    data.ChecksumSHA512,
			ChecksumMD5:       data.ChecksumMD5,
			ChecksumXXHASH64:  data.ChecksumXXHASH64,
			ChecksumXXHASH3:   data.ChecksumXXHASH3,
			ChecksumXXHASH128: data.ChecksumXXHASH128,
			ChecksumType:      data.ChecksumType,
		},
	}, nil
}

func (d *Daos) putBucketBytes(bucket, name string, value []byte) error {
	if err := d.bucketExists(bucket); err != nil {
		return err
	}
	if value == nil {
		return d.removeXattr(bucket, name)
	}
	return d.setXattr(bucket, name, value)
}

func (d *Daos) getBucketBytes(bucket, name string) ([]byte, error) {
	if err := d.bucketExists(bucket); err != nil {
		return nil, err
	}
	raw, err := d.xattr(bucket, name)
	if errors.Is(err, errNotExist) {
		return nil, errNotExist
	}
	if err != nil {
		return nil, mapFS(err)
	}
	if len(raw) == 0 {
		return nil, errNotExist
	}
	return raw, nil
}

func (d *Daos) objectAttrPath(bucket, object string) (string, error) {
	if err := d.bucketExists(bucket); err != nil {
		return "", err
	}
	if object == "" {
		return "", s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if _, obj, err := d.openLive(bucket, object, openRead); err != nil {
		return "", err
	} else {
		d.fs.Release(obj)
	}
	return objectPath(bucket, object), nil
}

func (d *Daos) removeXattr(p, name string) error {
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return mapFS(err)
	}
	defer d.fs.Release(obj)
	err = d.fs.RemoveXattr(obj, name)
	if errors.Is(err, errNotExist) {
		return nil
	}
	return mapFS(err)
}

func (d *Daos) storeTagHeader(obj Object, tagging *string) error {
	tags, err := backend.ParseObjectTags(awsString(tagging))
	if err != nil {
		return err
	}
	if tags == nil {
		return nil
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	return mapFS(d.fs.SetXattr(obj, attrTags, raw))
}

func (d *Daos) copyAttr(src string, dst Object, name string) error {
	raw, err := d.xattr(src, name)
	if errors.Is(err, errNotExist) || len(raw) == 0 {
		return nil
	}
	if err != nil {
		return mapFS(err)
	}
	return mapFS(d.fs.SetXattr(dst, name, raw))
}
