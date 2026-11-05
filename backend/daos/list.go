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
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

func (d *Daos) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	bucket := awsString(input.Bucket)
	prefix := awsString(input.Prefix)
	marker := awsString(input.Marker)
	delim := awsString(input.Delimiter)
	max := maxKeys(input.MaxKeys)
	results, err := d.walk(ctx, bucket, prefix, delim, marker, max, true)
	if err != nil {
		return s3response.ListObjectsResult{}, err
	}
	return s3response.ListObjectsResult{
		CommonPrefixes: results.CommonPrefixes,
		Contents:       results.Objects,
		Delimiter:      backend.GetPtrFromString(delim),
		Marker:         backend.GetPtrFromString(marker),
		NextMarker:     backend.GetPtrFromString(results.NextMarker),
		Prefix:         backend.GetPtrFromString(prefix),
		IsTruncated:    &results.Truncated,
		MaxKeys:        &max,
		Name:           backend.GetPtrFromString(bucket),
	}, nil
}

func (d *Daos) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	bucket := awsString(input.Bucket)
	prefix := awsString(input.Prefix)
	delim := awsString(input.Delimiter)
	marker := listMarker(input.ContinuationToken, input.StartAfter)
	max := maxKeys(input.MaxKeys)
	fetchOwner := input.FetchOwner != nil && *input.FetchOwner
	results, err := d.walk(ctx, bucket, prefix, delim, marker, max, fetchOwner)
	if err != nil {
		return s3response.ListObjectsV2Result{}, err
	}
	count := int32(len(results.Objects) + len(results.CommonPrefixes))
	return s3response.ListObjectsV2Result{
		CommonPrefixes:        results.CommonPrefixes,
		Contents:              results.Objects,
		IsTruncated:           &results.Truncated,
		MaxKeys:               &max,
		Name:                  backend.GetPtrFromString(bucket),
		KeyCount:              &count,
		Delimiter:             backend.GetPtrFromString(delim),
		ContinuationToken:     backend.GetPtrFromString(marker),
		NextContinuationToken: backend.GetPtrFromString(results.NextMarker),
		Prefix:                backend.GetPtrFromString(prefix),
		StartAfter:            backend.GetPtrFromString(awsString(input.StartAfter)),
	}, nil
}

func (d *Daos) walk(ctx context.Context, bucket, prefix, delim, marker string, max int32, fetchOwner bool) (backend.WalkResults, error) {
	if err := d.bucketExists(bucket); err != nil {
		return backend.WalkResults{}, err
	}
	results, err := backend.Walk(ctx, bucketFS{dfs: d.fs, bucket: bucket}, prefix, delim, marker, max, d.fileToObj(bucket, fetchOwner), []string{tmpDirName})
	if err != nil {
		return backend.WalkResults{}, err
	}
	return results, nil
}

func (d *Daos) fileToObj(bucket string, fetchOwner bool) backend.GetObjFunc {
	return func(objPath string, entry fs.DirEntry) (s3response.Object, error) {
		lookup := strings.TrimSuffix(objPath, "/")
		obj, err := d.fs.Open(objectPath(bucket, lookup), openRead)
		if errors.Is(err, errNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		if err != nil {
			return s3response.Object{}, mapFS(err)
		}
		defer d.fs.Release(obj)
		etagb, err := d.fs.GetXattr(obj, attrETag)
		if errors.Is(err, errNotExist) {
			if entry.IsDir() {
				return s3response.Object{}, backend.ErrSkipObj
			}
		} else if err != nil {
			return s3response.Object{}, mapFS(err)
		}
		info, err := entry.Info()
		if err != nil {
			return s3response.Object{}, err
		}
		etag := string(etagb)
		key := objPath
		size := info.Size()
		if entry.IsDir() {
			size = 0
			if !strings.HasSuffix(key, "/") {
				key += "/"
			}
		}
		mod := info.ModTime()
		out := s3response.Object{
			ETag:         &etag,
			Key:          &key,
			LastModified: &mod,
			Size:         &size,
			StorageClass: types.ObjectStorageClassStandard,
		}
		if fetchOwner {
			id := ""
			out.Owner = &types.Owner{ID: &id}
		}
		return out, nil
	}
}

func maxKeys(v *int32) int32 {
	if v == nil {
		return 1000
	}
	return *v
}

func listMarker(token, startAfter *string) string {
	marker := awsString(token)
	if after := awsString(startAfter); after > marker {
		return after
	}
	return marker
}
