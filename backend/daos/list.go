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
	"errors"
	"io/fs"
	"path"
	"strings"
	"time"

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
	getObj := d.fileToObj(bucket, fetchOwner)
	results, err := backend.Walk(ctx, bucketFS{dfs: d.fs, bucket: bucket}, prefix, delim, marker, max, getObj.get, backend.SkipDirs{Root: []string{tmpDirName}})
	getObj.Release()
	if err != nil {
		return backend.WalkResults{}, err
	}
	return results, nil
}

func (d *Daos) fileToObj(bucket string, fetchOwner bool) *objResolver {
	// One parent handle serves every entry of the same directory page.
	return &objResolver{
		d:      d,
		bucket: bucket,
		owner:  fetchOwner,
	}
}

// objResolver converts walked entries to objects, holding the parent
// directory handle open while the walk visits that directory.
type objResolver struct {
	d          *Daos
	bucket     string
	owner      bool
	cachedPath string
	cachedOpen Object
}

func (r *objResolver) parent(objDir string) (Object, error) {
	parentPath := objectPath(r.bucket, objDir)
	if parentPath == r.cachedPath {
		return r.cachedOpen, nil
	}
	r.Release()
	parent, err := r.d.fs.Open(parentPath, openRead)
	if err != nil {
		return nil, err
	}
	r.cachedPath = parentPath
	r.cachedOpen = parent
	return parent, nil
}

// Release drops the held parent handle. The walk calls it once it is done.
func (r *objResolver) Release() {
	if r.cachedOpen != nil {
		r.d.fs.Release(r.cachedOpen)
		r.cachedOpen = nil
		r.cachedPath = ""
	}
}

func (r *objResolver) get(objPath string, entry fs.DirEntry) (s3response.Object, error) {
	d := r.d
	lookup := strings.TrimSuffix(objPath, "/")
	dir, base := path.Split(lookup)
	parent, err := r.parent(path.Clean(dir))
	if err != nil {
		if errors.Is(err, errNotExist) {
			return s3response.Object{}, backend.ErrSkipObj
		}
		return s3response.Object{}, mapFS(err)
	}
	etag, info, rerr := d.relSummary(parent, base)
	if rerr != nil {
		if errors.Is(rerr, errNotExist) {
			// The entry vanished between enumeration and lookup.
			return s3response.Object{}, backend.ErrSkipObj
		}
		return s3response.Object{}, mapFS(rerr)
	}
	if etag == "" {
		if entry.IsDir() {
			return s3response.Object{}, backend.ErrSkipObj
		}
	}
	key := objPath
	size := info.Size
	if entry.IsDir() {
		size = 0
		if !strings.HasSuffix(key, "/") {
			key += "/"
		}
	}
	mod := time.Unix(info.Mtime, 0).UTC()
	out := s3response.Object{
		ETag:         &etag,
		Key:          &key,
		LastModified: &mod,
		Size:         &size,
		StorageClass: types.ObjectStorageClassStandard,
	}
	if r.owner {
		id := ""
		out.Owner = &types.Owner{ID: &id}
	}
	return out, nil
}

// relSummary opens one entry relative to its parent and reads the packed
// attributes and stat in two calls. A missing etag means the entry is not
// an object.
func (d *Daos) relSummary(parent Object, name string) (string, Info, error) {
	obj, err := d.fs.OpenRel(parent, name, openRead)
	if err != nil {
		return "", Info{}, err
	}
	defer d.fs.Release(obj)
	info, err := d.fs.StatObj(obj)
	if err != nil {
		return "", Info{}, err
	}
	etag := ""
	if m, err := d.loadAttrs(obj); err == nil {
		etag = m[attrETag]
	}
	return etag, info, nil
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
