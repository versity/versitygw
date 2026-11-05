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

package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const testMetaContainer = "vgw-meta"

// A bucket written before the meta container was configured keeps its
// settings in the container metadata, and they are still served.
func TestBucketMetaReadsContainerMetadata(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("bkt", map[string]string{
		"Acl":    encodeBytes(aclJSON(t, "alice")),
		"Policy": encodeBytes([]byte(`{"legacy":true}`)),
	})

	policy, err := az.GetBucketPolicy(context.Background(), "bkt")
	if err != nil {
		t.Fatalf("get bucket policy: %v", err)
	}
	if string(policy) != `{"legacy":true}` {
		t.Errorf("policy = %s, want the container metadata value", policy)
	}

	acl, err := az.GetBucketAcl(context.Background(), &s3.GetBucketAclInput{Bucket: ptr("bkt")})
	if err != nil {
		t.Fatalf("get bucket acl: %v", err)
	}
	if string(acl) != string(aclJSON(t, "alice")) {
		t.Errorf("acl = %s, want the container metadata value", acl)
	}
}

// Writing a setting moves it to the meta container and frees its container
// metadata key, leaving the other keys alone.
func TestBucketMetaWriteMovesSetting(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("bkt", map[string]string{
		"Policy": encodeBytes([]byte(`{"old":true}`)),
		"Cors":   encodeBytes([]byte("cors")),
	})

	err := az.PutBucketPolicy(context.Background(), "bkt", []byte(`{"new":true}`))
	if err != nil {
		t.Fatalf("put bucket policy: %v", err)
	}

	if data, ok := st.blob(testMetaContainer, "vgw-meta-policy-bkt"); !ok || string(data) != `{"new":true}` {
		t.Errorf("policy blob = %q (exists %v), want the new policy", data, ok)
	}
	if keys := st.metadataKeys("bkt"); !slices.Equal(keys, []string{"Cors"}) {
		t.Errorf("container metadata keys = %v, want [Cors]", keys)
	}

	policy, err := az.GetBucketPolicy(context.Background(), "bkt")
	if err != nil {
		t.Fatalf("get bucket policy: %v", err)
	}
	if string(policy) != `{"new":true}` {
		t.Errorf("policy = %s, want the new policy", policy)
	}
}

// Deleting a setting clears it wherever it is stored: a container metadata
// copy left behind would be served again. The blob is kept, empty, so that
// later reads need not look up the container metadata.
func TestBucketMetaDeleteClearsEveryCopy(t *testing.T) {
	tests := []struct {
		name     string
		metadata bool
		blob     bool
	}{
		{name: "container metadata", metadata: true},
		{name: "meta container", blob: true},
		{name: "both", metadata: true, blob: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			az, st := newFakeAzure(t, testMetaContainer)
			md := map[string]string{"Ownership": encodeBytes([]byte("BucketOwnerEnforced"))}
			if tt.metadata {
				md["Cors"] = encodeBytes([]byte("old cors"))
			}
			st.addContainer("bkt", md)
			if tt.blob {
				st.putBlob(testMetaContainer, "vgw-meta-cors-bkt", []byte("new cors"))
			}

			err := az.DeleteBucketCors(context.Background(), "bkt")
			if err != nil {
				t.Fatalf("delete bucket cors: %v", err)
			}

			_, err = az.GetBucketCors(context.Background(), "bkt")
			if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)) {
				t.Errorf("get bucket cors after delete: got %v, want NoSuchCORSConfiguration", err)
			}
			if data, ok := st.blob(testMetaContainer, "vgw-meta-cors-bkt"); !ok || len(data) != 0 {
				t.Errorf("cors blob = %q (exists %v), want an empty blob", data, ok)
			}
			if keys := st.metadataKeys("bkt"); !slices.Equal(keys, []string{"Ownership"}) {
				t.Errorf("container metadata keys = %v, want [Ownership]", keys)
			}
		})
	}
}

// A delete that fails to clear the container metadata copy still hides it.
func TestBucketMetaDeleteHidesContainerMetadata(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("bkt", map[string]string{"Cors": encodeBytes([]byte("old cors"))})
	st.putBlob(testMetaContainer, "vgw-meta-cors-bkt", []byte("new cors"))
	st.denied = map[string]bool{"PUT /bkt": true}

	err := az.DeleteBucketCors(context.Background(), "bkt")
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)) {
		t.Errorf("delete bucket cors: got %v, want AccessDenied", err)
	}

	cors, err := az.GetBucketCors(context.Background(), "bkt")
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)) {
		t.Errorf("get bucket cors after delete: got %q %v, want NoSuchCORSConfiguration", cors, err)
	}
}

// A missing bucket reads as NoSuchBucket, and a write does not store a blob
// for it.
func TestBucketMetaOfMissingBucket(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)

	_, err := az.GetBucketPolicy(context.Background(), "bkt")
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)) {
		t.Errorf("get bucket policy: got %v, want NoSuchBucket", err)
	}

	err = az.PutBucketPolicy(context.Background(), "bkt", []byte(`{"new":true}`))
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)) {
		t.Errorf("put bucket policy: got %v, want NoSuchBucket", err)
	}
	if _, ok := st.blob(testMetaContainer, "vgw-meta-policy-bkt"); ok {
		t.Error("put bucket policy stored a blob for a missing bucket")
	}
}

// The acl is read on nearly every request: from the meta container it takes
// one Azure request, and a bucket written before the meta container was
// configured takes a second one for the container metadata.
func TestBucketAclReadRequests(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("new", nil)
	st.putBlob(testMetaContainer, "vgw-meta-acl-new", aclJSON(t, "alice"))
	st.addContainer("legacy", map[string]string{"Acl": encodeBytes(aclJSON(t, "alice"))})

	for bucket, want := range map[string]int{"new": 1, "legacy": 2} {
		before := st.requestCount()
		acl, err := az.GetBucketAcl(context.Background(), &s3.GetBucketAclInput{Bucket: ptr(bucket)})
		if err != nil {
			t.Fatalf("get %v bucket acl: %v", bucket, err)
		}
		if string(acl) != string(aclJSON(t, "alice")) {
			t.Errorf("%v bucket acl = %s, want alice's", bucket, acl)
		}
		if got := st.requestCount() - before; got != want {
			t.Errorf("%v bucket acl took %v azure requests, want %v", bucket, got, want)
		}
	}
}

// The policy is read on nearly every request, and CORS on every request with
// an Origin. On a bucket created with the meta container, a setting that is
// not set, or was deleted, takes one Azure request to read.
func TestBucketMetaUnsetReadRequests(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	ctx := context.Background()
	err := az.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                    ptr("bkt"),
		ObjectOwnership:           types.ObjectOwnershipBucketOwnerEnforced,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, aclJSON(t, "alice"))
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	err = az.PutBucketPolicy(ctx, "bkt", []byte(`{}`))
	if err != nil {
		t.Fatalf("put bucket policy: %v", err)
	}
	err = az.DeleteBucketPolicy(ctx, "bkt")
	if err != nil {
		t.Fatalf("delete bucket policy: %v", err)
	}

	tests := []struct {
		name string
		read func() error
		want s3err.ErrorCode
	}{
		{
			name: "deleted policy",
			read: func() error { _, err := az.GetBucketPolicy(ctx, "bkt"); return err },
			want: s3err.ErrNoSuchBucketPolicy,
		},
		{
			name: "cors",
			read: func() error { _, err := az.GetBucketCors(ctx, "bkt"); return err },
			want: s3err.ErrNoSuchCORSConfiguration,
		},
		{
			name: "website",
			read: func() error { _, err := az.GetBucketWebsite(ctx, "bkt"); return err },
			want: s3err.ErrNoSuchWebsiteConfiguration,
		},
		{
			name: "tagging",
			read: func() error { _, err := az.GetBucketTagging(ctx, "bkt"); return err },
			want: s3err.ErrBucketTaggingNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := st.requestCount()
			err := tt.read()
			if !errors.Is(err, s3err.GetAPIError(tt.want)) {
				t.Errorf("got %v, want %v", err, s3err.GetAPIError(tt.want).Code)
			}
			if got := st.requestCount() - before; got != 1 {
				t.Errorf("took %v azure requests, want 1", got)
			}
		})
	}
}

// A new bucket keeps its acl and tags in the meta container, and does not
// inherit the settings a deleted bucket of the same name left behind.
func TestCreateBucketWithMetaContainer(t *testing.T) {
	tests := []struct {
		name string
		tags []types.Tag
	}{
		{name: "without tags"},
		{name: "with tags", tags: []types.Tag{{Key: ptr("env"), Value: ptr("prod")}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			az, st := newFakeAzure(t, testMetaContainer)
			for _, name := range []string{"acl", "policy", "cors", "website", "tags"} {
				st.putBlob(testMetaContainer, "vgw-meta-"+name+"-bkt", []byte("stale"))
			}

			acl := aclJSON(t, "alice")
			err := az.CreateBucket(context.Background(), &s3.CreateBucketInput{
				Bucket:                    ptr("bkt"),
				ObjectOwnership:           types.ObjectOwnershipBucketOwnerEnforced,
				CreateBucketConfiguration: &types.CreateBucketConfiguration{Tags: tt.tags},
			}, acl)
			if err != nil {
				t.Fatalf("create bucket: %v", err)
			}

			if keys := st.metadataKeys("bkt"); !slices.Equal(keys, []string{"Ownership"}) {
				t.Errorf("container metadata keys = %v, want [Ownership]", keys)
			}
			if data, _ := st.blob(testMetaContainer, "vgw-meta-acl-bkt"); string(data) != string(acl) {
				t.Errorf("acl blob = %s, want %s", data, acl)
			}
			empty := []string{"policy", "cors", "website"}
			if tt.tags == nil {
				empty = append(empty, "tags")
			}
			for _, name := range empty {
				if data, ok := st.blob(testMetaContainer, "vgw-meta-"+name+"-bkt"); !ok || len(data) != 0 {
					t.Errorf("%v blob = %q (exists %v), want an empty blob", name, data, ok)
				}
			}

			tags, err := az.GetBucketTagging(context.Background(), "bkt")
			if tt.tags == nil {
				if !errors.Is(err, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)) {
					t.Errorf("get bucket tagging: got %v %v, want NoSuchTagSet", tags, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("get bucket tagging: %v", err)
			}
			if !maps.Equal(tags, map[string]string{"env": "prod"}) {
				t.Errorf("tags = %v, want env=prod", tags)
			}
		})
	}
}

// A bucket whose acl cannot be stored would have no owner, so it is removed,
// also when the request is canceled. A failure to remove it is reported
// along with the cause.
func TestCreateBucketMetaFailure(t *testing.T) {
	aclPath := "/" + testMetaContainer + "/vgw-meta-acl-bkt"
	tests := []struct {
		name          string
		cancel        bool
		removeDenied  bool
		wantContainer bool
	}{
		{name: "removed"},
		{name: "removed after cancel", cancel: true},
		{name: "not removed", removeDenied: true, wantContainer: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			az, st := newFakeAzure(t, testMetaContainer)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				st.onRequest = func(r *http.Request) {
					if r.Method == http.MethodPut && r.URL.Path == aclPath {
						cancel()
					}
				}
			} else {
				st.denied = map[string]bool{"PUT " + aclPath: true}
			}
			if tt.removeDenied {
				st.denied["DELETE /bkt"] = true
			}

			err := az.CreateBucket(ctx, &s3.CreateBucketInput{
				Bucket:                    ptr("bkt"),
				ObjectOwnership:           types.ObjectOwnershipBucketOwnerEnforced,
				CreateBucketConfiguration: &types.CreateBucketConfiguration{},
			}, aclJSON(t, "alice"))
			if err == nil {
				t.Fatal("create bucket succeeded, want an error")
			}

			if got := st.hasContainer("bkt"); got != tt.wantContainer {
				t.Errorf("bucket exists = %v, want %v", got, tt.wantContainer)
			}
			reported := strings.Contains(err.Error(), `remove bucket "bkt"`)
			if reported != tt.removeDenied {
				t.Errorf("error %q reports the failed removal = %v, want %v", err, reported, tt.removeDenied)
			}
		})
	}
}

// The blobs of a deleted bucket are removed, also when the request is
// canceled once the bucket is gone.
func TestDeleteBucketRemovesMetaBlobs(t *testing.T) {
	for _, cancelAfterDelete := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled %v", cancelAfterDelete), func(t *testing.T) {
			az, st := newFakeAzure(t, testMetaContainer)
			st.addContainer("bkt", nil)
			for _, name := range []string{"acl", "policy", "cors", "website", "tags"} {
				st.putBlob(testMetaContainer, "vgw-meta-"+name+"-bkt", []byte("x"))
			}
			st.putBlob(testMetaContainer, "vgw-meta-acl-other", []byte("x"))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelAfterDelete {
				st.onRequest = func(r *http.Request) {
					if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/"+testMetaContainer+"/") {
						cancel()
					}
				}
			}

			err := az.DeleteBucket(ctx, "bkt")
			if err != nil {
				t.Fatalf("delete bucket: %v", err)
			}

			if names := st.blobNames(testMetaContainer); !slices.Equal(names, []string{"vgw-meta-acl-other"}) {
				t.Errorf("meta container blobs = %v, want only the other bucket's", names)
			}
		})
	}
}

// Another gateway can recreate a deleted bucket before the delete has
// removed its blobs, and the late removal must keep the new bucket's acl.
func TestDeleteBucketKeepsRecreatedBucketMeta(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("bkt", nil)
	for _, name := range []string{"acl", "policy", "cors", "website", "tags"} {
		st.putBlob(testMetaContainer, "vgw-meta-"+name+"-bkt", []byte("old"))
	}

	newAcl := aclJSON(t, "bob")
	recreated := false
	st.onRequest = func(r *http.Request) {
		if recreated || r.Method != http.MethodDelete ||
			!strings.HasPrefix(r.URL.Path, "/"+testMetaContainer+"/") {
			return
		}
		// as soon as Azure allows the name again
		recreated = true
		st.now = st.now.Add(30 * time.Second)
		st.containers["bkt"] = map[string]string{}
		st.storeBlob(testMetaContainer, "vgw-meta-acl-bkt", newAcl)
	}

	err := az.DeleteBucket(context.Background(), "bkt")
	if err != nil {
		t.Fatalf("delete bucket: %v", err)
	}

	if !recreated {
		t.Fatal("the bucket was not recreated during the delete")
	}
	if names := st.blobNames(testMetaContainer); !slices.Equal(names, []string{"vgw-meta-acl-bkt"}) {
		t.Errorf("meta container blobs = %v, want only the new acl", names)
	}
	if data, _ := st.blob(testMetaContainer, "vgw-meta-acl-bkt"); string(data) != string(newAcl) {
		t.Errorf("acl blob = %s, want %s", data, newAcl)
	}
}

// Bucket listings skip the meta container and read each bucket's owner from
// wherever its acl is stored.
func TestListBucketsWithMetaContainer(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("legacy", map[string]string{"Acl": encodeBytes(aclJSON(t, "alice"))})
	st.addContainer("new", nil)
	st.putBlob(testMetaContainer, "vgw-meta-acl-new", aclJSON(t, "alice"))
	st.addContainer("other", nil)
	st.putBlob(testMetaContainer, "vgw-meta-acl-other", aclJSON(t, "bob"))

	tests := []struct {
		name  string
		input s3response.ListBucketsInput
		want  []string
	}{
		{name: "owner", input: s3response.ListBucketsInput{Owner: "alice"}, want: []string{"legacy", "new"}},
		{name: "admin", input: s3response.ListBucketsInput{Owner: "root", IsAdmin: true}, want: []string{"legacy", "new", "other"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := az.ListBuckets(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("list buckets: %v", err)
			}
			var names []string
			for _, b := range res.Buckets.Bucket {
				names = append(names, b.Name)
			}
			if !slices.Equal(names, tt.want) {
				t.Errorf("buckets = %v, want %v", names, tt.want)
			}
		})
	}

	owners, err := az.ListBucketsAndOwners(context.Background())
	if err != nil {
		t.Fatalf("list buckets and owners: %v", err)
	}
	want := []s3response.Bucket{{Name: "legacy", Owner: "alice"}, {Name: "new", Owner: "alice"}, {Name: "other", Owner: "bob"}}
	if !slices.Equal(owners, want) {
		t.Errorf("buckets and owners = %v, want %v", owners, want)
	}
}

// The ListBuckets visibility callback gets the acl from wherever it is
// stored, and only for the buckets the caller doesn't own.
func TestListBucketsVisibilityWithMetaContainer(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("legacy", map[string]string{"Acl": encodeBytes(aclJSON(t, "bob"))})
	st.addContainer("new", nil)
	st.putBlob(testMetaContainer, "vgw-meta-acl-new", aclJSON(t, "bob"))
	st.addContainer("own", nil)
	st.putBlob(testMetaContainer, "vgw-meta-acl-own", aclJSON(t, "alice"))

	acls := map[string]string{}
	res, err := az.ListBuckets(context.Background(), s3response.ListBucketsInput{
		Owner: "alice",
		IsVisible: func(_ context.Context, bucket string, acl []byte) (bool, error) {
			acls[bucket] = string(acl)
			return bucket == "new", nil
		},
	})
	if err != nil {
		t.Fatalf("list buckets: %v", err)
	}

	var names []string
	for _, b := range res.Buckets.Bucket {
		names = append(names, b.Name)
	}
	if want := []string{"new", "own"}; !slices.Equal(names, want) {
		t.Errorf("buckets = %v, want %v", names, want)
	}
	want := map[string]string{"legacy": string(aclJSON(t, "bob")), "new": string(aclJSON(t, "bob"))}
	if !maps.Equal(acls, want) {
		t.Errorf("callback acls = %v, want %v", acls, want)
	}
}

func TestMetaContainerIsClosed(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	st.addContainer("bkt", nil)
	ctx := context.Background()
	meta, key := testMetaContainer, "vgw-meta-policy-bkt"

	err := az.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &meta}, nil)
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrBucketAlreadyExists)) {
		t.Errorf("CreateBucket: got %v, want BucketAlreadyExists", err)
	}

	calls := map[string]func() error{
		"HeadBucket": func() error {
			_, err := az.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &meta})
			return err
		},
		"DeleteBucket": func() error { return az.DeleteBucket(ctx, meta) },
		"GetBucketAcl": func() error {
			_, err := az.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &meta})
			return err
		},
		"PutBucketAcl":    func() error { return az.PutBucketAcl(ctx, meta, nil) },
		"PutBucketPolicy": func() error { return az.PutBucketPolicy(ctx, meta, []byte("{}")) },
		"GetBucketPolicy": func() error {
			_, err := az.GetBucketPolicy(ctx, meta)
			return err
		},
		"DeleteBucketPolicy": func() error { return az.DeleteBucketPolicy(ctx, meta) },
		"PutBucketTagging":   func() error { return az.PutBucketTagging(ctx, meta, map[string]string{}) },
		"PutObject": func() error {
			_, err := az.PutObject(ctx, s3response.PutObjectInput{Bucket: &meta, Key: &key})
			return err
		},
		"GetObject": func() error {
			_, err := az.GetObject(ctx, &s3.GetObjectInput{Bucket: &meta, Key: &key})
			return err
		},
		"HeadObject": func() error {
			_, err := az.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &meta, Key: &key})
			return err
		},
		"ListObjectsV2": func() error {
			_, err := az.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &meta})
			return err
		},
		"DeleteObject": func() error {
			_, err := az.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &meta, Key: &key})
			return err
		},
		"DeleteObjects": func() error {
			_, err := az.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &meta, Delete: &types.Delete{}})
			return err
		},
		"CopyObject from": func() error {
			_, err := az.CopyObject(ctx, s3response.CopyObjectInput{
				Bucket: ptr("bkt"), Key: ptr("obj"), CopySource: ptr(meta + "/" + key),
			})
			return err
		},
		"UploadPartCopy from": func() error {
			_, err := az.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket: ptr("bkt"), Key: ptr("obj"), CopySource: ptr(meta + "/" + key),
			})
			return err
		},
		"ListMultipartUploads": func() error {
			_, err := az.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &meta})
			return err
		},
		"GetObjectLockConfiguration": func() error {
			_, err := az.GetObjectLockConfiguration(ctx, meta)
			return err
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)) {
			t.Errorf("%v: got %v, want AccessDenied", name, err)
		}
	}

	if names := st.blobNames(testMetaContainer); len(names) != 0 {
		t.Errorf("meta container blobs = %v, want none", names)
	}
}

// Azure fails a container metadata write past 8 KiB with MetadataTooLarge.
// That is a client error, and a meta container avoids it.
func TestContainerMetadataTooLarge(t *testing.T) {
	policy := []byte(`{"Statement":"` + strings.Repeat("x", 8*1024) + `"}`)

	az, st := newFakeAzure(t, "")
	st.metadataLimit = 8 * 1024
	st.addContainer("bkt", nil)

	err := az.PutBucketPolicy(context.Background(), "bkt", policy)
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrMetadataTooLarge)) {
		t.Errorf("put bucket policy: got %v, want MetadataTooLarge", err)
	}

	az, st = newFakeAzure(t, testMetaContainer)
	st.metadataLimit = 8 * 1024
	st.addContainer("bkt", nil)

	err = az.PutBucketPolicy(context.Background(), "bkt", policy)
	if err != nil {
		t.Fatalf("put bucket policy with a meta container: %v", err)
	}
	got, err := az.GetBucketPolicy(context.Background(), "bkt")
	if err != nil {
		t.Fatalf("get bucket policy: %v", err)
	}
	if string(got) != string(policy) {
		t.Error("policy read back differs from the one stored")
	}
}

// An existing meta container is used as is, also by credentials that may
// not create containers.
func TestCreateMetaContainer(t *testing.T) {
	az, st := newFakeAzure(t, testMetaContainer)
	if !st.hasContainer(testMetaContainer) {
		t.Fatal("meta container was not created")
	}

	st.denied = map[string]bool{"PUT /" + testMetaContainer: true}
	err := az.createMetaContainer(context.Background())
	if err != nil {
		t.Errorf("create existing meta container: %v", err)
	}
}

// A bucket is not taken as the meta container: its owner could have stored
// objects named like the settings of other buckets.
func TestCreateMetaContainerRefusesBucket(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
	}{
		{
			name: "created without a meta container",
			metadata: map[string]string{
				"Acl":       encodeBytes(aclJSON(t, "mallory")),
				"Ownership": encodeBytes([]byte("BucketOwnerEnforced")),
			},
		},
		{
			name:     "created with a meta container",
			metadata: map[string]string{"Ownership": encodeBytes([]byte("BucketOwnerEnforced"))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			az, st := newFakeAzure(t, "")
			st.addContainer(testMetaContainer, tt.metadata)
			st.putBlob(testMetaContainer, "vgw-meta-acl-victim", aclJSON(t, "mallory"))
			az.metaContainer = testMetaContainer

			err := az.createMetaContainer(context.Background())
			if err == nil {
				t.Error("a bucket was taken as the meta container")
			}
		})
	}
}

// Gateway replicas starting together race to create the meta container, and
// the ones that lose must still start.
func TestCreateMetaContainerRace(t *testing.T) {
	az, st := newFakeAzure(t, "")
	az.metaContainer = testMetaContainer
	st.createdConcurrently = testMetaContainer

	err := az.createMetaContainer(context.Background())
	if err != nil {
		t.Errorf("create meta container created by another replica: %v", err)
	}
}

const fakeSAS = "sv=fake"

// newFakeAzure returns an Azure backend over in-memory storage. With a
// non-empty metaContainer, the backend uses it and creates it.
func newFakeAzure(t *testing.T, metaContainer string) (*Azure, *fakeStorage) {
	t.Helper()

	st := &fakeStorage{
		containers: map[string]map[string]string{},
		blobs:      map[string]map[string]fakeBlob{},
		// past a whole second, so a Date header, which has whole seconds,
		// is earlier than the writes made at the same time
		now: time.Date(2026, time.January, 2, 15, 4, 5, int(500*time.Millisecond), time.UTC),
	}
	srv := httptest.NewServer(st)
	t.Cleanup(srv.Close)

	client, err := azblob.NewClientWithNoCredential(srv.URL+"/?"+fakeSAS, nil)
	if err != nil {
		t.Fatalf("init client: %v", err)
	}

	az := &Azure{
		client:        client,
		serviceURL:    srv.URL,
		sasToken:      fakeSAS,
		metaContainer: metaContainer,
	}
	if metaContainer != "" {
		err := az.createMetaContainer(context.Background())
		if err != nil {
			t.Fatalf("create meta container: %v", err)
		}
	}

	return az, st
}

func aclJSON(t *testing.T, owner string) []byte {
	t.Helper()

	data, err := json.Marshal(auth.ACL{Owner: owner})
	if err != nil {
		t.Fatalf("marshal acl: %v", err)
	}
	return data
}

func ptr(s string) *string {
	return &s
}

// fakeStorage serves, from memory, the Azure container and blob calls that
// bucket settings make. Like Azure, it reports container metadata keys from
// GetProperties capitalized and from a container listing lowercased.
type fakeStorage struct {
	mu sync.Mutex
	// container name -> container metadata
	containers map[string]map[string]string
	// container name -> blob name -> blob
	blobs map[string]map[string]fakeBlob
	// now stamps the blobs written and is sent as the Date of every response
	now time.Time
	// denied holds requests, as "METHOD /container[/blob]", that fail with
	// 403 AuthorizationPermissionMismatch like credentials without the
	// permission
	denied map[string]bool
	// onRequest, when set, runs with the storage locked before a request
	// is served
	onRequest func(r *http.Request)
	// metadataLimit, when non-zero, fails a container metadata write whose
	// names and values add up to more
	metadataLimit int
	// createdConcurrently names a container that another client creates
	// right after a GetProperties reports it missing
	createdConcurrently string
	requests            int
}

type fakeBlob struct {
	data     []byte
	modified time.Time
}

func (s *fakeStorage) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *fakeStorage) addContainer(name string, md map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if md == nil {
		md = map[string]string{}
	}
	s.containers[name] = md
}

func (s *fakeStorage) putBlob(cntr, name string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storeBlob(cntr, name, data)
}

// storeBlob needs the storage locked.
func (s *fakeStorage) storeBlob(cntr, name string, data []byte) {
	if s.blobs[cntr] == nil {
		s.blobs[cntr] = map[string]fakeBlob{}
	}
	s.blobs[cntr][name] = fakeBlob{data: data, modified: s.now}
}

func (s *fakeStorage) blob(cntr, name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[cntr][name]
	return b.data, ok
}

func (s *fakeStorage) hasContainer(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.containers[name]
	return ok
}

func (s *fakeStorage) blobNames(cntr string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.blobs[cntr]))
}

func (s *fakeStorage) metadataKeys(cntr string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.containers[cntr]))
}

func (s *fakeStorage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++

	q := r.URL.Query()
	cntr, blb, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	fail := func(status int, code string) {
		w.Header().Set("x-ms-error-code", code)
		w.WriteHeader(status)
	}

	if s.onRequest != nil {
		s.onRequest(r)
	}
	w.Header().Set("Date", s.now.Format(http.TimeFormat))
	if s.denied[r.Method+" "+r.URL.Path] {
		fail(http.StatusForbidden, "AuthorizationPermissionMismatch")
		return
	}

	if cntr == "" {
		if q.Get("comp") != "list" {
			fail(http.StatusBadRequest, "UnsupportedQueryParameter")
			return
		}
		s.listContainers(w)
		return
	}

	md, exists := s.containers[cntr]
	if blb == "" {
		switch {
		case r.Method == http.MethodPut:
			// create, or set metadata with comp=metadata
			if q.Get("comp") != "metadata" && exists {
				fail(http.StatusConflict, "ContainerAlreadyExists")
				return
			}
			if q.Get("comp") == "metadata" && !exists {
				fail(http.StatusNotFound, "ContainerNotFound")
				return
			}
			newMd := map[string]string{}
			size := 0
			for k := range r.Header {
				// incoming header names are canonicalized: X-Ms-Meta-Policy
				if name, ok := strings.CutPrefix(k, "X-Ms-Meta-"); ok {
					newMd[name] = r.Header.Get(k)
					size += len(name) + len(newMd[name])
				}
			}
			if s.metadataLimit > 0 && size > s.metadataLimit {
				fail(http.StatusBadRequest, "MetadataTooLarge")
				return
			}
			s.containers[cntr] = newMd
			if q.Get("comp") == "metadata" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusCreated)
			}
		case !exists:
			fail(http.StatusNotFound, "ContainerNotFound")
			if cntr == s.createdConcurrently {
				s.containers[cntr] = map[string]string{}
			}
		case r.Method == http.MethodDelete:
			delete(s.containers, cntr)
			delete(s.blobs, cntr)
			w.WriteHeader(http.StatusAccepted)
		case q.Get("comp") == "list":
			s.listBlobs(w, cntr)
		default:
			for k, v := range md {
				w.Header().Set("x-ms-meta-"+k, v)
			}
			w.WriteHeader(http.StatusOK)
		}
		return
	}

	if !exists {
		fail(http.StatusNotFound, "ContainerNotFound")
		return
	}
	switch r.Method {
	case http.MethodPut:
		data, err := io.ReadAll(r.Body)
		if err != nil {
			fail(http.StatusBadRequest, "InvalidInput")
			return
		}
		s.storeBlob(cntr, blb, data)
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		b, ok := s.blobs[cntr][blb]
		if !ok {
			fail(http.StatusNotFound, "BlobNotFound")
			return
		}
		//nolint:errcheck
		w.Write(b.data)
	case http.MethodDelete:
		b, ok := s.blobs[cntr][blb]
		if !ok {
			fail(http.StatusNotFound, "BlobNotFound")
			return
		}
		if v := r.Header.Get("If-Unmodified-Since"); v != "" {
			since, err := http.ParseTime(v)
			if err != nil {
				fail(http.StatusBadRequest, "InvalidHeaderValue")
				return
			}
			if b.modified.After(since) {
				fail(http.StatusPreconditionFailed, "ConditionNotMet")
				return
			}
		}
		delete(s.blobs[cntr], blb)
		w.WriteHeader(http.StatusAccepted)
	default:
		fail(http.StatusMethodNotAllowed, "UnsupportedHttpVerb")
	}
}

func (s *fakeStorage) listContainers(w http.ResponseWriter) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Containers>`)
	for _, name := range slices.Sorted(maps.Keys(s.containers)) {
		fmt.Fprintf(&body, `<Container><Name>%s</Name><Properties>`+
			`<Last-Modified>Mon, 02 Jan 2006 15:04:05 GMT</Last-Modified><Etag>0x8DEADBEEF</Etag>`+
			`</Properties><Metadata>`, name)
		for k, v := range s.containers[name] {
			fmt.Fprintf(&body, `<%s>%s</%s>`, k, v, k)
		}
		body.WriteString(`</Metadata></Container>`)
	}
	body.WriteString(`</Containers><NextMarker/></EnumerationResults>`)

	w.Header().Set("Content-Type", "application/xml")
	//nolint:errcheck
	w.Write([]byte(body.String()))
}

func (s *fakeStorage) listBlobs(w http.ResponseWriter, cntr string) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for _, name := range slices.Sorted(maps.Keys(s.blobs[cntr])) {
		fmt.Fprintf(&body, `<Blob><Name>%s</Name><Properties>`+
			`<Last-Modified>Mon, 02 Jan 2006 15:04:05 GMT</Last-Modified>`+
			`<Etag>0x8DEADBEEF</Etag><Content-Length>%d</Content-Length>`+
			`</Properties></Blob>`, name, len(s.blobs[cntr][name].data))
	}
	body.WriteString(`</Blobs><NextMarker/></EnumerationResults>`)

	w.Header().Set("Content-Type", "application/xml")
	//nolint:errcheck
	w.Write([]byte(body.String()))
}
