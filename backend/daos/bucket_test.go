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
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func ownerCtx(owner string) context.Context {
	return context.WithValue(context.Background(), "bucket-owner", auth.Account{Access: owner})
}

func TestCreateBucketStoresAclAndRejectsAnExistingDirectory(t *testing.T) {
	fs := NewFake()
	d := NewWithFS(fs)
	acl, err := json.Marshal(auth.ACL{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := ownerCtx("alice")
	input := &s3.CreateBucketInput{
		Bucket:          backend.GetPtrFromString("photos"),
		ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
	}
	if err := d.CreateBucket(ctx, input, acl); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: backend.GetPtrFromString("photos")})
	if err != nil || string(got) != string(acl) {
		t.Fatalf("acl %q err %v", got, err)
	}
	own, err := d.GetBucketOwnershipControls(ctx, "photos")
	if err != nil || own != types.ObjectOwnershipBucketOwnerEnforced {
		t.Fatalf("ownership %q err %v", own, err)
	}
	if err := d.CreateBucket(ctx, input, acl); !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketAlreadyOwnedByYou, "photos")) {
		t.Fatalf("second create = %v", err)
	}
	if err := fs.Mkdir("imported"); err != nil {
		t.Fatal(err)
	}
	err = d.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: backend.GetPtrFromString("imported")}, acl)
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketAlreadyExists, "imported")) {
		t.Fatalf("imported = %v", err)
	}
	raw, err := d.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: backend.GetPtrFromString("imported")})
	if err != nil || len(raw) != 0 {
		t.Fatalf("imported acl %q err %v", raw, err)
	}
}

func TestCreateFailureRemovesTheDirectory(t *testing.T) {
	d, fs := newTest(t)
	err := d.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: backend.GetPtrFromString("wide"),
	}, bytes.Repeat([]byte("a"), maxXattrLen+1))
	if err == nil {
		t.Fatal("create succeeded")
	}
	if _, statErr := fs.Stat("wide"); !errors.Is(statErr, errNotExist) {
		t.Fatalf("wide stat = %v", statErr)
	}
}

func TestDeleteBucketLeavesTheContainer(t *testing.T) {
	d, fs := newTest(t)
	if err := fs.Mkdir("other"); err != nil {
		t.Fatal(err)
	}
	put(t, d, "keep", "x", "", nil)
	err := d.DeleteBucket(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("delete = %v", err)
	}
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("keep"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteBucket(context.Background(), "bucket"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat("other"); err != nil {
		t.Fatalf("other = %v", err)
	}
}

func TestDeleteBucketKeepsObjectPublishedDuringRemoval(t *testing.T) {
	d, fs := newTest(t)
	fs.PlantBeforeRemove("bucket/late")
	err := d.DeleteBucket(context.Background(), "bucket")
	if !errors.Is(err, s3err.GetBucketErr(s3err.ErrBucketNotEmpty, "bucket")) {
		t.Fatalf("delete = %v", err)
	}
	if _, err := fs.Stat("bucket/late"); err != nil {
		t.Fatalf("published object = %v", err)
	}
}

func TestListSkipsReservedNamesAndMissingAcl(t *testing.T) {
	fs := NewFake()
	d := NewWithFS(fs)
	acl, err := json.Marshal(auth.ACL{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := ownerCtx("alice")
	if err := d.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: backend.GetPtrFromString("photos")}, acl); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir("imported"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir(lockDirName); err != nil {
		t.Fatal(err)
	}
	if err := fs.Mkdir(versDirName); err != nil {
		t.Fatal(err)
	}
	admin, err := d.ListBuckets(ctx, s3response.ListBucketsInput{IsAdmin: true, Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(admin.Buckets.Bucket) != 2 || admin.Buckets.Bucket[0].Name != "imported" || admin.Buckets.Bucket[1].Name != "photos" {
		t.Fatalf("admin = %+v", admin.Buckets.Bucket)
	}
	mine, err := d.ListBuckets(ctx, s3response.ListBucketsInput{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mine.Buckets.Bucket) != 1 || mine.Buckets.Bucket[0].Name != "photos" {
		t.Fatalf("mine = %+v", mine.Buckets.Bucket)
	}
	if _, err := d.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: backend.GetPtrFromString("imported")}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: backend.GetPtrFromString(lockDirName)}); !errors.Is(err, s3err.GetBucketErr(s3err.ErrInvalidBucketName, lockDirName)) {
		t.Fatalf("lock head = %v", err)
	}
}

func TestBucketMetadataRoundTrip(t *testing.T) {
	d, _ := newTest(t)
	ctx := context.Background()
	policy := []byte(`{"Version":"2012-10-17"}`)
	if err := d.PutBucketPolicy(ctx, "bucket", policy); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetBucketPolicy(ctx, "bucket")
	if err != nil || string(got) != string(policy) {
		t.Fatalf("policy %q err %v", got, err)
	}
	if err := d.DeleteBucketPolicy(ctx, "bucket"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetBucketPolicy(ctx, "bucket"); !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
		t.Fatalf("missing policy = %v", err)
	}
	site := []byte("<WebsiteConfiguration></WebsiteConfiguration>")
	if err := d.PutBucketWebsite(ctx, "bucket", site); err != nil {
		t.Fatal(err)
	}
	decoded, err := d.GetBucketWebsite(ctx, "bucket")
	if err != nil || string(decoded) != string(site) {
		t.Fatalf("website %q err %v", decoded, err)
	}
	if err := d.PutBucketTagging(ctx, "bucket", map[string]string{"env": "lab"}); err != nil {
		t.Fatal(err)
	}
	tags, err := d.GetBucketTagging(ctx, "bucket")
	if err != nil || tags["env"] != "lab" {
		t.Fatalf("tags %+v err %v", tags, err)
	}
}

func TestObjectTagsAndRedirect(t *testing.T) {
	d, _ := newTest(t)
	redirect := "https://example.test/next"
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:                  backend.GetPtrFromString("bucket"),
		Key:                     backend.GetPtrFromString("obj"),
		Body:                    bytes.NewReader([]byte("hello")),
		Tagging:                 backend.GetPtrFromString("color=blue"),
		WebsiteRedirectLocation: &redirect,
		ChecksumAlgorithm:       types.ChecksumAlgorithmCrc32,
	})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := d.GetObjectTagging(context.Background(), "bucket", "obj", "")
	if err != nil || tags["color"] != "blue" {
		t.Fatalf("tags %+v err %v", tags, err)
	}
	if _, err := d.GetObjectTagging(context.Background(), "bucket", "obj", "v1"); !errors.Is(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "v1")) {
		t.Fatalf("version = %v", err)
	}
	head, err := d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil || awsString(head.WebsiteRedirectLocation) != redirect {
		t.Fatalf("redirect %q err %v", awsString(head.WebsiteRedirectLocation), err)
	}
	attrs, err := d.GetObjectAttributes(context.Background(), &s3.GetObjectAttributesInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil || awsString(attrs.ETag) == "" || attrs.ObjectSize == nil || *attrs.ObjectSize != 5 || attrs.Checksum == nil || attrs.Checksum.ChecksumCRC32 == nil {
		t.Fatalf("attrs %+v err %v", attrs, err)
	}
}

func TestChangeOwnerAndAdminList(t *testing.T) {
	fs := NewFake()
	d := NewWithFS(fs)
	acl, err := json.Marshal(auth.ACL{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateBucket(ownerCtx("alice"), &s3.CreateBucketInput{Bucket: backend.GetPtrFromString("photos")}, acl); err != nil {
		t.Fatal(err)
	}
	if err := d.ChangeBucketOwner(context.Background(), "photos", "bob"); err != nil {
		t.Fatal(err)
	}
	owners, err := d.ListBucketsAndOwners(context.Background())
	if err != nil || len(owners) != 1 || owners[0].Name != "photos" || owners[0].Owner != "bob" {
		t.Fatalf("owners %+v err %v", owners, err)
	}
}

func TestMultipartCreateCopiesTagging(t *testing.T) {
	d, _ := newTest(t)
	tagging := "color=blue"
	redirect := "https://example.test/next"
	created, err := d.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket:                  backend.GetPtrFromString("bucket"),
		Key:                     backend.GetPtrFromString("photos/a.jpg"),
		Tagging:                 &tagging,
		WebsiteRedirectLocation: &redirect,
	})
	if err != nil {
		t.Fatal(err)
	}
	etag := uploadPart(t, d, "photos/a.jpg", created.UploadId, 1, "hello")
	if _, _, err := d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("photos/a.jpg"),
		UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
			{PartNumber: int32ptr(1), ETag: &etag},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	tags, err := d.GetObjectTagging(context.Background(), "bucket", "photos/a.jpg", "")
	if err != nil || tags["color"] != "blue" {
		t.Fatalf("tags %+v err %v", tags, err)
	}
	head, err := d.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("photos/a.jpg"),
	})
	if err != nil || awsString(head.WebsiteRedirectLocation) != redirect {
		t.Fatalf("redirect %q err %v", awsString(head.WebsiteRedirectLocation), err)
	}
	if strings.Contains(created.UploadId, " ") {
		t.Fatal(created.UploadId)
	}
}
