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

package posix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// zfsSnapDir is the control directory a ZFS dataset exposes when it is mounted
// with snapdir=visible. Nothing in the backend knows this name; it is only a
// value an operator passes in PosixOpts.ExcludeDirs.
const zfsSnapDir = ".zfs"

const snapBucket = "snapbkt"

// zfsSnapdirMeta stands in for a ZFS dataset mounted with snapdir=visible:
// extended attributes work everywhere except under the .zfs control
// directory, where reads fail with EOPNOTSUPP as they do on FreeBSD.
type zfsSnapdirMeta struct{ meta.XattrMeta }

func (m zfsSnapdirMeta) WithRootDir(rootdir string) meta.MetadataStorer {
	m.XattrMeta = m.XattrMeta.WithRootDir(rootdir).(meta.XattrMeta)
	return m
}

func (m zfsSnapdirMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	for _, seg := range strings.Split(object, "/") {
		if seg == zfsSnapDir {
			return nil, syscall.ENOTSUP
		}
	}
	return m.XattrMeta.RetrieveAttribute(f, bucket, object, attribute)
}

// newSnapdirBackend returns a posix backend whose bucket holds two objects and
// a .zfs snapshot tree, the way a dataset mounted under the bucket appears to
// the gateway.
func newSnapdirBackend(t *testing.T, storer meta.MetadataStorer, excludeDirs []string) *Posix {
	t.Helper()

	opts := PosixOpts{NewDirPerm: 0755, AbsolutePaths: true, ExcludeDirs: excludeDirs}
	opts.VersioningDir = filepath.Join(t.TempDir(), "versions")
	if err := os.MkdirAll(opts.VersioningDir, 0755); err != nil {
		t.Fatalf("mkdir versioning dir: %v", err)
	}
	p, err := New(t.TempDir(), storer, opts)
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	t.Cleanup(p.Shutdown)

	createTestBucket(t, p, snapBucket)

	writeBucketFiles(t, p, map[string]string{
		"top.txt":                          "top",
		"child/a.txt":                      "a",
		"child/.zfs/snapshot/one/snap.txt": "snap",
	})
	return p
}

// writeBucketFiles writes files, keyed by their slash-separated path in the
// bucket, straight to the bucket directory.
func writeBucketFiles(t *testing.T, p *Posix, files map[string]string) {
	t.Helper()

	bdir := p.BucketPath(snapBucket)
	for name, data := range files {
		full := filepath.Join(bdir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir %q: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
}

func listObjectsKeys(p *Posix) ([]string, error) {
	out, err := p.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket: aws.String(snapBucket), MaxKeys: aws.Int32(1000),
	})
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, obj := range out.Contents {
		keys = append(keys, aws.ToString(obj.Key))
	}
	return keys, nil
}

func listObjectsV2Keys(p *Posix) ([]string, error) {
	out, err := p.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(snapBucket), MaxKeys: aws.Int32(1000), StartAfter: aws.String(""),
	})
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, obj := range out.Contents {
		keys = append(keys, aws.ToString(obj.Key))
	}
	return keys, nil
}

func listObjectVersionsKeys(p *Posix) ([]string, error) {
	out, err := p.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{
		Bucket: aws.String(snapBucket), MaxKeys: aws.Int32(1000),
	})
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, obj := range out.Versions {
		keys = append(keys, aws.ToString(obj.Key))
	}
	return keys, nil
}

type listOp struct {
	name string
	list func(*Posix) ([]string, error)
}

// listOps are the three listing operations that share the skip list.
var listOps = []listOp{
	{"ListObjects", listObjectsKeys},
	{"ListObjectsV2", listObjectsV2Keys},
	{"ListObjectVersions", listObjectVersionsKeys},
}

type metaMode struct {
	name   string
	storer func() meta.MetadataStorer
}

var snapdirMetaModes = []metaMode{
	{"xattr", func() meta.MetadataStorer { return meta.XattrMeta{} }},
	{"unsupported .zfs xattr", func() meta.MetadataStorer { return zfsSnapdirMeta{} }},
}

// TestListObjectsSkipsZFSSnapDir checks that a control directory named in
// PosixOpts.ExcludeDirs is not listed as bucket content and is not walked.
// The directory shows up in readdir and its metadata reads fail, which used to
// make the whole listing fail with an InternalError. Its snapshot tree must
// not be walked either, or the listing would report the snapshot contents as
// objects. All three listing operations share the same list.
func TestListObjectsSkipsZFSSnapDir(t *testing.T) {
	for _, mode := range snapdirMetaModes {
		t.Run(mode.name, func(t *testing.T) {
			p := newSnapdirBackend(t, mode.storer(), []string{zfsSnapDir})

			want := []string{"child/a.txt", "top.txt"}
			for _, op := range listOps {
				keys, err := op.list(p)
				if err != nil {
					t.Fatalf("%s: %v", op.name, err)
				}
				if !equalKeys(keys, want) {
					t.Fatalf("%s: keys = %v, want %v", op.name, keys, want)
				}
			}
		})
	}
}

// TestListObjectsExcludeDirsEmpty covers the default of an empty
// PosixOpts.ExcludeDirs: .zfs is ordinary content, so a plain xattr store
// reports the snapshot tree and a store that cannot read its xattrs fails the
// listing. That failure is the InternalError the option exists to avoid.
func TestListObjectsExcludeDirsEmpty(t *testing.T) {
	t.Run("xattr", func(t *testing.T) {
		p := newSnapdirBackend(t, meta.XattrMeta{}, nil)

		for _, op := range listOps {
			keys, err := op.list(p)
			if err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if !containsKey(keys, "child/.zfs/snapshot/one/snap.txt") {
				t.Fatalf("%s: keys = %v, want the .zfs snapshot object to be listed", op.name, keys)
			}
		}
	})

	t.Run("unsupported .zfs xattr", func(t *testing.T) {
		p := newSnapdirBackend(t, zfsSnapdirMeta{}, nil)

		for _, op := range listOps {
			if _, err := op.list(p); err == nil {
				t.Fatalf("%s succeeded, want the .zfs metadata error", op.name)
			}
		}
	})
}

// TestListObjectsExcludeDirsFileNotSkipped checks that only directories are
// excluded. A regular file with an excluded name is an ordinary object: it is
// listed, and it does not hide the objects that sort after it in the same
// directory, which ListObjectVersions used to drop.
func TestListObjectsExcludeDirsFileNotSkipped(t *testing.T) {
	p := newSnapdirBackend(t, meta.XattrMeta{}, []string{zfsSnapDir})
	writeBucketFiles(t, p, map[string]string{
		"d/" + zfsSnapDir: "file",
		"d/b.txt":         "b",
		"d/c.txt":         "c",
	})

	want := []string{"child/a.txt", "d/" + zfsSnapDir, "d/b.txt", "d/c.txt", "top.txt"}
	for _, op := range listOps {
		keys, err := op.list(p)
		if err != nil {
			t.Fatalf("%s: %v", op.name, err)
		}
		if !equalKeys(keys, want) {
			t.Errorf("%s: keys = %v, want %v", op.name, keys, want)
		}
	}
}

// TestListingSkipDirs checks the directories the walks receive: the metadata
// directory is skipped at the bucket root only, the excluded directories at
// any depth, and an excluded directory that could never match a directory
// entry name is rejected instead of silently doing nothing.
func TestListingSkipDirs(t *testing.T) {
	got, err := listingSkipDirs([]string{zfsSnapDir})
	if err != nil {
		t.Fatalf("listing skip dirs: %v", err)
	}
	if want := []string{MetaTmpDir}; !equalKeys(got.Root, want) {
		t.Errorf("root skip dirs = %v, want %v", got.Root, want)
	}
	if want := []string{zfsSnapDir}; !equalKeys(got.Any, want) {
		t.Errorf("any-depth skip dirs = %v, want %v", got.Any, want)
	}

	for _, dir := range []string{"", ".", "..", "child/.zfs"} {
		if _, err := listingSkipDirs([]string{dir}); err == nil {
			t.Errorf("listingSkipDirs(%q) succeeded, want an error", dir)
		}
	}
}

// TestListObjectsNestedMetaTmpDir checks that only the metadata directory at
// the bucket root is hidden. The gateway never creates one further down, so a
// nested .sgwtmp directory holds objects a client stored there, which object
// requests accept and so the listings must report.
func TestListObjectsNestedMetaTmpDir(t *testing.T) {
	ctx := context.Background()
	bucket := snapBucket
	key := "d/" + MetaTmpDir + "/x"

	p := newSnapdirBackend(t, meta.XattrMeta{}, []string{zfsSnapDir})
	if err := putTestObject(t, p, bucket, key, "data"); err != nil {
		t.Fatalf("PutObject %q: %v", key, err)
	}
	if _, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key}); err != nil {
		t.Fatalf("HeadObject %q: %v", key, err)
	}
	writeBucketFiles(t, p, map[string]string{MetaTmpDir + "/stray": "tmp"})

	want := []string{"child/a.txt", key, "top.txt"}
	for _, op := range listOps {
		keys, err := op.list(p)
		if err != nil {
			t.Fatalf("%s: %v", op.name, err)
		}
		if !equalKeys(keys, want) {
			t.Errorf("%s: keys = %v, want %v", op.name, keys, want)
		}
	}
}

// TestExcludeDirsCaseAgrees checks that the listings and object requests
// match an excluded name the same way, ignoring case: a directory spelled in
// another case is neither listed nor reachable, rather than listed with
// objects that can't be read.
func TestExcludeDirsCaseAgrees(t *testing.T) {
	ctx := context.Background()
	bucket := snapBucket
	key := "e/.ZFS/x"

	p := newSnapdirBackend(t, meta.XattrMeta{}, []string{zfsSnapDir})
	writeBucketFiles(t, p, map[string]string{key: "x"})

	want := []string{"child/a.txt", "top.txt"}
	for _, op := range listOps {
		keys, err := op.list(p)
		if err != nil {
			t.Fatalf("%s: %v", op.name, err)
		}
		if !equalKeys(keys, want) {
			t.Errorf("%s: keys = %v, want %v", op.name, keys, want)
		}
	}

	_, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrExcludedObjectKey)) {
		t.Errorf("HeadObject %q: got %v, want ReservedObjectKey", key, err)
	}
}

// TestExcludedDirKeysReserved checks that object requests can't reach a path
// under an excluded directory. The listings never show objects there, and on
// ZFS the .zfs directory, reachable by name even with snapdir=hidden, would
// serve snapshot contents under keys that policies on the live keys don't
// cover.
func TestExcludedDirKeysReserved(t *testing.T) {
	ctx := context.Background()
	reserved := s3err.GetAPIError(s3err.ErrExcludedObjectKey)
	bucket := snapBucket
	snapKey := "child/.zfs/snapshot/one/snap.txt"

	p := newSnapdirBackend(t, meta.XattrMeta{}, []string{zfsSnapDir})
	snapPath := filepath.Join(p.BucketPath(bucket), filepath.FromSlash(snapKey))

	for _, key := range []string{
		snapKey,
		"child/.zfs/",
		"child/.ZFS/snapshot/one/snap.txt",
		"child/x/../.zfs/snapshot/one/snap.txt",
		"child//.zfs/snapshot/one/snap.txt",
		".zfs/a",
		"child/a.txt/../.zfs/snapshot/one/snap.txt",
	} {
		_, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: aws.String(key)})
		if !errors.Is(err, reserved) {
			t.Errorf("HeadObject %q: got %v, want ReservedObjectKey", key, err)
		}
	}

	if _, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &snapKey}); !errors.Is(err, reserved) {
		t.Errorf("GetObject: got %v, want ReservedObjectKey", err)
	}

	for _, key := range []string{"child/.zfs/new.txt", "child/.zfs/snapshot/two/", "child/.zfs/"} {
		if err := putTestObject(t, p, bucket, key, ""); !errors.Is(err, reserved) {
			t.Errorf("PutObject %q: got %v, want ReservedObjectKey", key, err)
		}
	}
	if _, err := os.Stat(filepath.Join(p.BucketPath(bucket), "child", zfsSnapDir, "new.txt")); !os.IsNotExist(err) {
		t.Errorf("PutObject created an object under the excluded directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.BucketPath(bucket), "child", zfsSnapDir, "snapshot", "two")); !os.IsNotExist(err) {
		t.Errorf("PutObject created a directory under the excluded directory: %v", err)
	}

	if _, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &snapKey}); !errors.Is(err, reserved) {
		t.Errorf("DeleteObject: got %v, want ReservedObjectKey", err)
	}
	if _, err := os.Stat(snapPath); err != nil {
		t.Errorf("DeleteObject removed the object under the excluded directory: %v", err)
	}

	_, err := p.CopyObject(ctx, s3response.CopyObjectInput{
		Bucket:              &bucket,
		Key:                 aws.String("copied.txt"),
		CopySource:          aws.String(bucket + "/" + snapKey),
		ExpectedBucketOwner: aws.String(""),
	})
	if !errors.Is(err, reserved) {
		t.Errorf("CopyObject from excluded directory: got %v, want ReservedObjectKey", err)
	}
	_, err = p.CopyObject(ctx, s3response.CopyObjectInput{
		Bucket:              &bucket,
		Key:                 aws.String("child/.zfs/copied.txt"),
		CopySource:          aws.String(bucket + "/top.txt"),
		ExpectedBucketOwner: aws.String(""),
	})
	if !errors.Is(err, reserved) {
		t.Errorf("CopyObject into excluded directory: got %v, want ReservedObjectKey", err)
	}

	_, err = p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: aws.String("child/.zfs/mp.txt"),
	})
	if !errors.Is(err, reserved) {
		t.Errorf("CreateMultipartUpload: got %v, want ReservedObjectKey", err)
	}

	// A file with an excluded name is an ordinary object, as the listings
	// report it, and so are keys that only resemble the excluded name.
	for _, key := range []string{"d/" + zfsSnapDir, "child/.zfsx/a", "child/x.zfs/a"} {
		if err := putTestObject(t, p, bucket, key, "data"); err != nil {
			t.Errorf("PutObject %q: %v", key, err)
			continue
		}
		if _, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: aws.String(key)}); err != nil {
			t.Errorf("HeadObject %q: %v", key, err)
		}
	}
}

// TestExcludeDirsEmptyKeysAllowed checks the default: without ExcludeDirs,
// .zfs is an ordinary name and its objects can be read.
func TestExcludeDirsEmptyKeysAllowed(t *testing.T) {
	bucket := snapBucket
	p := newSnapdirBackend(t, meta.XattrMeta{}, nil)

	_, err := p.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: &bucket, Key: aws.String("child/.zfs/snapshot/one/snap.txt"),
	})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
}

func containsKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func equalKeys(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestExcludedDirBucketRejected checks that an excluded name is not a bucket,
// even with relaxed bucket names. On ZFS a bucket named .zfs at a dataset root
// would otherwise serve snapshot contents through keys with no excluded
// element of their own.
func TestExcludedDirBucketRejected(t *testing.T) {
	ctx := context.Background()
	invalid := s3err.GetAPIError(s3err.ErrInvalidBucketName)

	sidecar := t.TempDir()
	sc, err := meta.NewSideCar(sidecar)
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	root := t.TempDir()
	p, err := New(root, sc, PosixOpts{
		NewDirPerm:    0755,
		AbsolutePaths: true,
		SideCarDir:    sidecar,
		ExcludeDirs:   []string{zfsSnapDir},
	})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	t.Cleanup(p.Shutdown)

	createTestBucket(t, p, "bkt")
	snapKey := "snapshot/s1/bkt/private/secret.txt"
	snapFile := filepath.Join(root, zfsSnapDir, filepath.FromSlash(snapKey))
	if err := os.MkdirAll(filepath.Dir(snapFile), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(snapFile, []byte("secret"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, bucket := range []string{zfsSnapDir, strings.ToUpper(zfsSnapDir)} {
		if p.IsBucketValid(bucket) {
			t.Errorf("IsBucketValid(%q) = true, want false", bucket)
		}
		if _, err := p.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket}); !errors.Is(err, invalid) {
			t.Errorf("HeadBucket %q: got %v, want InvalidBucketName", bucket, err)
		}
		// Rejected before the ACL is read, which fails on a ZFS control
		// directory with xattr metadata.
		if _, err := p.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket}); !errors.Is(err, invalid) {
			t.Errorf("GetBucketAcl %q: got %v, want InvalidBucketName", bucket, err)
		}
		if _, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &snapKey}); !errors.Is(err, invalid) {
			t.Errorf("HeadObject %q: got %v, want InvalidBucketName", bucket, err)
		}
		if _, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &snapKey}); !errors.Is(err, invalid) {
			t.Errorf("GetObject %q: got %v, want InvalidBucketName", bucket, err)
		}
		if err := putTestObject(t, p, bucket, "new.txt", "x"); !errors.Is(err, invalid) {
			t.Errorf("PutObject %q: got %v, want InvalidBucketName", bucket, err)
		}
		err := p.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket:                    &bucket,
			CreateBucketConfiguration: &types.CreateBucketConfiguration{},
		}, []byte{})
		if !errors.Is(err, invalid) {
			t.Errorf("CreateBucket %q: got %v, want InvalidBucketName", bucket, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, zfsSnapDir, "new.txt")); !os.IsNotExist(err) {
		t.Errorf("PutObject created an object in the excluded directory: %v", err)
	}

	out, err := p.ListBuckets(ctx, s3response.ListBucketsInput{IsAdmin: true, MaxBuckets: 1000})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	var names []string
	for _, b := range out.Buckets.Bucket {
		names = append(names, b.Name)
	}
	if !equalKeys(names, []string{"bkt"}) {
		t.Errorf("ListBuckets: got %v, want [bkt]", names)
	}

	owners, err := p.ListBucketsAndOwners(ctx)
	if err != nil {
		t.Fatalf("ListBucketsAndOwners: %v", err)
	}
	names = nil
	for _, b := range owners {
		names = append(names, b.Name)
	}
	if !equalKeys(names, []string{"bkt"}) {
		t.Errorf("ListBucketsAndOwners: got %v, want [bkt]", names)
	}
}
