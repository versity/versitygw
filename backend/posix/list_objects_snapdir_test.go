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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend/meta"
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

	bdir := p.BucketPath(snapBucket)
	for name, data := range map[string]string{
		"top.txt":                          "top",
		"child/a.txt":                      "a",
		"child/.zfs/snapshot/one/snap.txt": "snap",
	} {
		full := filepath.Join(bdir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir %q: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	return p
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

// TestListObjectsSkipsZFSSnapDir checks that a control directory named in
// PosixOpts.ExcludeDirs is not listed as bucket content and is not walked.
// The directory shows up in readdir and its metadata reads fail, which used to
// make the whole listing fail with an InternalError. Its snapshot tree must
// not be walked either, or the listing would report the snapshot contents as
// objects. All three listing operations share the same list.
func TestListObjectsSkipsZFSSnapDir(t *testing.T) {
	for mode, mkMeta := range map[string]func() meta.MetadataStorer{
		"xattr":                  func() meta.MetadataStorer { return meta.XattrMeta{} },
		"unsupported .zfs xattr": func() meta.MetadataStorer { return zfsSnapdirMeta{} },
	} {
		t.Run(mode, func(t *testing.T) {
			p := newSnapdirBackend(t, mkMeta(), []string{zfsSnapDir})

			want := []string{"child/a.txt", "top.txt"}
			for name, list := range map[string]func() ([]string, error){
				"ListObjects":        func() ([]string, error) { return listObjectsKeys(p) },
				"ListObjectsV2":      func() ([]string, error) { return listObjectsV2Keys(p) },
				"ListObjectVersions": func() ([]string, error) { return listObjectVersionsKeys(p) },
			} {
				keys, err := list()
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if !equalKeys(keys, want) {
					t.Fatalf("%s: keys = %v, want %v", name, keys, want)
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

		keys, err := listObjectsKeys(p)
		if err != nil {
			t.Fatalf("list objects: %v", err)
		}
		if !containsKey(keys, "child/.zfs/snapshot/one/snap.txt") {
			t.Fatalf("keys = %v, want the .zfs snapshot object to be listed", keys)
		}
	})

	t.Run("unsupported .zfs xattr", func(t *testing.T) {
		p := newSnapdirBackend(t, zfsSnapdirMeta{}, nil)

		if _, err := listObjectsKeys(p); err == nil {
			t.Fatal("list objects succeeded, want the .zfs metadata error")
		}
	})
}

// TestListingSkipDirs checks the list the walks receive: the metadata
// directory is always skipped, and an excluded directory that could never
// match a directory entry name is rejected instead of silently doing nothing.
func TestListingSkipDirs(t *testing.T) {
	got, err := listingSkipDirs([]string{zfsSnapDir})
	if err != nil {
		t.Fatalf("listing skip dirs: %v", err)
	}
	if want := []string{MetaTmpDir, zfsSnapDir}; !equalKeys(got, want) {
		t.Fatalf("skip dirs = %v, want %v", got, want)
	}

	for _, dir := range []string{"", "child/.zfs"} {
		if _, err := listingSkipDirs([]string{dir}); err == nil {
			t.Errorf("listingSkipDirs(%q) succeeded, want an error", dir)
		}
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
