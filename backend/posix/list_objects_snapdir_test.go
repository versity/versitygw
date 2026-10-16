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

// TestListObjectsSkipsZFSSnapDir checks that the ZFS control directory a
// dataset exposes when it is mounted with snapdir=visible is not listed as
// bucket content. The directory shows up in readdir and its metadata reads
// fail, which used to make the whole listing fail with an InternalError. Its
// snapshot tree must not be walked either, or the listing would report the
// snapshot contents as objects.
func TestListObjectsSkipsZFSSnapDir(t *testing.T) {
	for mode, mkMeta := range map[string]func(*testing.T) (meta.MetadataStorer, PosixOpts){
		"xattr": func(*testing.T) (meta.MetadataStorer, PosixOpts) {
			return meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755, AbsolutePaths: true}
		},
		"unsupported .zfs xattr": func(*testing.T) (meta.MetadataStorer, PosixOpts) {
			return zfsSnapdirMeta{}, PosixOpts{NewDirPerm: 0755, AbsolutePaths: true}
		},
	} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			storer, opts := mkMeta(t)
			opts.VersioningDir = filepath.Join(t.TempDir(), "versions")
			if err := os.MkdirAll(opts.VersioningDir, 0755); err != nil {
				t.Fatalf("mkdir versioning dir: %v", err)
			}
			p, err := New(root, storer, opts)
			if err != nil {
				t.Fatalf("new posix: %v", err)
			}
			defer p.Shutdown()

			bucket := "snapbkt"
			createTestBucket(t, p, bucket)

			// The objects and the dataset mounted inside the bucket are
			// written to the filesystem, the way a ZFS dataset mounted
			// under the bucket appears to the gateway.
			bdir := p.BucketPath(bucket)
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

			want := []string{"child/a.txt", "top.txt"}

			t.Run("ListObjects", func(t *testing.T) {
				out, err := p.ListObjects(context.Background(), &s3.ListObjectsInput{
					Bucket: &bucket, MaxKeys: aws.Int32(1000),
				})
				if err != nil {
					t.Fatalf("list objects: %v", err)
				}
				var keys []string
				for _, obj := range out.Contents {
					keys = append(keys, aws.ToString(obj.Key))
				}
				if !equalKeys(keys, want) {
					t.Fatalf("keys = %v, want %v", keys, want)
				}
			})

			t.Run("ListObjectsV2", func(t *testing.T) {
				out, err := p.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
					Bucket: &bucket, MaxKeys: aws.Int32(1000), StartAfter: aws.String(""),
				})
				if err != nil {
					t.Fatalf("list objects v2: %v", err)
				}
				var keys []string
				for _, obj := range out.Contents {
					keys = append(keys, aws.ToString(obj.Key))
				}
				if !equalKeys(keys, want) {
					t.Fatalf("keys = %v, want %v", keys, want)
				}
			})

			t.Run("ListObjectVersions", func(t *testing.T) {
				out, err := p.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{
					Bucket: &bucket, MaxKeys: aws.Int32(1000),
				})
				if err != nil {
					t.Fatalf("list object versions: %v", err)
				}
				var keys []string
				for _, obj := range out.Versions {
					keys = append(keys, aws.ToString(obj.Key))
				}
				if !equalKeys(keys, want) {
					t.Fatalf("keys = %v, want %v", keys, want)
				}
			})
		})
	}
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
