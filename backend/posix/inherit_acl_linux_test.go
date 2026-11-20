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

//go:build linux

package posix

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend/meta"
	"golang.org/x/sys/unix"
)

const (
	aclAccessXattr = "system.posix_acl_access"

	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclMask     = 0x10
	aclOther    = 0x20

	aclTestUID = 65534
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// testDefaultACL is the xattr value of the ACL
// user::rwx,user:65534:r--,group::r-x,mask::r-x,other::r-x
func testDefaultACL() []byte {
	return encodeACL([]aclEntry{
		{aclUserObj, 7, 0xffffffff},
		{aclUser, 4, aclTestUID},
		{aclGroupObj, 5, 0xffffffff},
		{aclMask, 5, 0xffffffff},
		{aclOther, 5, 0xffffffff},
	})
}

func encodeACL(entries []aclEntry) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

// skipWithoutOTmpfile skips the test when the filesystem of dir does not
// support O_TMPFILE: the temporary file is then made in the bucket's
// metadata directory and no default ACL applies to it.
func skipWithoutOTmpfile(t *testing.T, dir string) {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Skipf("filesystem does not support O_TMPFILE: %v", err)
	}
	unix.Close(fd)
}

// hasNamedUser reports whether the access ACL of path has an entry for uid.
func hasNamedUser(t *testing.T, path string, uid uint32) bool {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, aclAccessXattr, buf)
	if errors.Is(err, unix.ENODATA) {
		return false
	}
	if err != nil {
		t.Fatalf("get access ACL of %v: %v", path, err)
	}
	for b := buf[4:n]; len(b) >= 8; b = b[8:] {
		if binary.LittleEndian.Uint16(b) == aclUser && binary.LittleEndian.Uint32(b[4:]) == uid {
			return true
		}
	}
	return false
}

// TestInheritDefaultACL checks that with InheritDefaultACL a new object gets
// the default ACL of the directory it is published in, also when that
// directory is made by the PUT and when the object replaces a file, and
// that without it the object gets no ACL.
func TestInheritDefaultACL(t *testing.T) {
	for _, inherit := range []bool{false, true} {
		name := "default"
		if inherit {
			name = "inherit"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			p, err := New(root, meta.XattrMeta{}, PosixOpts{
				AbsolutePaths:     true,
				InheritDefaultACL: inherit,
			})
			if err != nil {
				t.Fatalf("new posix: %v", err)
			}
			bucket := "bucket"
			createTestBucket(t, p, bucket)

			dir := filepath.Join(root, bucket, "share")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatalf("make dir: %v", err)
			}
			err = unix.Setxattr(dir, aclDefaultXattr, testDefaultACL(), 0)
			if errors.Is(err, syscall.EOPNOTSUPP) {
				t.Skip("filesystem does not support POSIX ACLs")
			}
			if err != nil {
				t.Fatalf("set default ACL: %v", err)
			}
			if inherit {
				skipWithoutOTmpfile(t, dir)
			}

			for _, key := range []string{
				"share/object",         // in the directory
				"share/object",         // replacing the file
				"share/new/dir/object", // in directories the PUT makes
			} {
				if err := putTestObject(t, p, bucket, key, "hello"); err != nil {
					t.Fatalf("put %v: %v", key, err)
				}
				got := hasNamedUser(t, filepath.Join(root, bucket, key), aclTestUID)
				if got != inherit {
					t.Fatalf("%v has the inherited ACL entry: %v, want %v", key, got, inherit)
				}
			}

			// nothing but the objects and the directories is left behind
			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("read dir: %v", err)
			}
			if len(ents) != 2 {
				names := []string{}
				for _, e := range ents {
					names = append(names, e.Name())
				}
				t.Fatalf("dir has %v, want object and new", names)
			}
		})
	}
}

// TestInheritDefaultACLWithoutOTmpfile checks that with O_TMPFILE disabled
// the named temporary file is still made in the bucket's metadata directory
// and never in the directory of the object.
func TestInheritDefaultACLWithoutOTmpfile(t *testing.T) {
	root := t.TempDir()
	p, err := New(root, meta.XattrMeta{}, PosixOpts{
		AbsolutePaths:     true,
		InheritDefaultACL: true,
		ForceNoTmpFile:    true,
	})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	bucket := "bucket"
	createTestBucket(t, p, bucket)

	f, err := p.openObjectTmpFile(bucket, "a/object", 5, auth.Account{}, false, odirectNotAllowed)
	if err != nil {
		t.Fatalf("open tmp file: %v", err)
	}
	defer f.cleanup()

	want := filepath.Join(root, bucket, MetaTmpDir)
	if got := filepath.Dir(f.File().Name()); got != want {
		t.Fatalf("temp file made in %v, want %v", got, want)
	}
}

// TestClosestDir checks the directory an O_TMPFILE is made in when the
// directory of the object does not exist yet.
func TestClosestDir(t *testing.T) {
	root := t.TempDir()
	bucket := filepath.Join(root, "bucket")
	if err := os.MkdirAll(filepath.Join(bucket, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bucket, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ dir, want string }{
		{"a/b", "a/b"},
		{"a/b/c/d", "a/b"},
		{"x/y", ""},
		{"", ""},
		// a file where a directory is expected: the PUT fails later
		{"file/c", ""},
	}
	for _, tc := range cases {
		got, err := closestDir(bucket, filepath.Join(bucket, tc.dir))
		if want := filepath.Join(bucket, tc.want); err != nil || got != want {
			t.Errorf("closestDir(%q) = %v, %v, want %v", tc.dir, got, err, want)
		}
	}

	// the default bucket path is relative to the root directory
	t.Chdir(root)
	for _, tc := range cases {
		got, err := closestDir("bucket", filepath.Join("bucket", tc.dir))
		if want := filepath.Join("bucket", tc.want); err != nil || got != want {
			t.Errorf("relative closestDir(%q) = %v, %v, want %v", tc.dir, got, err, want)
		}
	}

	if got, err := closestDir(bucket, filepath.Join(bucket, "..", "other")); err == nil {
		t.Errorf("closestDir outside the bucket = %v, want an error", got)
	}

	if os.Geteuid() != 0 {
		// a directory that can't be searched is not skipped
		a := filepath.Join(bucket, "a")
		if err := os.Chmod(a, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(a, 0o755)
		if got, err := closestDir(bucket, filepath.Join(a, "b", "c")); !errors.Is(err, syscall.EACCES) {
			t.Errorf("closestDir below an unsearchable dir = %v, %v, want EACCES", got, err)
		}
	}
}

// TestInheritDefaultACLMode checks that with InheritDefaultACL an object in a
// directory with a default ACL keeps the group and other permissions the ACL
// gives it, even when the ACL is narrower than NewFilePerm, and that without
// a default ACL the object still gets NewFilePerm.
func TestInheritDefaultACLMode(t *testing.T) {
	root := t.TempDir()
	p, err := New(root, meta.XattrMeta{}, PosixOpts{
		AbsolutePaths:     true,
		InheritDefaultACL: true,
	})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	bucket := "bucket"
	createTestBucket(t, p, bucket)

	dir := filepath.Join(root, bucket, "private")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("make dir: %v", err)
	}
	// user::rw-,group::r--,other::---: a minimal ACL, which the kernel
	// applies to the mode of new files without giving them an access ACL
	err = unix.Setxattr(dir, aclDefaultXattr, encodeACL([]aclEntry{
		{aclUserObj, 6, 0xffffffff},
		{aclGroupObj, 4, 0xffffffff},
		{aclOther, 0, 0xffffffff},
	}), 0)
	if errors.Is(err, syscall.EOPNOTSUPP) {
		t.Skip("filesystem does not support POSIX ACLs")
	}
	if err != nil {
		t.Fatalf("set default ACL: %v", err)
	}
	skipWithoutOTmpfile(t, dir)

	for key, want := range map[string]os.FileMode{
		"private/object": 0o640,
		"plain/object":   0o644,
	} {
		if err := putTestObject(t, p, bucket, key, "hello"); err != nil {
			t.Fatalf("put %v: %v", key, err)
		}
		fi, err := os.Stat(filepath.Join(root, bucket, key))
		if err != nil {
			t.Fatalf("stat %v: %v", key, err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%v has mode %o, want %o", key, got, want)
		}
	}
}

// setDefaultACL sets the default ACL of dir, skipping the test when the
// filesystem does not support ACLs or O_TMPFILE.
func setDefaultACL(t *testing.T, dir string, acl []byte) {
	t.Helper()
	err := unix.Setxattr(dir, aclDefaultXattr, acl, 0)
	if errors.Is(err, syscall.EOPNOTSUPP) {
		t.Skip("filesystem does not support POSIX ACLs")
	}
	if err != nil {
		t.Fatalf("set default ACL: %v", err)
	}
	skipWithoutOTmpfile(t, dir)
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %v: %v", path, err)
	}
	return fi.Mode().Perm()
}

// readOnlyOwnerACL is the ACL user::r--,user:65534:r--,group::r--,mask::r--,
// other::r--, which gives the owner of a new file no write permission
func readOnlyOwnerACL() []aclEntry {
	return []aclEntry{
		{aclUserObj, 4, 0xffffffff},
		{aclUser, 4, aclTestUID},
		{aclGroupObj, 4, 0xffffffff},
		{aclMask, 4, 0xffffffff},
		{aclOther, 4, 0xffffffff},
	}
}

// TestInheritDefaultACLOwner checks that an object in a directory whose
// default ACL gives the owner no write permission still gets the owner
// permissions of NewFilePerm, so that the gateway can write its attributes,
// both for a PUT and for the restore of a version, which writes them after
// the object is published. The named entry and the mask the ACL gave the
// object are kept. Run as a user other than root to check the attributes
// are written: root can write them to a read-only file.
func TestInheritDefaultACLOwner(t *testing.T) {
	ctx := context.Background()
	p := newVersionedTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket, key := "bucket", "share/object"
	createTestBucket(t, p, bucket)
	if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}
	dir := filepath.Join(p.BucketPath(bucket), "share")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("make dir: %v", err)
	}
	setDefaultACL(t, dir, encodeACL(readOnlyOwnerACL()))
	path := filepath.Join(dir, "object")

	check := func(wantBody, wantEtag string) {
		t.Helper()
		if got := fileMode(t, path); got != 0o644 {
			t.Errorf("object has mode %o, want 644", got)
		}
		if !hasNamedUser(t, path, aclTestUID) {
			t.Errorf("object lost the inherited ACL entry")
		}
		body, etag := getTestObject(t, p, bucket, key)
		if string(body) != wantBody || etag != wantEtag {
			t.Errorf("object is %q with etag %v, want %q with etag %v", body, etag, wantBody, wantEtag)
		}
	}

	v1, err := testPut(p, bucket, key, []byte("v1"), nil, nil)
	if err != nil {
		t.Fatalf("put v1: %v", err)
	}
	check("v1", v1.ETag)
	v2, err := testPut(p, bucket, key, []byte("v2"), nil, nil)
	if err != nil {
		t.Fatalf("put v2: %v", err)
	}
	check("v2", v2.ETag)

	// deleting the latest version restores v1 in place
	_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:    &bucket,
		Key:       &key,
		VersionId: &v2.VersionID,
	})
	if err != nil {
		t.Fatalf("delete latest version: %v", err)
	}
	check("v1", v1.ETag)
}

// TestInheritDefaultACLMultipart checks that an object made by
// CompleteMultipartUpload gets the default ACL of its directory, and that
// its parts, which are not objects, keep NewFilePerm.
func TestInheritDefaultACLMultipart(t *testing.T) {
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	dir := filepath.Join(p.BucketPath(bucket), "share")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("make dir: %v", err)
	}
	setDefaultACL(t, dir, testDefaultACL())

	body := bytes.Repeat([]byte("x"), 1024)
	_, complete := testCompleteMultipart(t, p, bucket, "share/mp", body, nil, nil)
	if _, err := complete(); err != nil {
		t.Fatalf("complete multipart upload: %v", err)
	}
	path := filepath.Join(dir, "mp")
	if !hasNamedUser(t, path, aclTestUID) {
		t.Errorf("multipart object has no inherited ACL entry")
	}
	got, _ := getTestObject(t, p, bucket, "share/mp")
	if !bytes.Equal(got, body) {
		t.Errorf("multipart object has the wrong content")
	}
}

// TestInheritDefaultACLTempFiles checks that a temporary file that is not
// published as an object, such as a multipart part, gets NewFilePerm even in
// a directory with a default ACL.
func TestInheritDefaultACLTempFiles(t *testing.T) {
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	dir := filepath.Join(p.BucketPath(bucket), "parts")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("make dir: %v", err)
	}
	// user::rw-,group::---,other::---
	setDefaultACL(t, dir, encodeACL([]aclEntry{
		{aclUserObj, 6, 0xffffffff},
		{aclGroupObj, 0, 0xffffffff},
		{aclOther, 0, 0xffffffff},
	}))

	f, err := p.openTmpFile(dir, bucket, "part", 0, auth.Account{}, false, odirectNotAllowed)
	if err != nil {
		t.Fatalf("open tmp file: %v", err)
	}
	defer f.cleanup()
	fi, err := f.File().Stat()
	if err != nil {
		t.Fatalf("stat tmp file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("temp file has mode %o, want 644", got)
	}
}

// TestInheritDefaultACLKeepsDir checks that with InheritDefaultACL deleting
// the last object of a directory with a default ACL keeps the directory, so
// that the next object still gets its ACL, and that other directories are
// still removed.
func TestInheritDefaultACLKeepsDir(t *testing.T) {
	for _, inherit := range []bool{false, true} {
		name := "default"
		if inherit {
			name = "inherit"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: inherit}
			})
			bucket := "bucket"
			createTestBucket(t, p, bucket)
			share := filepath.Join(p.BucketPath(bucket), "team", "share")
			if err := os.MkdirAll(share, 0o755); err != nil {
				t.Fatalf("make dir: %v", err)
			}
			setDefaultACL(t, share, testDefaultACL())

			for _, key := range []string{"team/share/a", "plain/a"} {
				if err := putTestObject(t, p, bucket, key, "a"); err != nil {
					t.Fatalf("put %v: %v", key, err)
				}
				_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: aws.String(key)})
				if err != nil {
					t.Fatalf("delete %v: %v", key, err)
				}
			}

			_, err := os.Stat(share)
			if kept := err == nil; kept != inherit {
				t.Errorf("dir with a default ACL kept: %v, want %v", kept, inherit)
			}
			if _, err := os.Stat(filepath.Join(p.BucketPath(bucket), "plain")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("dir without a default ACL was not removed: %v", err)
			}
		})
	}
}

// TestInheritDefaultACLBucketACL checks that with a default ACL on the bucket
// directory, which mkdir copies to every directory the gateway makes, those
// directories are still removed with their last object, and that only a
// directory with an ACL of its own is kept.
func TestInheritDefaultACLBucketACL(t *testing.T) {
	ctx := context.Background()
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true}
	})
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	bucketPath := p.BucketPath(bucket)
	setDefaultACL(t, bucketPath, testDefaultACL())
	share := filepath.Join(bucketPath, "team", "share")
	if err := os.MkdirAll(share, 0o755); err != nil {
		t.Fatalf("make dir: %v", err)
	}
	setDefaultACL(t, share, encodeACL(readOnlyOwnerACL()))

	for _, key := range []string{"a/b/c/object", "team/share/object"} {
		if err := putTestObject(t, p, bucket, key, "x"); err != nil {
			t.Fatalf("put %v: %v", key, err)
		}
		_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: aws.String(key)})
		if err != nil {
			t.Fatalf("delete %v: %v", key, err)
		}
	}

	if _, err := os.Stat(filepath.Join(bucketPath, "a")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dir with the bucket's default ACL was not removed: %v", err)
	}
	if _, err := os.Stat(share); err != nil {
		t.Errorf("dir with its own default ACL was not kept: %v", err)
	}
	if err := putTestObject(t, p, bucket, "a", "x"); err != nil {
		t.Errorf("put a: %v", err)
	}
}

// TestInheritDefaultACLWithoutOTmpfileRemovesDir checks that without
// O_TMPFILE, when the option has no effect, a directory with a default ACL
// is removed with its last object as it is without the option.
func TestInheritDefaultACLWithoutOTmpfileRemovesDir(t *testing.T) {
	ctx := context.Background()
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true, ForceNoTmpFile: true}
	})
	bucket, key := "bucket", "share/object"
	createTestBucket(t, p, bucket)
	share := filepath.Join(p.BucketPath(bucket), "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatalf("make dir: %v", err)
	}
	setDefaultACL(t, share, testDefaultACL())
	if err := putTestObject(t, p, bucket, key, "x"); err != nil {
		t.Fatalf("put: %v", err)
	}
	_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(share); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dir with a default ACL was not removed: %v", err)
	}
}

// TestInheritDefaultACLWriteOnlyDir checks that objects can be put in a
// directory the gateway can write to but not read, with and without the
// option: neither an O_TMPFILE nor its linkat() needs read permission on the
// directory. The first PUT in a new bucket makes a named temporary file, as
// .sgwtmp doesn't exist yet, and the second one an O_TMPFILE. With Fsync,
// which can't sync a directory it can't read, the PUTs fail before the
// objects are published. Run as a user other than root, which can read any
// directory.
func TestInheritDefaultACLWriteOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any directory")
	}
	for _, inherit := range []bool{false, true} {
		for _, fsync := range []bool{false, true} {
			name := "default"
			if inherit {
				name = "inherit"
			}
			if fsync {
				name += "/fsync"
			}
			t.Run(name, func(t *testing.T) {
				p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
					return meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: inherit, Fsync: fsync}
				})
				bucket := "bucket"
				createTestBucket(t, p, bucket)
				dir := filepath.Join(p.BucketPath(bucket), "dropbox")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatalf("make dir: %v", err)
				}
				skipWithoutOTmpfile(t, dir)
				setDefaultACL(t, dir, testDefaultACL())
				if err := os.Chmod(dir, 0o333); err != nil {
					t.Fatalf("chmod dir: %v", err)
				}
				t.Cleanup(func() { os.Chmod(dir, 0o755) })

				for _, name := range []string{"first", "second"} {
					err := putTestObject(t, p, bucket, "dropbox/"+name, "x")
					path := filepath.Join(dir, name)
					_, statErr := os.Stat(path)
					if fsync {
						if err == nil {
							t.Errorf("%v put succeeded with fsync in a write-only dir", name)
						}
						if !errors.Is(statErr, os.ErrNotExist) {
							t.Errorf("%v object published by a failed put: %v", name, statErr)
						}
						continue
					}
					if err != nil {
						t.Fatalf("%v put in a write-only dir: %v", name, err)
					}
					if acl := hasNamedUser(t, path, aclTestUID); acl != inherit {
						t.Errorf("%v object has the default ACL: %v, want %v", name, acl, inherit)
					}
				}
			})
		}
	}
}

// TestInheritDefaultACLOpenErrors checks which errors of the O_TMPFILE open
// in the directory of the object fall back to a named file in the bucket's
// metadata directory: only those of a filesystem without O_TMPFILE. A
// removed directory is chosen again a bounded number of times, and any other
// error is returned.
func TestInheritDefaultACLOpenErrors(t *testing.T) {
	root := t.TempDir()
	p, err := New(root, meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, InheritDefaultACL: true})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	skipWithoutOTmpfile(t, filepath.Join(root, bucket))
	tmpDir := filepath.Join(root, bucket, MetaTmpDir)

	for _, tc := range []struct {
		name     string
		errs     []error // the errors of the first opens
		wantErr  error
		wantName bool // a named file in tmpDir
		opens    int
	}{
		{name: "unsupported", errs: []error{syscall.EOPNOTSUPP}, wantName: true, opens: 1},
		{name: "old kernel", errs: []error{syscall.EISDIR}, wantName: true, opens: 1},
		{name: "quota", errs: []error{syscall.EDQUOT}, wantErr: syscall.EDQUOT, opens: 1},
		{name: "no space", errs: []error{syscall.ENOSPC}, wantErr: syscall.ENOSPC, opens: 1},
		{name: "permission", errs: []error{syscall.EACCES}, wantErr: syscall.EACCES, opens: 1},
		{name: "removed once", errs: []error{syscall.ENOENT}, opens: 2},
		{name: "stale once", errs: []error{syscall.ESTALE}, opens: 2},
		{
			name:    "always removed",
			errs:    []error{syscall.ENOENT, syscall.ENOENT, syscall.ENOENT, syscall.ENOENT},
			wantErr: syscall.ENOENT,
			opens:   maxTmpDirRetries + 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opens := 0
			openat = func(dirfd int, path string, flags int, mode uint32) (int, error) {
				opens++
				if opens <= len(tc.errs) {
					return -1, tc.errs[opens-1]
				}
				return unix.Openat(dirfd, path, flags, mode)
			}
			t.Cleanup(func() { openat = unix.Openat })

			f, err := p.openObjectTmpFile(bucket, "a/object", 5, auth.Account{}, false, odirectNotAllowed)
			if opens != tc.opens {
				t.Errorf("opened %v times, want %v", opens, tc.opens)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got error %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("open tmp file: %v", err)
			}
			defer f.cleanup()
			named := filepath.Dir(f.File().Name()) == tmpDir
			if named != tc.wantName {
				t.Errorf("temp file %v is named in %v: %v, want %v", f.File().Name(), tmpDir, named, tc.wantName)
			}
		})
	}
}
