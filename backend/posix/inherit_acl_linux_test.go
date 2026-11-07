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
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend/meta"
	"golang.org/x/sys/unix"
)

const (
	aclAccessXattr  = "system.posix_acl_access"
	aclDefaultXattr = "system.posix_acl_default"

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

// TestInheritDefaultACLWithoutOTmpfile checks that without O_TMPFILE the
// named temporary file is still made in the bucket's metadata directory and
// never in the directory of the object.
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
	bucket := filepath.Join(t.TempDir(), "bucket")
	if err := os.MkdirAll(filepath.Join(bucket, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bucket, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ dir, want string }{
		{"a/b", "a/b"},
		{"a/b/c/d", "a/b"},
		{"x/y", ""},
		{"", ""},
		// a file where a directory is expected: the PUT fails later
		{"file/c", ""},
	} {
		got := closestDir(bucket, filepath.Join(bucket, tc.dir))
		if want := filepath.Join(bucket, tc.want); got != want {
			t.Errorf("closestDir(%q) = %v, want %v", tc.dir, got, want)
		}
	}
}

// TestInheritDefaultACLMode checks that with InheritDefaultACL an object in a
// directory with a default ACL keeps the mode the ACL gives it, even when the
// ACL is narrower than NewFilePerm, and that without a default ACL the
// object still gets NewFilePerm.
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
