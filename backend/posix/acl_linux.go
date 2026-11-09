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
	"errors"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// aclDefaultXattr is the extended attribute that holds a directory's POSIX
// default ACL
const aclDefaultXattr = "system.posix_acl_default"

// hasDefaultACL reports whether the directory path has a default ACL.
func hasDefaultACL(path string) (bool, error) {
	acl, err := defaultACL(path)
	return acl != nil, err
}

// hasDefaultACLFd reports whether the directory opened as fd, which may be an
// O_PATH handle, has a default ACL. fgetxattr() doesn't work on an O_PATH
// handle, so the ACL is read through the handle's /proc entry, or through
// dir, the path the handle was opened with, when /proc is not mounted.
func hasDefaultACLFd(fd int, dir string) (bool, error) {
	ok, err := hasDefaultACL(filepath.Join(procfddir, strconv.Itoa(fd)))
	if errors.Is(err, unix.ENOENT) {
		return hasDefaultACL(dir)
	}
	return ok, err
}

// ownDefaultACL reports whether the directory path has a default ACL other
// than the one of its parent. A directory without one, or with the same one
// as its parent, which mkdir copies to every new directory, loses nothing
// when it is removed: the next mkdir in the parent makes it again with the
// same ACL.
func ownDefaultACL(path string) (bool, error) {
	acl, err := defaultACL(path)
	if err != nil || acl == nil {
		return false, err
	}
	parentACL, err := defaultACL(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	return !bytes.Equal(acl, parentACL), nil
}

// defaultACL returns the xattr value of the default ACL of the directory
// path, or nil when it has none.
func defaultACL(path string) ([]byte, error) {
	for {
		size, err := unix.Getxattr(path, aclDefaultXattr, nil)
		if noACL(err) || (err == nil && size == 0) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size)
		n, err := unix.Getxattr(path, aclDefaultXattr, buf)
		if errors.Is(err, unix.ERANGE) {
			// the ACL grew since its size was read
			continue
		}
		if noACL(err) || (err == nil && n == 0) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
}

// noACL reports whether err is the error of reading an ACL that is not set,
// or of a filesystem without ACLs.
func noACL(err error) bool {
	return errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP)
}
