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
	"errors"

	"golang.org/x/sys/unix"
)

// aclDefaultXattr is the extended attribute that holds a directory's POSIX
// default ACL
const aclDefaultXattr = "system.posix_acl_default"

// hasDefaultACL reports whether the directory path has a default ACL.
func hasDefaultACL(path string) (bool, error) {
	return aclPresent(unix.Getxattr(path, aclDefaultXattr, nil))
}

// hasDefaultACLFd reports whether the open directory fd has a default ACL.
func hasDefaultACLFd(fd int) (bool, error) {
	return aclPresent(unix.Fgetxattr(fd, aclDefaultXattr, nil))
}

func aclPresent(size int, err error) (bool, error) {
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return size > 0, nil
}
