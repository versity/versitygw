// Copyright 2024 Versity Software
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

package meta

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/xattr"
	"github.com/versity/versitygw/s3err"
)

const (
	xattrPrefix = "user."
)

var (
	// ErrNoSuchKey is returned when the key does not exist.
	ErrNoSuchKey = errors.New("no such key")
)

type XattrMeta struct{}

// RetrieveAttribute retrieves the value of a specific attribute for an object in a bucket.
func (x XattrMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	if f != nil {
		b, err := xattr.FGet(f, xattrPrefix+attribute)
		if errors.Is(err, xattr.ENOATTR) {
			return nil, ErrNoSuchKey
		}
		return b, err
	}

	b, err := xattr.Get(filepath.Join(bucket, object), xattrPrefix+attribute)
	if errors.Is(err, xattr.ENOATTR) {
		return nil, ErrNoSuchKey
	}
	return b, err
}

// StoreAttribute stores the value of a specific attribute for an object in a bucket.
func (x XattrMeta) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	if f != nil {
		err := xattr.FSet(f, xattrPrefix+attribute, value)
		if errors.Is(err, syscall.EROFS) {
			return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		return err
	}

	err := xattr.Set(filepath.Join(bucket, object), xattrPrefix+attribute, value)
	if errors.Is(err, syscall.EROFS) {
		return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
	}
	return err
}

// DeleteAttribute removes the value of a specific attribute for an object in a bucket.
func (x XattrMeta) DeleteAttribute(bucket, object, attribute string) error {
	err := xattr.Remove(filepath.Join(bucket, object), xattrPrefix+attribute)
	if errors.Is(err, xattr.ENOATTR) {
		return ErrNoSuchKey
	}
	if errors.Is(err, syscall.EROFS) {
		return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
	}
	return err
}

// DeleteAttributes is not implemented for xattr since xattrs
// are automatically removed when the file is deleted.
func (x XattrMeta) DeleteAttributes(bucket, object string) error {
	return nil
}

// ListAttributes lists all attributes for an object in a bucket.
func (x XattrMeta) ListAttributes(bucket, object string) ([]string, error) {
	attrs, err := xattr.List(filepath.Join(bucket, object))
	if err != nil {
		return nil, err
	}
	attributes := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		if !isUserAttr(attr) {
			continue
		}
		attributes = append(attributes, strings.TrimPrefix(attr, xattrPrefix))
	}
	return attributes, nil
}

func isUserAttr(attr string) bool {
	return strings.HasPrefix(attr, xattrPrefix)
}

// Test is a helper function to test if xattrs are supported.
func (x XattrMeta) Test(path string) error {
	// check for platform support
	if !xattr.XATTR_SUPPORTED {
		return fmt.Errorf("xattrs are not supported on this platform")
	}

	// check if the filesystem supports xattrs
	_, err := xattr.Get(path, "user.test")
	if errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("xattrs are not supported on this filesystem")
	}

	return nil
}
