package meta

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/xattr"
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
func (x XattrMeta) RetrieveAttribute(bucket, object, attribute string) ([]byte, error) {
	b, err := xattr.Get(filepath.Join(bucket, object), xattrPrefix+attribute)
	if errors.Is(err, errNoData) {
		return nil, ErrNoSuchKey
	}
	return b, err
}

// StoreAttribute stores the value of a specific attribute for an object in a bucket.
func (x XattrMeta) StoreAttribute(bucket, object, attribute string, value []byte) error {
	return xattr.Set(filepath.Join(bucket, object), xattrPrefix+attribute, value)
}

// DeleteAttribute removes the value of a specific attribute for an object in a bucket.
func (x XattrMeta) DeleteAttribute(bucket, object, attribute string) error {
	err := xattr.Remove(filepath.Join(bucket, object), xattrPrefix+attribute)
	if errors.Is(err, errNoData) {
		return ErrNoSuchKey
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
func (x XattrMeta) Test(path string) bool {
	_, err := xattr.Get(path, "user.test")
	return !errors.Is(err, syscall.ENOTSUP)
}
