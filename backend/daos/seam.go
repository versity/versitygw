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

package daos

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
)

const (
	openRead = 1 << iota
	openWrite
	openCreate
	openExcl
)

const (
	maxXattrName = 255
	maxXattrLen  = 65536
)

var (
	errExist       = errors.New("daos: file exists")
	errNotExist    = errors.New("daos: no such file or directory")
	errNotDir      = errors.New("daos: not a directory")
	errIsDir       = errors.New("daos: is a directory")
	errNotEmpty    = errors.New("daos: directory not empty")
	errNameLong    = errors.New("daos: name too long")
	errInvalid     = errors.New("daos: invalid argument")
	errFileOverDir = errors.New("daos: file over directory")
)

const maxComponent = 255

type componentTooLong struct {
	size int64
	max  int64
}

func (e componentTooLong) Error() string {
	return "daos: component too long"
}

func firstLongComponent(path string) (componentTooLong, bool) {
	for _, part := range strings.Split(clean(path), "/") {
		if part != "" && len(part) > maxComponent {
			return componentTooLong{size: int64(len(part)), max: int64(maxComponent)}, true
		}
	}
	return componentTooLong{}, false
}

func pathErr(path string, err error) error {
	if err == nil || (!errors.Is(err, errNameLong) && !errors.Is(err, errInvalid)) {
		return err
	}
	if long, ok := firstLongComponent(path); ok {
		return long
	}
	return err
}

func errnoSentinel(rc int) error {
	if rc == 0 {
		return nil
	}
	switch syscall.Errno(rc) {
	case syscall.ENOENT, syscall.ENODATA:
		return errNotExist
	case syscall.EEXIST:
		return errExist
	case syscall.ENOTDIR:
		return errNotDir
	case syscall.EISDIR:
		return errIsDir
	case syscall.ENOTEMPTY:
		return errNotEmpty
	case syscall.ENAMETOOLONG:
		return errNameLong
	case syscall.EINVAL:
		return errInvalid
	default:
		return fmt.Errorf("dfs errno %d", rc)
	}
}

// Object is an open DFS object. The cgo implementation wraps dfs_obj_t.
// The fake used by tests is another implementation.
type Object interface {
	isObject()
}

// Info is the stat result object and listing paths need.
type Info struct {
	Name  string
	Size  int64
	IsDir bool
	Mtime int64
}

// FS is the DFS seam. Production code calls this interface. One
// implementation is cgo, built only with the daos tag. The fake is the other.
type FS interface {
	Open(path string, flags int) (Object, error)
	Read(obj Object, buf []byte, off int64) (int, error)
	Write(obj Object, buf []byte, off int64) (int, error)
	Mkdir(path string) error
	Remove(path string, force bool) error
	Move(src, dst string) error
	Stat(path string) (Info, error)
	SetXattr(obj Object, name string, value []byte) error
	GetXattr(obj Object, name string) ([]byte, error)
	RemoveXattr(obj Object, name string) error
	ReadDir(path string) ([]Info, error)
	Release(obj Object) error
	StatObj(obj Object) (Info, error)
	Close() error
}
