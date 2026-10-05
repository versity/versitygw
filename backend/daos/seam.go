// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

import "errors"

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
	errExist    = errors.New("daos: file exists")
	errNotExist = errors.New("daos: no such file or directory")
	errNotDir   = errors.New("daos: not a directory")
	errIsDir    = errors.New("daos: is a directory")
	errNotEmpty = errors.New("daos: directory not empty")
	errNameLong = errors.New("daos: name too long")
)

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
	ReadDir(path string) ([]Info, error)
	Release(obj Object) error
	StatObj(obj Object) (Info, error)
	Close() error
}
