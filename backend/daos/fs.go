// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
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
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"
)

// bucketFS is one bucket directory as an fs.FS. Walk lists through this
// adapter. It does not see the rest of the container.
type bucketFS struct {
	dfs    FS
	bucket string
}

func (b bucketFS) Open(name string) (fs.File, error) {
	if name == "" || !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	full := b.bucket
	base := "."
	if name != "." {
		full = b.bucket + "/" + name
		base = path.Base(name)
	}
	info, err := b.dfs.Stat(full)
	if err != nil {
		return nil, fsErr("open", name, err)
	}
	obj, err := b.dfs.Open(full, openRead)
	if err != nil {
		return nil, fsErr("open", name, err)
	}
	return &bucketFile{
		dfs: b.dfs,
		obj: obj,
		info: dfsInfo{
			name:  base,
			size:  info.Size,
			dir:   info.IsDir,
			mtime: info.Mtime,
		},
		full: full,
	}, nil
}

type bucketFile struct {
	dfs    FS
	obj    Object
	info   dfsInfo
	full   string
	off    int64
	kids   []fs.DirEntry
	kidOff int
}

func (f *bucketFile) Stat() (fs.FileInfo, error) { return f.info, nil }

func (f *bucketFile) Read(p []byte) (int, error) {
	n, err := f.dfs.Read(f.obj, p, f.off)
	f.off += int64(n)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	if err != nil {
		return n, fsErr("read", f.info.name, err)
	}
	return n, nil
}

func (f *bucketFile) Close() error {
	if f.obj == nil {
		return nil
	}
	err := f.dfs.Release(f.obj)
	f.obj = nil
	return err
}

func (f *bucketFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.kids == nil {
		infos, err := f.dfs.ReadDir(f.full)
		if err != nil {
			return nil, fsErr("readdir", f.full, err)
		}
		f.kids = make([]fs.DirEntry, len(infos))
		for i, info := range infos {
			f.kids[i] = fs.FileInfoToDirEntry(dfsInfo{
				name:  info.Name,
				size:  info.Size,
				dir:   info.IsDir,
				mtime: info.Mtime,
			})
		}
		slices.SortFunc(f.kids, func(a, b fs.DirEntry) int {
			return strings.Compare(a.Name(), b.Name())
		})
	}
	if f.kidOff >= len(f.kids) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	end := len(f.kids)
	if n > 0 && f.kidOff+n < end {
		end = f.kidOff + n
	}
	out := f.kids[f.kidOff:end]
	f.kidOff = end
	if n > 0 && f.kidOff >= len(f.kids) {
		return out, io.EOF
	}
	return out, nil
}

type dfsInfo struct {
	name  string
	size  int64
	dir   bool
	mtime int64
}

func (i dfsInfo) Name() string { return i.name }
func (i dfsInfo) Size() int64  { return i.size }
func (i dfsInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (i dfsInfo) ModTime() time.Time { return time.Unix(i.mtime, 0).UTC() }
func (i dfsInfo) IsDir() bool        { return i.dir }
func (i dfsInfo) Sys() any           { return nil }

func fsErr(op, name string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNotExist):
		err = fs.ErrNotExist
	case errors.Is(err, errNotDir):
		err = syscall.ENOTDIR
	}
	return &fs.PathError{Op: op, Path: name, Err: err}
}
