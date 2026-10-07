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

//go:build linux && cgo && daos

package daos

/*
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <daos_api.h>
#include <daos_fs.h>

int versitygw_anchor_eof(daos_anchor_t *anchor) {
	return daos_anchor_is_eof(anchor);
}

int64_t versitygw_mtime(const struct stat *st) { return (int64_t)st->st_mtime; }
int64_t versitygw_size(const struct stat *st) { return (int64_t)st->st_size; }
int versitygw_isdir(const struct stat *st) { return S_ISDIR(st->st_mode); }

int versitygw_dfs_read(dfs_t *dfs, dfs_obj_t *obj, void *buf, size_t len,
		       uint64_t off, uint64_t *nread) {
	d_iov_t iov;
	d_sg_list_t sgl;
	daos_size_t got = 0;

	iov.iov_buf = buf;
	iov.iov_buf_len = len;
	iov.iov_len = len;
	sgl.sg_nr = 1;
	sgl.sg_nr_out = 0;
	sgl.sg_iovs = &iov;
	int rc = dfs_read(dfs, obj, &sgl, (daos_off_t)off, &got, NULL);
	if (nread != NULL)
		*nread = (uint64_t)got;
	return rc;
}

int versitygw_dfs_write(dfs_t *dfs, dfs_obj_t *obj, const void *buf, size_t len,
			uint64_t off) {
	d_iov_t iov;
	d_sg_list_t sgl;

	iov.iov_buf = (void *)buf;
	iov.iov_buf_len = len;
	iov.iov_len = len;
	sgl.sg_nr = 1;
	sgl.sg_nr_out = 0;
	sgl.sg_iovs = &iov;
	return dfs_write(dfs, obj, &sgl, (daos_off_t)off, NULL);
}

int versitygw_remove(dfs_t *dfs, dfs_obj_t *parent, const char *name, int force) {
	daos_obj_id_t oid;
	return dfs_remove(dfs, parent, name, force ? true : false, &oid);
}

int versitygw_move(dfs_t *dfs, dfs_obj_t *src_parent, const char *src,
		   dfs_obj_t *dst_parent, const char *dst) {
	daos_obj_id_t oid;
	return dfs_move(dfs, src_parent, src, dst_parent, dst, &oid);
}
*/
import "C"
import (
	"fmt"
	"path"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type dfsFS struct {
	dfs *C.dfs_t
}

type dfsObj struct {
	fs  *dfsFS
	obj *C.dfs_obj_t
}

func (dfsObj) isObject() {}

var (
	dfsMu sync.Mutex
	dfsUp bool
)

func ensureDFS() error {
	dfsMu.Lock()
	defer dfsMu.Unlock()
	if dfsUp {
		return nil
	}
	if err := dfsErrno(C.dfs_init()); err != nil {
		return err
	}
	dfsUp = true
	return nil
}

func openContainer(pool, sys, cont string) (*dfsFS, error) {
	if err := ensureDFS(); err != nil {
		return nil, err
	}
	cpool := C.CString(pool)
	defer C.free(unsafe.Pointer(cpool))
	ccont := C.CString(cont)
	defer C.free(unsafe.Pointer(ccont))
	var csys *C.char
	if sys != "" {
		csys = C.CString(sys)
		defer C.free(unsafe.Pointer(csys))
	}
	var dfs *C.dfs_t
	rc := C.dfs_connect(cpool, csys, ccont, C.O_RDWR, nil, &dfs)
	if err := dfsErrno(rc); err != nil {
		return nil, err
	}
	return &dfsFS{dfs: dfs}, nil
}

func (f *dfsFS) Close() error {
	if f == nil || f.dfs == nil {
		return nil
	}
	rc := C.dfs_disconnect(f.dfs)
	f.dfs = nil
	dfsMu.Lock()
	if dfsUp {
		C.dfs_fini()
		dfsUp = false
	}
	dfsMu.Unlock()
	return dfsErrno(rc)
}

func (f *dfsFS) Open(p string, flags int) (Object, error) {
	if flags&openCreate != 0 {
		return f.openCreate(p, flags)
	}
	cpath := C.CString(absPath(p))
	defer C.free(unsafe.Pointer(cpath))
	var obj *C.dfs_obj_t
	rc := C.dfs_lookup(f.dfs, cpath, openMode(flags), &obj, nil, nil)
	if err := dfsErrno(rc); err != nil {
		return nil, err
	}
	return &dfsObj{fs: f, obj: obj}, nil
}

func (f *dfsFS) openCreate(p string, flags int) (Object, error) {
	parent, name, release, err := f.parent(p, C.O_RDWR)
	if err != nil {
		return nil, err
	}
	defer release()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var obj *C.dfs_obj_t
	rc := C.dfs_open(f.dfs, parent, cname, C.S_IFREG|0644, openMode(flags), 0, 0, nil, &obj)
	if err := dfsErrno(rc); err != nil {
		return nil, err
	}
	return &dfsObj{fs: f, obj: obj}, nil
}

func (f *dfsFS) Read(obj Object, buf []byte, off int64) (int, error) {
	o := obj.(*dfsObj)
	if len(buf) == 0 {
		return 0, nil
	}
	var n C.uint64_t
	rc := C.versitygw_dfs_read(o.fs.dfs, o.obj, unsafe.Pointer(&buf[0]), C.size_t(len(buf)), C.uint64_t(off), &n)
	if err := dfsErrno(rc); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (f *dfsFS) Write(obj Object, buf []byte, off int64) (int, error) {
	o := obj.(*dfsObj)
	if len(buf) == 0 {
		return 0, nil
	}
	rc := C.versitygw_dfs_write(o.fs.dfs, o.obj, unsafe.Pointer(&buf[0]), C.size_t(len(buf)), C.uint64_t(off))
	if err := dfsErrno(rc); err != nil {
		return 0, err
	}
	return len(buf), nil
}

func (f *dfsFS) Mkdir(p string) error {
	parent, name, release, err := f.parent(p, C.O_RDWR)
	if err != nil {
		return err
	}
	defer release()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return dfsErrno(C.dfs_mkdir(f.dfs, parent, cname, 0755, 0))
}

func (f *dfsFS) Remove(p string, force bool) error {
	parent, name, release, err := f.parent(p, C.O_RDWR)
	if err != nil {
		return err
	}
	defer release()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	forceInt := C.int(0)
	if force {
		forceInt = 1
	}
	return dfsErrno(C.versitygw_remove(f.dfs, parent, cname, forceInt))
}

func (f *dfsFS) Move(src, dst string) error {
	sp, sn, srel, err := f.parent(src, C.O_RDWR)
	if err != nil {
		return err
	}
	defer srel()
	dp, dn, drel, err := f.parent(dst, C.O_RDWR)
	if err != nil {
		return err
	}
	defer drel()
	csn := C.CString(sn)
	defer C.free(unsafe.Pointer(csn))
	cdn := C.CString(dn)
	defer C.free(unsafe.Pointer(cdn))
	return dfsErrno(C.versitygw_move(f.dfs, sp, csn, dp, cdn))
}

func (f *dfsFS) Stat(p string) (Info, error) {
	parent, name, release, err := f.parent(p, C.O_RDONLY)
	if err != nil {
		return Info{}, err
	}
	defer release()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var st C.struct_stat
	if err := dfsErrno(C.dfs_stat(f.dfs, parent, cname, &st)); err != nil {
		return Info{}, err
	}
	return Info{
		Name:  name,
		Size:  int64(C.versitygw_size(&st)),
		IsDir: C.versitygw_isdir(&st) != 0,
		Mtime: int64(C.versitygw_mtime(&st)),
	}, nil
}

func (f *dfsFS) SetXattr(obj Object, name string, value []byte) error {
	if len(name) > maxXattrName || len(value) > maxXattrLen {
		return errNameLong
	}
	o := obj.(*dfsObj)
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var ptr unsafe.Pointer
	if len(value) > 0 {
		ptr = unsafe.Pointer(&value[0])
	}
	return dfsErrno(C.dfs_setxattr(o.fs.dfs, o.obj, cname, ptr, C.daos_size_t(len(value)), 0))
}

func (f *dfsFS) RemoveXattr(obj Object, name string) error {
	if len(name) > maxXattrName {
		return errNameLong
	}
	o := obj.(*dfsObj)
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return dfsErrno(C.dfs_removexattr(o.fs.dfs, o.obj, cname))
}

func (f *dfsFS) GetXattr(obj Object, name string) ([]byte, error) {
	o := obj.(*dfsObj)
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	buf := C.malloc(C.size_t(maxXattrLen))
	if buf == nil {
		return nil, fmt.Errorf("dfs: out of memory")
	}
	defer C.free(buf)
	n := C.daos_size_t(maxXattrLen)
	if err := dfsErrno(C.dfs_getxattr(o.fs.dfs, o.obj, cname, buf, &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(buf, C.int(n)), nil
}

func (f *dfsFS) ReadDir(p string) ([]Info, error) {
	obj, err := f.Open(p, openRead)
	if err != nil {
		return nil, err
	}
	defer f.Release(obj)
	o := obj.(*dfsObj)
	var anchor C.daos_anchor_t
	var out []Info
	for {
		var dirs [64]C.struct_dirent
		nr := C.uint32_t(len(dirs))
		rc := C.dfs_readdir(f.dfs, o.obj, &anchor, &nr, &dirs[0])
		if err := dfsErrno(rc); err != nil {
			return nil, err
		}
		for i := 0; i < int(nr); i++ {
			name := C.GoString(&dirs[i].d_name[0])
			if name == "" || name == "." || name == ".." {
				continue
			}
			info, err := f.Stat(path.Join(p, name))
			if err != nil {
				return nil, err
			}
			out = append(out, info)
		}
		if C.versitygw_anchor_eof(&anchor) != 0 || nr == 0 {
			break
		}
	}
	return out, nil
}

func (f *dfsFS) Release(obj Object) error {
	o := obj.(*dfsObj)
	if o.obj == nil {
		return nil
	}
	rc := C.dfs_release(o.obj)
	o.obj = nil
	return dfsErrno(rc)
}

func (f *dfsFS) StatObj(obj Object) (Info, error) {
	o := obj.(*dfsObj)
	var st C.struct_stat
	if err := dfsErrno(C.dfs_ostat(f.dfs, o.obj, &st)); err != nil {
		return Info{}, err
	}
	return Info{
		Size:  int64(C.versitygw_size(&st)),
		IsDir: C.versitygw_isdir(&st) != 0,
		Mtime: int64(C.versitygw_mtime(&st)),
	}, nil
}

func (f *dfsFS) parent(p string, flags C.int) (parent *C.dfs_obj_t, name string, release func(), err error) {
	release = func() {}
	p = clean(p)
	if p == "" || p == "." {
		return nil, "", release, errNotDir
	}
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" || dir == "." {
		return nil, base, release, nil
	}
	cdir := C.CString(absPath(dir))
	defer C.free(unsafe.Pointer(cdir))
	rc := C.dfs_lookup(f.dfs, cdir, flags, &parent, nil, nil)
	if err = dfsErrno(rc); err != nil {
		return nil, "", release, err
	}
	held := parent
	release = func() { C.dfs_release(held) }
	return parent, base, release, nil
}

func absPath(p string) string {
	p = clean(p)
	if p == "" || p == "." {
		return "/"
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func openMode(flags int) C.int {
	mode := C.int(C.O_RDONLY)
	if flags&(openWrite|openCreate) != 0 {
		mode = C.O_RDWR
	}
	if flags&openCreate != 0 {
		mode |= C.O_CREAT
	}
	if flags&openExcl != 0 {
		mode |= C.O_EXCL
	}
	return mode
}

func dfsErrno(rc C.int) error {
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
	default:
		return fmt.Errorf("dfs errno %d", int(rc))
	}
}
