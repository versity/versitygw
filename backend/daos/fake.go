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

import (
	"path"
	"strings"
	"sync"
	"time"
)

// Fake is an in-memory DFS seam. Move clobbers the destination and keeps the
// source object's attributes, which is the behavior the publish path relies
// on. It does not model overlapping renames.
type Fake struct {
	mu           sync.Mutex
	root         *node
	failMove     bool
	failMoveAt   int
	moveCount    int
	bytesRead    int64
	bytesWritten int64
}

type node struct {
	name    string
	dir     bool
	data    []byte
	mtime   int64
	xattr   map[string][]byte
	kids    map[string]*node
	deleted bool
}

type fakeObj struct {
	n *node
}

func (fakeObj) isObject() {}

// NewFake returns an empty container root.
func NewFake() *Fake {
	return &Fake{root: &node{dir: true, kids: map[string]*node{}, mtime: now()}}
}

func now() int64 { return time.Now().Unix() }

func (f *Fake) Open(p string, flags int) (Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.walk(p, false)
	if err != nil {
		if !errorsIs(err, errNotExist) || flags&openCreate == 0 {
			return nil, err
		}
		parent, base, err := f.parent(p, true)
		if err != nil {
			return nil, err
		}
		if _, ok := parent.kids[base]; ok {
			return nil, errExist
		}
		n = &node{name: base, mtime: now(), xattr: map[string][]byte{}}
		parent.kids[base] = n
	} else if flags&openExcl != 0 && flags&openCreate != 0 {
		return nil, errExist
	}
	if n.dir && flags&openWrite != 0 {
		return nil, errIsDir
	}
	return fakeObj{n}, nil
}

func (f *Fake) Read(obj Object, buf []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := obj.(fakeObj).n
	if n.dir {
		return 0, errIsDir
	}
	if off >= int64(len(n.data)) {
		return 0, nil
	}
	nread := copy(buf, n.data[off:])
	f.bytesRead += int64(nread)
	return nread, nil
}

// BytesRead is how many payload bytes Read has returned. Tests use it to
// prove complete copied the part bytes instead of only renaming them.
func (f *Fake) BytesRead() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bytesRead
}

func (f *Fake) Write(obj Object, buf []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := obj.(fakeObj).n
	if n.dir {
		return 0, errIsDir
	}
	end := int(off) + len(buf)
	if end > len(n.data) {
		next := make([]byte, end)
		copy(next, n.data)
		n.data = next
	}
	copy(n.data[off:], buf)
	n.mtime = now()
	f.bytesWritten += int64(len(buf))
	return len(buf), nil
}

// BytesWritten is how many payload bytes Write has stored.
func (f *Fake) BytesWritten() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bytesWritten
}

func (f *Fake) Mkdir(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, base, err := f.parent(p, false)
	if err != nil {
		return err
	}
	if kid, ok := parent.kids[base]; ok {
		if kid.dir {
			return errExist
		}
		return errNotDir
	}
	parent.kids[base] = &node{name: base, dir: true, kids: map[string]*node{}, mtime: now(), xattr: map[string][]byte{}}
	return nil
}

func (f *Fake) Remove(p string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, base, err := f.parent(p, false)
	if err != nil {
		return err
	}
	kid, ok := parent.kids[base]
	if !ok {
		return errNotExist
	}
	if kid.dir && len(kid.kids) > 0 && !force {
		return errNotEmpty
	}
	delete(parent.kids, base)
	kid.deleted = true
	return nil
}

// FailNextMove makes the next Move return an error without changing names.
func (f *Fake) FailNextMove() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failMove = true
}

// FailMoveOn fails the nth Move from now, counting from 1, without changing names.
func (f *Fake) FailMoveOn(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.moveCount = 0
	f.failMoveAt = n
}

func (f *Fake) Move(src, dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.moveCount++
	if f.failMove {
		f.failMove = false
		return errNotExist
	}
	if f.failMoveAt > 0 && f.moveCount == f.failMoveAt {
		f.failMoveAt = 0
		return errNotExist
	}
	sp, sb, err := f.parent(src, false)
	if err != nil {
		return err
	}
	n, ok := sp.kids[sb]
	if !ok {
		return errNotExist
	}
	dp, db, err := f.parent(dst, true)
	if err != nil {
		return err
	}
	if old, ok := dp.kids[db]; ok {
		old.deleted = true
	}
	delete(sp.kids, sb)
	n.name = db
	dp.kids[db] = n
	return nil
}

func (f *Fake) Stat(p string) (Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.walk(p, false)
	if err != nil {
		return Info{}, err
	}
	return infoOf(n), nil
}

func (f *Fake) SetXattr(obj Object, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(name) > maxXattrName || len(value) > maxXattrLen {
		return errNameLong
	}
	n := obj.(fakeObj).n
	if n.xattr == nil {
		n.xattr = map[string][]byte{}
	}
	n.xattr[name] = append([]byte(nil), value...)
	return nil
}

func (f *Fake) GetXattr(obj Object, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := obj.(fakeObj).n
	v, ok := n.xattr[name]
	if !ok {
		return nil, errNotExist
	}
	return append([]byte(nil), v...), nil
}

func (f *Fake) ReadDir(p string) ([]Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.walk(p, false)
	if err != nil {
		return nil, err
	}
	if !n.dir {
		return nil, errNotDir
	}
	out := make([]Info, 0, len(n.kids))
	for _, kid := range n.kids {
		out = append(out, infoOf(kid))
	}
	return out, nil
}

func (f *Fake) Release(Object) error { return nil }

func (f *Fake) Close() error { return nil }

func (f *Fake) walk(p string, mkdir bool) (*node, error) {
	cur := f.root
	p = clean(p)
	if p == "" || p == "." {
		return cur, nil
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" {
			continue
		}
		if !cur.dir {
			return nil, errNotDir
		}
		next, ok := cur.kids[part]
		if !ok {
			if !mkdir {
				return nil, errNotExist
			}
			next = &node{name: part, dir: true, kids: map[string]*node{}, mtime: now(), xattr: map[string][]byte{}}
			cur.kids[part] = next
		}
		cur = next
	}
	return cur, nil
}

func (f *Fake) parent(p string, mkdir bool) (*node, string, error) {
	p = clean(p)
	if p == "" || p == "." {
		return nil, "", errNotDir
	}
	dir, base := path.Split(p)
	parent, err := f.walk(dir, mkdir)
	if err != nil {
		return nil, "", err
	}
	if !parent.dir {
		return nil, "", errNotDir
	}
	return parent, base, nil
}

func infoOf(n *node) Info {
	return Info{Name: n.name, Size: int64(len(n.data)), IsDir: n.dir, Mtime: n.mtime}
}

func clean(p string) string {
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}

func errorsIs(err, target error) bool { return err == target }
