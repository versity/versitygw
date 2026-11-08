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
	"path"
	"strings"
	"sync"
	"time"
)

// Fake is an in-memory DFS seam. Move clobbers the destination and keeps the
// source object's attributes, which is the behavior the publish path relies
// on. It does not model overlapping renames.
type Fake struct {
	mu            sync.Mutex
	root          *node
	failMove      bool
	failMoveAt    int
	moveCount     int
	plantBefore   string
	bytesRead     int64
	bytesWritten  int64
	fullOpens     int
	handles       int
	maxRead       int
	chunk         int64
	writeLens     []int
	openTrace     []string
	oclassSet     []string
	chunkSizesSet []int64
}

// SetChunkSize makes ChunkSize report n. Tests use it to exercise
// chunk-aligned buffering.
func (f *Fake) SetDefaultChunk(n int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chunk = n
}

// CapRead makes Read return at most n bytes per call. Tests use it to
// exercise short-read accumulation. Zero disables the cap.
func (f *Fake) CapRead(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxRead = n
}

// FullOpens is how many full-path Open calls have been made. Tests use it
// to prove a code path resolves entries relative to a held handle instead.
func (f *Fake) FullOpens() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fullOpens
}

// Handles is the number of objects currently held open and not released.
func (f *Fake) Handles() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.handles
}

// WriteLens returns the lengths of every Write call, in order.
func (f *Fake) WriteLens() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.writeLens...)
}

// OclassCalls returns the object class names passed to SetOclass, in order.
func (f *Fake) OclassCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.oclassSet...)
}

// ChunkSizeCalls returns the chunk sizes passed to SetChunkSize, in order.
func (f *Fake) ChunkSizeCalls() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.chunkSizesSet...)
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
	// Directories may be opened for write: updating a directory
	// (creating a child) needs a writable handle. Read and write on
	// the directory itself still fail below.
	f.fullOpens++
	f.handles++
	f.openTrace = append(f.openTrace, p)
	return fakeObj{n}, nil
}

func (f *Fake) OpenRel(parent Object, name string, flags int) (Object, error) {
	p, ok := parent.(fakeObj)
	if !ok {
		return nil, errInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, err := f.openNode(p.n, name, flags)
	if err == nil {
		f.handles++
	}
	return obj, err
}

func (f *Fake) openNode(parent *node, name string, flags int) (Object, error) {
	n, ok := parent.kids[name]
	if !ok {
		if flags&openCreate == 0 {
			return nil, errNotExist
		}
		if !parent.dir {
			return nil, errNotDir
		}
		n = &node{name: name, mtime: now(), xattr: map[string][]byte{}}
		parent.kids[name] = n
	} else if flags&openExcl != 0 && flags&openCreate != 0 {
		return nil, errExist
	}
	// Same as the full-path open above: writable directory handles are
	// allowed so children can be created through them.
	f.handles++
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
	if f.maxRead > 0 && nread > f.maxRead {
		nread = f.maxRead
	}
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
	f.writeLens = append(f.writeLens, len(buf))
	return len(buf), nil
}

// BytesWritten is how many payload bytes Write has stored.
func (f *Fake) BytesWritten() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bytesWritten
}

func (f *Fake) ChunkSize(Object) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.chunk == 0 {
		return 1 << 20, nil
	}
	return f.chunk, nil
}

// ResetCounters clears the open counters and trace. Tests call it between
// phases to isolate the calls of one operation.
func (f *Fake) ResetCounters() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fullOpens = 0
	f.handles = 0
	f.openTrace = nil
}

// OpenTrace returns the full paths opened by path-based Open, in order.
func (f *Fake) OpenTrace() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.openTrace...)
}

// PlantFile creates a regular file at the given clean path, bypassing the
// S3 layer. Tests use it to model a file sitting where a directory is
// expected.
func (f *Fake) PlantFile(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, base, err := f.parent(p, true)
	if err != nil {
		return err
	}
	parent.kids[base] = &node{name: base, mtime: now(), xattr: map[string][]byte{}}
	return nil
}

func (f *Fake) Mkdir(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent, base, err := f.parent(p, false)
	if err != nil {
		return err
	}
	return f.mkdirNode(parent, base)
}

func (f *Fake) MkdirRel(parent Object, name string) error {
	p, ok := parent.(fakeObj)
	if !ok {
		return errInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mkdirNode(p.n, name)
}

func (f *Fake) mkdirNode(parent *node, base string) error {
	if kid, ok := parent.kids[base]; ok {
		if kid.dir {
			return errExist
		}
		return errNotDir
	}
	if !parent.dir {
		return errNotDir
	}
	parent.kids[base] = &node{name: base, dir: true, kids: map[string]*node{}, mtime: now(), xattr: map[string][]byte{}}
	return nil
}

func (f *Fake) PlantBeforeRemove(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plantBefore = p
}

func (f *Fake) Remove(p string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.plantBefore != "" && pathDir(clean(f.plantBefore)) == clean(p) {
		planted := f.plantBefore
		f.plantBefore = ""
		parent, base, err := f.parent(planted, true)
		if err == nil {
			if _, ok := parent.kids[base]; !ok {
				parent.kids[base] = &node{name: base, data: []byte("late"), mtime: now()}
			}
		}
	}
	if strings.HasSuffix(p, "/") {
		n, err := f.walk(p, false)
		if err != nil {
			return err
		}
		if !n.dir {
			return errNotExist
		}
	}
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
	if strings.HasSuffix(p, "/") {
		n, err := f.walk(p, false)
		if err != nil {
			return Info{}, err
		}
		if !n.dir {
			return Info{}, errNotExist
		}
		return infoOf(n), nil
	}
	n, err := f.walk(p, false)
	if err != nil {
		return Info{}, err
	}
	return infoOf(n), nil
}

func (f *Fake) StatRel(parent Object, name string) (Info, error) {
	p, ok := parent.(fakeObj)
	if !ok {
		return Info{}, errInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := p.n.kids[name]
	if !ok {
		return Info{}, errNotExist
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

func (f *Fake) RemoveXattr(obj Object, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := obj.(fakeObj).n
	if _, ok := n.xattr[name]; !ok {
		return errNotExist
	}
	delete(n.xattr, name)
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
	return f.kidsOf(n), nil
}

func (f *Fake) ReadDirObj(obj Object) ([]Info, error) {
	p, ok := obj.(fakeObj)
	if !ok {
		return nil, errInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !p.n.dir {
		return nil, errNotDir
	}
	return f.kidsOf(p.n), nil
}

func (f *Fake) kidsOf(n *node) []Info {
	out := make([]Info, 0, len(n.kids))
	for _, kid := range n.kids {
		out = append(out, infoOf(kid))
	}
	return out
}

func (f *Fake) Release(Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handles > 0 {
		f.handles--
	}
	return nil
}

func (f *Fake) StatObj(obj Object) (Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return infoOf(obj.(fakeObj).n), nil
}

func (f *Fake) SetOclass(obj Object, oclass string) error {
	if _, ok := obj.(fakeObj); !ok {
		return errInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oclassSet = append(f.oclassSet, oclass)
	return nil
}

func (f *Fake) SetChunkSize(obj Object, n int64) error {
	if _, ok := obj.(fakeObj); !ok {
		return errInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chunkSizesSet = append(f.chunkSizesSet, n)
	return nil
}

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
		if len(part) > maxComponent {
			return nil, componentTooLong{size: int64(len(part)), max: int64(maxComponent)}
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
	if len(base) > maxComponent {
		return nil, "", componentTooLong{size: int64(len(base)), max: int64(maxComponent)}
	}
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
