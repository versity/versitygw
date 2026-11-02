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

package posix

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// syncFile and syncDir are variables so tests can observe the calls.
var (
	syncFile = func(f *os.File) error { return f.Sync() }
	syncDir  = func(dir string) error {
		// Windows cannot fsync a directory handle.
		if runtime.GOOS == "windows" {
			return nil
		}
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
)

// syncData flushes an object's data and its inode, which includes the
// xattr metadata, before the object is published.
func (tmp *tmpfile) syncData() error {
	if !tmp.fsync {
		return nil
	}
	if err := syncFile(tmp.f); err != nil {
		return fmt.Errorf("fsync object data: %w", err)
	}
	return nil
}

// syncNamespace flushes the directory entry that publishes the object, and
// those of any parent directories created for it, by syncing the object's
// directory and each parent up to and including the bucket directory.
func (tmp *tmpfile) syncNamespace() error {
	if !tmp.fsync {
		return nil
	}
	stop := filepath.Clean(tmp.bucket)
	dir := filepath.Dir(filepath.Join(tmp.bucket, tmp.objname))
	for {
		if err := syncDir(dir); err != nil {
			return fmt.Errorf("fsync directory %q: %w", dir, err)
		}
		parent := filepath.Dir(dir)
		if dir == stop || parent == dir {
			return nil
		}
		dir = parent
	}
}

// syncObjectMeta flushes the attributes written to an object that is already
// in place, which no data sync before a publish covers: those of a directory
// object and those of an object rewritten in place. With sidecar metadata the
// attributes live in other files, which this does not flush.
func (p *Posix) syncObjectMeta(bucket, object string) error {
	if !p.fsync {
		return nil
	}
	path := p.ObjectPath(bucket, object)
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat object for fsync: %w", err)
	}
	if fi.IsDir() {
		if err := syncDir(path); err != nil {
			return fmt.Errorf("fsync object metadata: %w", err)
		}
		return nil
	}
	// FlushFileBuffers needs a handle that can write, which os.Open on
	// Windows is not.
	flags := os.O_RDONLY
	if runtime.GOOS == "windows" {
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return fmt.Errorf("open object for fsync: %w", err)
	}
	defer f.Close()
	if err := syncFile(f); err != nil {
		return fmt.Errorf("fsync object metadata: %w", err)
	}
	return nil
}
