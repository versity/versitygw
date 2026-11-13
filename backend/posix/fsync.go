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

// syncFile and syncDir are variables so tests can observe the calls. syncDir
// flushes the directory d, opened from the path dir.
var (
	syncFile = func(f *os.File) error { return f.Sync() }
	syncDir  = func(dir string, d *os.File) error { return d.Sync() }
)

// openDirForSync opens dir, the directory an object is published in, for the
// fsync of its entry, before the object is published: fsync needs a
// directory opened for reading, and when the gateway can't read the
// directory the PUT then fails before the object exists, not after it is
// published. It returns nil when nothing is synced: when fsync is off, or on
// Windows, which cannot fsync a directory handle.
func (tmp *tmpfile) openDirForSync(dir string) (*os.File, error) {
	if !tmp.fsync || runtime.GOOS == "windows" {
		return nil, nil
	}
	return os.Open(dir)
}

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
// objDir is the object's directory, opened with openDirForSync before the
// object was published, or nil when nothing is synced. It is closed.
func (tmp *tmpfile) syncNamespace(objDir *os.File) error {
	if objDir == nil {
		return nil
	}
	defer objDir.Close()
	stop := filepath.Clean(tmp.bucket)
	dir := filepath.Dir(filepath.Join(tmp.bucket, tmp.objname))
	for d := objDir; ; d = nil {
		if d == nil {
			var err error
			d, err = os.Open(dir)
			if err != nil {
				return fmt.Errorf("fsync directory %q: %w", dir, err)
			}
		}
		err := syncDir(dir, d)
		if d != objDir {
			d.Close()
		}
		if err != nil {
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
// attributes live in other files, which this does not flush, and the data and
// its sidecar are not updated atomically, so a crash can leave them out of step.
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
		// The directory may have been created for this request, along with
		// its parents, so flush each up to and including the bucket.
		stop := filepath.Clean(p.BucketPath(bucket))
		dir := filepath.Clean(path)
		for {
			if err := syncDirPath(dir); err != nil {
				return fmt.Errorf("fsync object metadata: %w", err)
			}
			parent := filepath.Dir(dir)
			if dir == stop || parent == dir {
				return nil
			}
			dir = parent
		}
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

// syncDirPath opens the directory dir and flushes it. Windows cannot fsync a
// directory handle, so nothing is synced there.
func syncDirPath(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return syncDir(dir, d)
}
