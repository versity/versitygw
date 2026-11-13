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

// syncDirs owns the directory handles from the object's parent to the bucket.
type syncDirs []*os.File

func (dirs syncDirs) Close() {
	for _, d := range dirs {
		d.Close()
	}
}

// openDirForSync opens every directory that will be synced before publishing.
// Read permission failures must fail the PUT before the object exists, and
// a concurrent DELETE after publication must not invalidate the handles.
// Windows cannot fsync directory handles.
func (tmp *tmpfile) openDirForSync(dir string) (syncDirs, error) {
	if !tmp.fsync || runtime.GOOS == "windows" {
		return nil, nil
	}
	var dirs syncDirs
	stop := filepath.Clean(tmp.bucket)
	for {
		d, err := os.Open(dir)
		if err != nil {
			dirs.Close()
			return nil, fmt.Errorf("open sync directory %q: %w", dir, err)
		}
		dirs = append(dirs, d)
		parent := filepath.Dir(dir)
		if dir == stop || parent == dir {
			return dirs, nil
		}
		dir = parent
	}
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

// syncNamespace flushes the publication and its parent entries using only
// handles opened before publication. All handles are closed, even on error.
func (tmp *tmpfile) syncNamespace(dirs syncDirs) error {
	defer dirs.Close()
	for _, d := range dirs {
		if err := syncDir(d.Name(), d); err != nil {
			return fmt.Errorf("fsync directory %q: %w", d.Name(), err)
		}
	}
	return nil
}
