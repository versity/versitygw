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
