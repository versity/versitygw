// Copyright 2023 Versity Software
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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type tmpfile struct {
	f       *os.File
	bucket  string
	objname string
	size    int64
}

func openTmpFile(dir, bucket, obj string, size int64) (*tmpfile, error) {
	// Create a temp file for upload while in progress (see link comments below).
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, fmt.Errorf("make temp dir: %w", err)
	}
	f, err := os.CreateTemp(dir,
		fmt.Sprintf("%x.", sha256.Sum256([]byte(obj))))
	if err != nil {
		return nil, err
	}
	return &tmpfile{f: f, bucket: bucket, objname: obj, size: size}, nil
}

func (tmp *tmpfile) link() error {
	tempname := tmp.f.Name()
	// cleanup in case anything goes wrong, if rename succeeds then
	// this will no longer exist
	defer os.Remove(tempname)

	// We use Rename as the atomic operation for object puts. The upload is
	// written to a temp file to not conflict with any other simultaneous
	// uploads. The final operation is to move the temp file into place for
	// the object. This ensures the object semantics of last upload completed
	// wins and is not some combination of writes from simultaneous uploads.
	objPath := filepath.Join(tmp.bucket, tmp.objname)
	err := os.Remove(objPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale path: %w", err)
	}

	err = tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	err = os.Rename(tempname, objPath)
	if err != nil {
		return fmt.Errorf("rename tmpfile: %w", err)
	}

	return nil
}

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length %v", tmp.size)
	}

	n, err := tmp.f.Write(b)
	tmp.size -= int64(n)
	return n, err
}

func (tmp *tmpfile) cleanup() {
	tmp.f.Close()
}
