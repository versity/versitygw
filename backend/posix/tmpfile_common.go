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
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length %v", tmp.size)
	}

	n, err := tmp.f.Write(b)
	tmp.size -= int64(n)
	return n, err
}

func (tmp *tmpfile) File() *os.File {
	return tmp.f
}

// SidecarToken returns the per-upload identifier used to name the temporary
// sidecar directory staged by StoreAttribute.  It must be called after
// link() so that tmp.ino has been set.
//
// On Unix the token is "<pid>.<inode>", which is unique for the lifetime of
// the upload's data file regardless of fd number reuse.
// On platforms where inodes are unavailable (e.g. Windows) it falls back to
// "<pid>.<basename(f.Name())>", which is unique because CreateTemp generates
// uniquely-named files.
//
// IMPORTANT: the token format must stay in sync with tmpSidecarID() in
// backend/meta/sidecar.go, which computes the same value from the live *os.File
// during StoreAttribute.  Both functions must produce identical output for the
// staging and commit steps to find the same directory.
func (tmp *tmpfile) SidecarToken() string {
	if tmp.ino != 0 {
		return fmt.Sprintf("%d.%d", os.Getpid(), tmp.ino)
	}
	// Fallback: path-based token for platforms without POSIX inodes.
	return fmt.Sprintf("%d.%s", os.Getpid(), filepath.Base(tmp.f.Name()))
}

func sleepWithJitter(backoffMs int) {
	if backoffMs <= 1 {
		time.Sleep(1 * time.Millisecond)
		return
	}

	maxJitter := max(1, backoffMs/4)
	jitter := rand.Intn((maxJitter*2)+1) - maxJitter
	sleepMs := max(backoffMs+jitter, 1)
	time.Sleep(time.Duration(sleepMs) * time.Millisecond)
}
