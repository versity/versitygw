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
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
)

// Object publish locking
//
// S3 conditional writes (If-Match / If-None-Match: *) require that reading the
// current object state, evaluating the condition, and publishing the
// replacement happen as one atomic step per bucket/key. The gateway is
// stateless and multiple gateway processes may share the same backend
// filesystem, so an in-process mutex alone is not sufficient: exclusion is
// provided by an advisory lock (flock on unix, LockFileEx on windows) on a
// shared lock file, combined with a process-local striped mutex so that
// contention within one process is resolved cheaply and each process presents
// at most one waiter to the filesystem lock.
//
// Lock identity: bucket/.sgwtmp/objlock/<shard>, where shard is the first
// byte of sha256(object key) rendered as two hex characters. Hashing the key
// gives a stable, traversal-safe, fixed-length name; sharding (256 slots per
// bucket) keeps the number of lock files bounded while still letting writes
// to unrelated keys proceed concurrently in the common case. Lock files are
// empty, created on demand, and never unlinked: unlinking an flock file opens
// a classic race where a waiter holds a lock on an unlinked inode while a new
// file takes its place, which is unsafe to detect reliably on NFS due to
// attribute caching.
//
// The lock is held only for the commit phase (condition re-check, metadata
// stores, final link/rename) — request bodies are staged to a temp file
// before the lock is taken. The OS releases advisory locks automatically when
// the file handle is closed or the process exits, so failures, cancellation,
// or crashes cannot leave a permanently stale lock.
//
// NFS notes: flock on Linux NFS clients is mapped to NFSv4 byte-range locks
// (or NLM on NFSv3), giving cross-client exclusion. Mounting with
// "-o nolock" or "-o local_lock=flock"/"local_lock=all" disables server-side
// locking and reduces exclusion to a single client; conditional-write
// atomicity across gateways requires server-backed locking. If the filesystem
// does not support advisory locking at all, the gateway falls back to
// process-local exclusion and logs a warning once.

const (
	// objLockDir is the per-bucket directory holding object publish lock files
	objLockDir = MetaTmpDir + "/objlock"
	// objLockShards is the number of lock shards per bucket
	objLockShards = 256
)

// objLockShard returns the shard index for an object key.
func objLockShard(object string) uint8 {
	sum := sha256.Sum256([]byte(object))
	return sum[0]
}

// lockObjectPublish acquires the publish lock for bucket/object. It returns a
// release function that must be called (typically deferred) once the new
// object state is visible. All code paths that create or replace an object at
// its final key must hold this lock across condition evaluation and
// publication.
func (p *Posix) lockObjectPublish(ctx context.Context, bucket, object string) (func(), error) {
	shard := objLockShard(object)

	mu := &p.objLockMus[shard]
	mu.Lock()

	f, err := p.openObjLockFile(bucket, shard)
	if err != nil {
		mu.Unlock()
		return nil, err
	}

	err = lockFileExclusive(ctx, f)
	if err != nil {
		f.Close()
		if ctx.Err() != nil {
			mu.Unlock()
			return nil, ctx.Err()
		}
		// The filesystem does not support advisory locking (e.g. NFS
		// mounted with -o nolock). Fall back to process-local exclusion
		// and warn once: conditional writes are then only atomic within
		// this gateway process.
		p.objLockWarn.Do(func() {
			debuglogger.Logf("object lock file locking unavailable (%v): "+
				"conditional write atomicity limited to this process", err)
		})
		return mu.Unlock, nil
	}

	return func() {
		// closing the file releases the advisory lock
		f.Close()
		mu.Unlock()
	}, nil
}

// openObjLockFile opens (creating as needed) the lock file for the shard in
// the given bucket.
func (p *Posix) openObjLockFile(bucket string, shard uint8) (*os.File, error) {
	name := filepath.Join(bucket, objLockDir, fmt.Sprintf("%02x", shard))

	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, os.FileMode(defaultFilePerm))
	if err == nil {
		return f, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("open object lock file: %w", err)
	}

	// lock dir not created yet
	err = backend.MkdirAll(filepath.Join(bucket, objLockDir), 0, 0, false, p.newDirPerm)
	if err != nil {
		return nil, fmt.Errorf("make object lock dir: %w", err)
	}
	f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE, os.FileMode(defaultFilePerm))
	if err != nil {
		return nil, fmt.Errorf("open object lock file: %w", err)
	}
	return f, nil
}

const (
	objLockInitialBackoff = time.Millisecond
	objLockMaxBackoff     = 16 * time.Millisecond
)
