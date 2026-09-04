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
)

// Object publish locking
//
// S3 conditional writes (If-Match / If-None-Match: *) require that reading the
// current object state, evaluating the condition, and publishing the
// replacement happen as one atomic step per bucket/key. The gateway is
// stateless and multiple gateway processes may share the same backend
// filesystem, so an in-process mutex alone is not sufficient: exclusion is
// provided by a configured advisory lock (flock or fcntl on unix, LockFileEx
// on windows) on a shared lock file, combined with a process-local striped mutex so that
// contention within one process is resolved cheaply and each process presents
// at most one waiter to the filesystem lock.
//
// Lock identity: <root>/.vgwlocks/<bucket-hash>/<shard>, where shard is the
// first byte of sha256(object key) rendered as two hex characters. Hashing the
// bucket and key gives stable, traversal-safe, fixed-length names; sharding
// (256 slots per bucket) keeps the number of lock files bounded while still
// letting writes to unrelated keys proceed concurrently in the common case.
// Lock files are outside the bucket tree so Windows bucket deletion cannot
// fail merely because an active request has the lock file open. They are empty,
// created on demand, and never unlinked: unlinking an flock file opens a
// classic race where a waiter holds a lock on an unlinked inode while a new
// file takes its place, which is unsafe to detect reliably on NFS due to
// attribute caching.
//
// The lock is held only for the commit phase (condition re-check, metadata
// stores, final link/rename) — request bodies are staged to a temp file
// before the lock is taken. The OS releases advisory locks automatically when
// the file handle is closed or the process exits, so failures, cancellation,
// or crashes cannot leave a permanently stale lock.
//
// Filesystem lock scope varies by filesystem and mount options. Operators using
// multiple gateway processes must select a mode that their filesystem provides
// with cluster-wide exclusion. The local mode provides only process-local
// exclusion and is unsafe for conditional writes across gateway processes. The
// none mode rejects conditional writes.

const (
	// objLockDir is the root directory holding object publish lock files.
	objLockDir = ".vgwlocks"
	// objLockShards is the number of lock shards per bucket
	objLockShards = 256
)

// ObjectLockMode selects the advisory locking primitive used to serialize
// conditional object publishes.
type ObjectLockMode string

const (
	ObjectLockModeFlock ObjectLockMode = "flock"
	ObjectLockModeFcntl ObjectLockMode = "fcntl"
	ObjectLockModeLocal ObjectLockMode = "local"
	ObjectLockModeNone  ObjectLockMode = "none"
)

func resolveObjectLockMode(mode ObjectLockMode, forceNoObjLockFile bool) (ObjectLockMode, error) {
	if mode == "" {
		if forceNoObjLockFile {
			return ObjectLockModeLocal, nil
		}
		return ObjectLockModeFlock, nil
	}
	if forceNoObjLockFile && mode != ObjectLockModeLocal {
		return "", fmt.Errorf("disable object lock file conflicts with object lock mode %q", mode)
	}
	switch mode {
	case ObjectLockModeFlock, ObjectLockModeFcntl, ObjectLockModeLocal, ObjectLockModeNone:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid object lock mode %q (want flock, fcntl, local, or none)", mode)
	}
}

// verifyObjectLockMode verifies that the configured shared lock primitive is
// available on the filesystem containing the gateway's lock directory. It
// cannot verify cross-node lock coherence.
func (p *Posix) verifyObjectLockMode() error {
	if p.objectLockMode == ObjectLockModeLocal || p.objectLockMode == ObjectLockModeNone {
		return nil
	}
	if err := validateObjectLockMode(p.objectLockMode); err != nil {
		return err
	}

	lockDir := filepath.Join(p.rootdir, objLockDir)
	if err := backend.MkdirAll(lockDir, 0, 0, false, p.newDirPerm); err != nil {
		return fmt.Errorf("make object lock directory: %w", err)
	}
	f, err := os.CreateTemp(lockDir, ".startup-lock-*")
	if err != nil {
		return fmt.Errorf("create object lock probe: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if err := lockFileExclusive(context.Background(), f, p.objectLockMode); err != nil {
		return fmt.Errorf("verify object lock mode %q: %w", p.objectLockMode, err)
	}
	return nil
}

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

	slot := p.objLockSlots[shard]
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-slot:
	}
	releaseLocal := func() { slot <- struct{}{} }
	if err := ctx.Err(); err != nil {
		releaseLocal()
		return nil, err
	}
	if p.objectLockMode == ObjectLockModeLocal || p.objectLockMode == ObjectLockModeNone {
		return releaseLocal, nil
	}

	f, err := p.openObjLockFile(bucket, shard)
	if err != nil {
		releaseLocal()
		return nil, err
	}

	err = lockFileExclusive(ctx, f, p.objectLockMode)
	if err != nil {
		f.Close()
		if ctx.Err() != nil {
			releaseLocal()
			return nil, ctx.Err()
		}
		releaseLocal()
		return nil, fmt.Errorf("lock object publish: %w", err)
	}

	return func() {
		// closing the file releases the advisory lock
		f.Close()
		releaseLocal()
	}, nil
}

func newObjLockSlots() [objLockShards]chan struct{} {
	var slots [objLockShards]chan struct{}
	for i := range slots {
		slots[i] = make(chan struct{}, 1)
		slots[i] <- struct{}{}
	}
	return slots
}

// openObjLockFile opens (creating as needed) the lock file for the shard in
// the given bucket.
func (p *Posix) openObjLockFile(bucket string, shard uint8) (*os.File, error) {
	bucketHash := sha256.Sum256([]byte(bucket))
	lockDir := filepath.Join(p.rootdir, objLockDir, fmt.Sprintf("%x", bucketHash))
	name := filepath.Join(lockDir, fmt.Sprintf("%02x", shard))

	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, defaultNewFilePerm)
	if err == nil {
		return f, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("open object lock file: %w", err)
	}

	// lock dir not created yet
	err = backend.MkdirAll(lockDir, 0, 0, false, p.newDirPerm)
	if err != nil {
		return nil, fmt.Errorf("make object lock dir: %w", err)
	}
	f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE, defaultNewFilePerm)
	if err != nil {
		return nil, fmt.Errorf("open object lock file: %w", err)
	}
	return f, nil
}

const (
	objLockInitialBackoff = time.Millisecond
	objLockMaxBackoff     = 16 * time.Millisecond
)
