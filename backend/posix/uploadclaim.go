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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
)

// Multipart upload claims
//
// CompleteMultipartUpload claims an upload by renaming its directory
// <uploadId> to <uploadId>.<etag>.inprogress, assembles the object from the
// claimed directory, and renames it back when it fails. The claimed
// directory alone can't tell another call whether its owner is still
// assembling the object, is about to fail and rename it back, or died
// without renaming it back. The owner therefore holds the claim lock of the
// upload from before the rename until the object is published or the
// directory is renamed back:
//   - another call completing or aborting the upload waits for the owner,
//     then finds the published object or the upload directory renamed back,
//     so its result follows the owner's actual outcome,
//   - a claim found while holding the claim lock was left by a process that
//     died. It is renamed back to <uploadId>, so the upload can be listed,
//     aborted and completed again, or removed when the object was published
//     or the parts may have been moved into an object that wasn't.
//
// Taking the claim lock before the rename also makes the claim exclusive
// where the rename alone doesn't: FreeBSD looks up the source and the target
// of a rename separately, and a rename whose source and target are the same
// directory succeeds without doing anything.
//
// The claim lock is a process-local mutex per upload and, in the flock and
// fcntl object lock modes, the advisory lock of a lock file per upload in the
// object lock directory, which the OS releases when the process holding it
// exits. Only the holder of the process-local mutex opens the lock file, so
// fcntl's per-process lock ownership is never shared by two calls. In the
// local mode a claim is known to be live only in the process that made it,
// so undoing a claim no call of the process holds assumes a single gateway
// process per backend. The none mode is for gateway processes sharing a
// backend without a lock that excludes them, so such a claim may be another
// process's live claim: it is never undone, and a call that finds it is told
// to retry.
//
// The lock file of an upload is removed once the upload no longer exists.
// Upload IDs are never reused, so a call that still locks the removed file,
// and one that creates a new file in its place, both find the upload gone.

const (
	// uploadClaimLockDir holds the claim lock files of a bucket's uploads in
	// its directory of the object lock directory.
	uploadClaimLockDir = "uploads"
	// claimConsumedName marks a claimed upload whose parts may be moved
	// into the object being assembled.
	claimConsumedName = "consumed"
)

type uploadClaimLocks struct {
	mu    sync.Mutex
	locks map[string]*uploadClaimSlot
}

type uploadClaimSlot struct {
	ch   chan struct{}
	refs int
}

// acquire takes the process-local claim lock of key, returning false instead
// of waiting for its holder when wait is false.
func (l *uploadClaimLocks) acquire(ctx context.Context, key string, wait bool) (func(), bool, error) {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*uploadClaimSlot)
	}
	s := l.locks[key]
	if s == nil {
		s = &uploadClaimSlot{ch: make(chan struct{}, 1)}
		l.locks[key] = s
	}
	s.refs++
	l.mu.Unlock()

	put := func() {
		l.mu.Lock()
		s.refs--
		if s.refs == 0 {
			delete(l.locks, key)
		}
		l.mu.Unlock()
	}

	if wait {
		select {
		case s.ch <- struct{}{}:
		case <-ctx.Done():
			put()
			return nil, false, ctx.Err()
		}
	} else {
		select {
		case s.ch <- struct{}{}:
		default:
			put()
			return nil, false, nil
		}
	}

	return func() {
		<-s.ch
		put()
	}, true, nil
}

// uploadClaim is a held claim lock of an upload.
type uploadClaim struct {
	file         *os.File
	path         string
	releaseLocal func()
	gone         bool
}

// uploadGone records that the upload no longer exists, so its lock file is
// removed when the lock is released.
func (c *uploadClaim) uploadGone() {
	c.gone = true
}

func (c *uploadClaim) release() {
	if c.file != nil {
		// closing the file releases the advisory lock
		c.file.Close()
		if c.gone {
			os.Remove(c.path)
		}
	}
	c.releaseLocal()
}

// lockUploadClaim takes the claim lock of the upload. With wait false it
// returns nil instead of waiting while another call holds the lock.
func (p *Posix) lockUploadClaim(ctx context.Context, bucket, uploadID string, wait bool) (*uploadClaim, error) {
	releaseLocal, ok, err := p.uploadClaims.acquire(ctx, bucket+"/"+uploadID, wait)
	if err != nil || !ok {
		return nil, err
	}
	claim := &uploadClaim{releaseLocal: releaseLocal}
	if p.objectLockMode == ObjectLockModeLocal || p.objectLockMode == ObjectLockModeNone {
		return claim, nil
	}

	claim.path, claim.file, err = p.openUploadClaimFile(bucket, uploadID)
	if err != nil {
		releaseLocal()
		return nil, err
	}

	if wait {
		err = lockFileExclusive(ctx, claim.file, p.objectLockMode)
	} else {
		ok, err = tryLockFileExclusive(claim.file, p.objectLockMode)
		if err == nil && !ok {
			claim.file.Close()
			releaseLocal()
			return nil, nil
		}
	}
	if err != nil {
		claim.file.Close()
		releaseLocal()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("lock upload claim: %w", err)
	}

	return claim, nil
}

// openUploadClaimFile opens (creating as needed) the claim lock file of the
// upload.
func (p *Posix) openUploadClaimFile(bucket, uploadID string) (string, *os.File, error) {
	bucketHash := sha256.Sum256([]byte(bucket))
	lockDir := filepath.Join(p.rootdir, objLockDir, fmt.Sprintf("%x", bucketHash), uploadClaimLockDir)
	name := filepath.Join(lockDir, uploadID)

	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, defaultNewFilePerm)
	if errors.Is(err, fs.ErrNotExist) {
		// lock dir not created yet
		err = backend.MkdirAll(lockDir, 0, 0, false, p.newDirPerm)
		if err != nil {
			return "", nil, fmt.Errorf("make upload claim lock dir: %w", err)
		}
		f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE, defaultNewFilePerm)
	}
	if err != nil {
		return "", nil, fmt.Errorf("open upload claim lock file: %w", err)
	}
	return name, f, nil
}

// tryLockFileExclusive takes the lock on f only when no one holds it.
func tryLockFileExclusive(f *os.File, mode ObjectLockMode) (bool, error) {
	// an already canceled context stops lockFileExclusive after its first
	// attempt
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := lockFileExclusive(ctx, f, mode)
	if errors.Is(err, context.Canceled) {
		return false, nil
	}
	return err == nil, err
}

// recoverUploadClaims undoes the claims of the upload left by processes that
// died while completing it. The caller holds the claim lock. objdir is the
// directory of the uploads of the key, and object is the key's encoded name.
// It reports whether the upload directory was restored.
func (p *Posix) recoverUploadClaims(bucket, object, objdir, uploadID string) (bool, error) {
	ents, err := os.ReadDir(objdir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read uploads: %w", err)
	}

	var claims []string
	for _, ent := range ents {
		name := ent.Name()
		if ent.IsDir() && strings.HasPrefix(name, uploadID+".") && strings.HasSuffix(name, inProgressSuffix) {
			claims = append(claims, name)
		}
	}
	if len(claims) == 0 {
		return false, nil
	}
	if p.objectLockMode == ObjectLockModeNone {
		// the claim lock doesn't exclude the other gateway processes, one
		// of which may be completing the upload
		return false, s3err.GetAPIError(s3err.ErrSlowDown)
	}

	published, err := p.publishedByUpload(bucket, object, uploadID)
	if err != nil {
		return false, err
	}

	metaObjDir := filepath.Join(MetaTmpMultipartDir, filepath.Base(objdir))
	uploadIDDir := filepath.Join(objdir, uploadID)

	var restored bool
	for _, name := range claims {
		claimDir := filepath.Join(objdir, name)

		_, err := os.Stat(filepath.Join(claimDir, claimConsumedName))
		consumed := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("stat claim consumed marker: %w", err)
		}

		if published || consumed || restored {
			err := os.RemoveAll(claimDir)
			if err != nil {
				return false, fmt.Errorf("remove stale upload claim: %w", err)
			}
			_ = p.meta.DeleteAttributes(bucket, filepath.Join(metaObjDir, name))
			continue
		}

		err = os.Rename(claimDir, uploadIDDir)
		if err != nil {
			return false, fmt.Errorf("restore stale upload claim: %w", err)
		}
		err = p.meta.RenameObject(bucket, filepath.Join(metaObjDir, name), filepath.Join(metaObjDir, uploadID))
		if err != nil {
			return false, fmt.Errorf("restore stale upload claim metadata: %w", err)
		}
		restored = true
	}

	return restored, nil
}

// restoreUploadClaim restores the upload when its claim was left by a process
// that died, returning the upload directory. It returns nil while another call
// completes the upload, and when the upload no longer exists.
func (p *Posix) restoreUploadClaim(ctx context.Context, bucket, object, objdir, uploadID string) (fs.FileInfo, error) {
	if p.objectLockMode == ObjectLockModeNone {
		// claims are never undone in this mode
		return nil, nil
	}
	claim, err := p.lockUploadClaim(ctx, bucket, uploadID, false)
	if err != nil || claim == nil {
		return nil, err
	}
	defer claim.release()

	_, err = p.recoverUploadClaims(bucket, object, objdir, uploadID)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(filepath.Join(objdir, uploadID))
	if errors.Is(err, fs.ErrNotExist) {
		claim.uploadGone()
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat restored upload: %w", err)
	}
	return fi, nil
}

// markClaimConsumed records in the claimed upload directory that its parts
// may be moved into the object being assembled.
func (p *Posix) markClaimConsumed(claimDir string) error {
	marker := filepath.Join(claimDir, claimConsumedName)
	f, err := os.OpenFile(marker, os.O_RDWR|os.O_CREATE, defaultNewFilePerm)
	if err != nil {
		return fmt.Errorf("create claim consumed marker: %w", err)
	}
	f.Close()
	if p.fsync {
		err = syncDir(claimDir)
		if err != nil {
			os.Remove(marker)
			return fmt.Errorf("sync claim consumed marker: %w", err)
		}
	}
	return nil
}

// publishedByUpload reports whether the object at the key, given by its
// encoded name, was published by the upload. Multipart uploads are never
// created for keys with a trailing slash, and a directory at the object path
// is the object of such a key.
func (p *Posix) publishedByUpload(bucket, object, uploadID string) (bool, error) {
	if strings.HasSuffix(object, "/") {
		return false, nil
	}
	fi, err := os.Stat(p.ObjectPath(bucket, object))
	if errors.Is(err, fs.ErrNotExist) || isErrNotDir(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat object: %w", err)
	}
	if fi.IsDir() {
		return false, nil
	}

	mpMetaBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, mpMetaKey)
	if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get object multipart metadata: %w", err)
	}
	mpMeta, err := backend.UnmarshalMpUploadMetadata(mpMetaBytes, false)
	if err != nil {
		return false, fmt.Errorf("parse object multipart metadata: %w", err)
	}
	return mpMeta.UploadID == uploadID, nil
}
