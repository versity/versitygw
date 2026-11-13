// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

package daos

import (
	"errors"

	"github.com/versity/versitygw/s3err"
)

// The guarded publication helper. Every destination mutation - PUT,
// CopyObject, multipart completion, and the file case of DELETE -
// commits through publish. The helper owns the namespace mutex for
// the whole commit: destination conditions are evaluated against the
// name it observes, the previous generation is retired before the
// publish Move, and a failed publish restores it. Callers stage
// bodies and compute checksums first; nothing but Moves and
// bookkeeping runs inside.

// pubState carries what publish needs to know about the destination.
type pubState struct {
	// retires is the retire path when a previous generation was
	// moved aside; empty when the destination was absent or a
	// directory.
	retires string
	// prevGen tracks the previous generation for registry updates.
	prevGen *generation
}

// publish moves staging to dst under the namespace mutex. ifMatch /
// ifNoneMatch, when non-nil, are evaluated inside the critical
// section against the destination as observed there; a missing
// destination with If-Match is ErrNoSuchKey, matching the shared
// evaluator. kind and opID feed the durable record.
func (d *Daos) publish(bucket, key, staging string, ifMatch, ifNoneMatch *string, kind, opID string) (pubState, error) {
	var st pubState
	dst := objectPath(bucket, key)

	// The durable record binds the operation to its target before
	// the first namespace mutation. Its write must be complete
	// before the retire Move can run.
	rec := opRecord{ID: opID, Kind: kind, Bucket: bucket, Key: key, Staging: staging}
	if err := d.writeRecord(rec); err != nil {
		return st, err
	}

	d.coord.ns.mu.Lock()
	defer d.coord.ns.mu.Unlock()

	// Destination conditions run inside the guard: no writer can
	// interleave between this evaluation and the publish Move.
	if ifMatch != nil || ifNoneMatch != nil {
		if err := d.checkDestPreconditions(bucket, key, ifMatch, ifNoneMatch); err != nil {
			d.removeRecord(bucket, rec.ID)
			return st, err
		}
	}

	info, err := d.fs.Stat(dst)
	switch {
	case err == nil && !info.IsDir:
		// Retire the current generation: the rename keeps the
		// object id, so an open handle keeps streaming. The
		// retire name embeds the full operation UUID, so two
		// operations on one key never collide.
		st.retires = retirePathFor(bucket, key)
		if merr := d.fs.Move(dst, st.retires); merr != nil {
			d.removeRecord(bucket, rec.ID)
			if aerr := d.ambiguousAfter(merr, dst, st.retires, rec); aerr != nil {
				return st, aerr
			}
			return st, d.mapKeyErr(merr, key)
		}
		d.coord.trackRetire(bucket, key, st.retires, rec.ID)
	case err == nil:
		// A directory at the destination is never retired; the
		// publish Move itself must fail with the conflict.
	case !errors.Is(err, errNotExist):
		d.removeRecord(bucket, rec.ID)
		return st, d.mapKeyErr(err, key)
	}

	if err := d.mkdirParents(dst); err != nil {
		if st.retires != "" {
			_ = d.fs.Move(st.retires, dst)
		}
		d.removeRecord(bucket, rec.ID)
		return st, d.mapKeyErr(err, key)
	}
	if err := d.fs.Move(staging, dst); err != nil {
		// Failed publish: restore the retired generation so the
		// acknowledged object is not lost alongside the new one.
		if st.retires != "" {
			if rerr := d.fs.Move(st.retires, dst); rerr != nil {
				return st, d.coord.quarantineKey(bucket, key, rec.ID, kind, []string{st.retires, staging, dst})
			}
		}
		d.coord.commitRetireRollback(bucket, key, st.retires)
		d.removeRecord(bucket, rec.ID)
		return st, d.mapKeyErr(err, key)
	}
	// Committed: the previous generation is a retiree that reclaims
	// when its readers drain. The record survives only while a
	// protected artifact does: a reader-pinned retiree keeps it, an
	// idle one is reclaimed right away and drops it. With no retiree
	// there is nothing to protect and the record goes now.
	d.coord.commitRetire(bucket, key, st.retires, rec.ID)
	if st.retires == "" {
		d.removeRecord(bucket, rec.ID)
	} else if d.reclaimIfIdle(bucket, key) {
		d.removeRecord(bucket, rec.ID)
	}
	return st, nil
}

// ambiguousAfter decides whether a failed Move may have left both
// names (relaxed-mode dfs_move: destination inserted, source not yet
// removed). Such an outcome is never guessed at: the key is
// quarantined with the record identifying the artifacts.
func (d *Daos) ambiguousAfter(moveErr error, src, dst string, rec opRecord) error {
	if !errors.Is(moveErr, errAmbiguousMove) {
		return nil
	}
	return d.coord.quarantineKey(rec.Bucket, rec.Key, rec.ID, rec.Kind, []string{src, dst})
}

// deleteFile routes the regular-file case of DeleteObject through
// retirement: the response is not delayed by readers, and the bytes
// reclaim when the last reader closes. Directories keep their
// nonrecursive remove and ErrDirectoryNotEmpty behavior.
func (d *Daos) deleteFile(bucket, key string) error {
	dst := objectPath(bucket, key)
	opID := newOpID()
	rec := opRecord{ID: opID, Kind: recKindDelete, Bucket: bucket, Key: key}
	if err := d.writeRecord(rec); err != nil {
		return err
	}

	d.coord.ns.mu.Lock()
	defer d.coord.ns.mu.Unlock()

	info, err := d.fs.Stat(dst)
	if errors.Is(err, errNotExist) {
		d.removeRecord(bucket, opID)
		return nil // delete of an absent key succeeds
	}
	if err != nil {
		d.removeRecord(bucket, opID)
		return d.mapKeyErr(err, key)
	}
	if info.IsDir {
		d.removeRecord(bucket, opID)
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	rp := retirePathFor(bucket, key)
	if merr := d.fs.Move(dst, rp); merr != nil {
		if aerr := d.ambiguousAfter(merr, dst, rp, rec); aerr != nil {
			return aerr
		}
		d.removeRecord(bucket, opID)
		return d.mapKeyErr(merr, key)
	}
	// The delete is acknowledged here; reclamation waits for
	// readers.
	d.coord.commitRetire(bucket, key, rp, opID)
	if d.reclaimIfIdle(bucket, key) {
		d.removeRecord(bucket, opID)
	}
	return nil
}
