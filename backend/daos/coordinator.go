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
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// The DAOS namespace has no atomic conditional publish, and libdfs
// punches the object an open handle streams from when its directory
// entry is replaced or removed. Correct publication therefore has to
// be coordinated in the backend: every destination mutation passes
// through one guarded publish helper, retired generations outlive
// their readers, and upload sessions exclude overlapping writers.
// The coordinator owns that state for one gateway process. Locks are
// ordered bucket admission -> upload session -> namespace; the
// registry mutex covers bookkeeping only and is never held across a
// lock wait or a DFS call.

// namespace serializes the commit section of every destination
// mutation: destination condition checks, retirement, publication,
// rollback, directory-marker writes, nonrecursive directory deletes,
// and the metadata capture of reader acquisition. Body staging and
// checksums stay outside.
type namespace struct {
	mu sync.Mutex
}

// uploadLocks stripes session guards by upload UUID. UploadPart,
// UploadPartCopy, CompleteMultipartUpload, and AbortMultipartUpload
// hold one stripe for the whole operation; active and claimed upload
// names hash to the same stripe because the key is the upload UUID.
type uploadLocks struct {
	mu      sync.Mutex
	stripes [64]sync.Mutex
}

func (u *uploadLocks) lock(uploadID string) func() {
	id, err := uuid.Parse(uploadID)
	if err != nil {
		id = uuid.NewSHA1(uuid.NameSpaceURL, []byte(uploadID))
	}
	slot := int(id[15]) % len(u.stripes)
	u.stripes[slot].Lock()
	return u.stripes[slot].Unlock
}

// generation identifies one durable version of an object: the live
// object, or a retired copy waiting out its readers. Records are
// immutable; refcount counts leases, and state governs reclamation.
type generation struct {
	id      string // operation UUID that created this generation
	retired string // retire path; empty while live
	state   genState
	refc    int
	// reclaimNow marks a committed retiree with no reader that the
	// publisher must remove right after commit.
	reclaimNow bool
}

type genState int

const (
	// genLive: the object at dst is this generation. Never reclaimed.
	genLive genState = iota
	// genRetiredCommitted: replaced or deleted; reclaim when refc
	// drains.
	genRetiredCommitted
	// genRetiredPending: a publication is in flight; never reclaimed
	// until it commits (back to live replacement) or rolls back.
	genRetiredPending
	// genRecovery: the outcome is unresolved (ambiguous Move);
	// reclamation is blocked until reconciliation.
	genRecovery
)

// keyRec tracks the generations of one destination key. keyStr is the
// canonical identity used by leases and quarantine checks.
type keyRec struct {
	keyStr  string
	live    *generation
	retired map[string]*generation // by retire path
}

type recoveryRec struct {
	id        string // operation UUID
	bucket    string
	key       string // canonical key, may be empty for bucket-level holds
	kind      string // put/copy/mpu-publish/delete/upload-session
	artifacts []string
	createdAt time.Time
}

// coord is the single-gateway concurrency coordinator.
type coord struct {
	ns       namespace
	uploads  uploadLocks
	mu       sync.Mutex // registry + recovery bookkeeping only
	keys     map[string]*keyRec
	recovery map[string]*recoveryRec
	hold     map[string]bool // bucket-level hold from unclassifiable residue
}

func newCoord() *coord {
	return &coord{
		keys:     map[string]*keyRec{},
		recovery: map[string]*recoveryRec{},
		hold:     map[string]bool{},
	}
}

// canonicalKey derives the registry identity of a destination: the
// cleaned object path after validation, so dot-segment and repeated
// separator variants of one key share one record.
func canonicalKey(bucket, key string) string {
	return clean(objectPath(bucket, key))
}

// readerLease pins one generation while its bytes stream.
type readerLease struct {
	c    *coord
	gen  *generation
	once sync.Once
}

// acquire registers a lease on the key's current live generation,
// creating the record for an object the coordinator has not seen
// published (pre-existing objects): without that, a later overwrite
// would retire a generation nobody pinned. The caller must already
// hold the namespace mutex (reader metadata capture runs inside the
// publication critical section).
func (c *coord) acquire(bucket, key string) *readerLease {
	ck := canonicalKey(bucket, key)
	c.mu.Lock()
	rec := c.keys[ck]
	if rec == nil {
		rec = &keyRec{keyStr: ck, retired: map[string]*generation{}}
		c.keys[ck] = rec
	}
	if rec.live == nil {
		rec.live = &generation{id: ""}
	}
	gen := rec.live
	gen.refc++
	c.mu.Unlock()
	return &readerLease{c: c, gen: gen}
}

// release drops one lease. Idempotent. When a committed retired
// generation drains, it is reclaimed here; pending and recovery
// generations are never touched.
func (l *readerLease) release(fs FS) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		c := l.c
		g := l.gen
		c.mu.Lock()
		if g.refc > 0 {
			g.refc--
		}
		reclaim := g.state == genRetiredCommitted && g.refc == 0
		if reclaim {
			g.state = genLive // terminal marker; record pruned below
		}
		ck := ""
		for k, rec := range c.keys {
			for _, rg := range rec.retired {
				if rg == g {
					ck = k
				}
			}
		}
		if reclaim && ck != "" {
			delete(c.keys[ck].retired, g.retired)
			if len(c.keys[ck].retired) == 0 && c.keys[ck].live == nil {
				delete(c.keys, ck)
			}
		}
		c.mu.Unlock()
		if reclaim && fs != nil && g.retired != "" {
			_ = fs.Remove(g.retired, false)
		}
	})
}

// quarantineKey blocks mutation of a key with unresolved state. The
// returned recovery error identifies the operation.
func (c *coord) quarantineKey(bucket, key, opID, kind string, artifacts []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := opID
	if id == "" {
		id = uuid.NewString()
	}
	c.recovery[id] = &recoveryRec{
		id: id, bucket: bucket, key: canonicalKey(bucket, key),
		kind: kind, artifacts: artifacts, createdAt: time.Now(),
	}
	return fmt.Errorf("daos: unresolved recovery state for %s/%s (operation %s): reconciliation required", bucket, key, id)
}

// quarantineUpload blocks part writes, completion, abort, and
// destructive cleanup for one upload session.
func (c *coord) quarantineUpload(bucket, key, uploadID string, artifacts []string) error {
	return c.quarantineKey(bucket, key, uploadID, "upload-session", artifacts)
}

// trackRetire records a retire that just happened under the
// namespace mutex. The generation is pending: the publication has not
// committed yet, so reclamation is blocked.
func (c *coord) trackRetire(bucket, key, retirePath, opID string) {
	ck := canonicalKey(bucket, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.keys[ck]
	if rec == nil {
		rec = &keyRec{keyStr: ck, retired: map[string]*generation{}}
		c.keys[ck] = rec
	}
	g := &generation{id: opID, retired: retirePath, state: genRetiredPending}
	rec.retired[retirePath] = g
}

// commitRetire finalizes a retire whose publication committed. The
// previous generation reclaims when its readers drain; the live
// generation becomes a fresh record.
func (c *coord) commitRetire(bucket, key, retirePath, opID string) {
	ck := canonicalKey(bucket, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.keys[ck]
	if rec == nil {
		rec = &keyRec{keyStr: ck, retired: map[string]*generation{}}
		c.keys[ck] = rec
	}
	rec.live = &generation{id: opID}
	if retirePath != "" {
		if g, ok := rec.retired[retirePath]; ok {
			if g.refc > 0 {
				g.state = genRetiredCommitted
			} else {
				// No reader ever opened it: reclaim is the
				// caller's job right after commit.
				g.state = genRetiredCommitted
				g.reclaimNow = true
			}
		}
	}
}

// commitRetireRollback undoes the registry effect of a retire whose
// publication failed and was restored.
func (c *coord) commitRetireRollback(bucket, key, retirePath string) {
	if retirePath == "" {
		return
	}
	ck := canonicalKey(bucket, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec := c.keys[ck]; rec != nil {
		delete(rec.retired, retirePath)
		if rec.live == nil && len(rec.retired) == 0 {
			delete(c.keys, ck)
		}
	}
}

// retireePinned reports whether a retire path still has readers.
func (c *coord) retireePinned(bucket, retirePath string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rec := range c.keys {
		if g, ok := rec.retired[retirePath]; ok && g.refc > 0 {
			return true
		}
	}
	return false
}

// bucketHeld reports whether the bucket carries unresolved recovery
// state (records or a scan hold) that blocks destructive cleanup.
func (c *coord) bucketHeld(bucket string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hold[bucket] {
		return true
	}
	for _, r := range c.recovery {
		if r.bucket == bucket {
			return true
		}
	}
	return false
}

// recordProtected reports whether the bucket still carries records
// protecting live artifacts (reader-pinned retirees, recovery
// entries, in-flight publications). Cleanup must leave their op-
// records in place: removing a record while its retiree survives
// would orphan the artifact.
func (c *coord) recordProtected(bucket string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hold[bucket] {
		return true
	}
	for _, r := range c.recovery {
		if r.bucket == bucket {
			return true
		}
	}
	for _, rec := range c.keys {
		for _, g := range rec.retired {
			if g.state == genRetiredPending || g.state == genRecovery {
				return true
			}
		}
	}
	return false
}

// idleRetire returns the retire path of a committed retiree that has
// no reader and clears its bookkeeping; empty when the newest retiree
// still has readers or is pending.
func (c *coord) idleRetire(bucket, key string) string {
	ck := canonicalKey(bucket, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.keys[ck]
	if rec == nil {
		return ""
	}
	for p, g := range rec.retired {
		if g.reclaimNow {
			delete(rec.retired, p)
			if rec.live == nil && len(rec.retired) == 0 {
				delete(c.keys, ck)
			}
			return p
		}
	}
	return ""
}

// held reports whether the key or its bucket is blocked.
func (c *coord) held(bucket, key string) bool {
	ck := canonicalKey(bucket, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hold[bucket] {
		return true
	}
	if _, ok := c.recovery[ck]; ok {
		return true
	}
	// recovery records keyed by op id: linear scan is fine, records
	// are few (they require operator reconciliation).
	for _, r := range c.recovery {
		if r.bucket == bucket && (r.key == ck || r.kind == "upload-session" && r.key == ck) {
			return true
		}
	}
	return false
}

// uploadHeld reports whether an upload session is quarantined.
func (c *coord) uploadHeld(bucket, key, uploadID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.recovery {
		if r.id == uploadID || r.kind == "upload-session" && r.id == uploadID {
			return true
		}
	}
	return false
}

// sweepIdle prunes records with no leases, no active work, and no
// recovery entries. The live record stays while the object exists.
func (c *coord) sweepIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, rec := range c.keys {
		for p, g := range rec.retired {
			if g.state == genRetiredCommitted && g.refc == 0 && g.retired == "" {
				delete(rec.retired, p)
			}
		}
		if rec.live == nil && len(rec.retired) == 0 {
			delete(c.keys, k)
		}
	}
}

// classifyResidue is the startup scan. It runs before any admission
// gate opens and never restores anything: valid records quarantine
// their key, orphan artifacts with no readable record hold the
// bucket. See the record protocol in records.go.
func (c *coord) classifyResidue(fs FS) error {
	if fs == nil {
		return nil
	}
	buckets, err := fs.ReadDir(".")
	if err != nil {
		return nil
	}
	var holds []string
	for _, b := range buckets {
		if !b.IsDir || strings.HasPrefix(b.Name, ".") {
			continue
		}
		tmp := objectPath(b.Name, tmpDirName)
		ents, err := fs.ReadDir(tmp)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			switch {
			case strings.HasPrefix(ent.Name, "op-"):
				if r, ok := parseRecord(fs, path.Join(tmp, ent.Name)); ok {
					c.mu.Lock()
					c.recovery[r.id] = r
					c.mu.Unlock()
					continue
				}
				holds = append(holds, b.Name)
			case strings.HasPrefix(ent.Name, "retire-"), strings.HasPrefix(ent.Name, "put-"):
				holds = append(holds, b.Name)
			}
		}
	}
	if len(holds) > 0 {
		sort.Strings(holds)
		c.mu.Lock()
		for _, b := range holds {
			c.hold[b] = true
		}
		c.mu.Unlock()
	}
	return nil
}

// parseRecord decodes one op-<uuid> record. A record that cannot be
// read or validated in full returns false: its artifacts fall to the
// bucket-level hold instead of a guessed key.
func parseRecord(fs FS, p string) (*recoveryRec, bool) {
	obj, err := fs.Open(p, openRead)
	if err != nil {
		return nil, false
	}
	defer fs.Release(obj)
	raw, err := readFullAll(fs, obj)
	if err != nil || len(raw) == 0 || len(raw) > maxRecordBytes {
		return nil, false
	}
	var r recoveryRec
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, false
	}
	if r.bucket == "" || r.kind == "" || r.id == "" {
		return nil, false
	}
	return &r, true
}

// readFullAll drains a regular file through the seam; used for
// recovery records, which are small.
func readFullAll(fs FS, obj Object) ([]byte, error) {
	var out []byte
	off := int64(0)
	buf := make([]byte, 4096)
	for {
		n, err := fs.Read(obj, buf, off)
		if n > 0 {
			out = append(out, buf[:n]...)
			off += int64(n)
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
	}
}

var errBucketHeld = errors.New("daos: bucket has unresolved residue; reconciliation required")

// errAmbiguousMove marks a Move whose failure may have left both
// names alive: relaxed-mode dfs_move inserts the destination and
// copies xattrs before removing the source, so an error after the
// insert leaves an alias. The fake injects it; production Maps treat
// every failed alias-capable Move conservatively via quarantine.
var errAmbiguousMove = errors.New("daos: move outcome ambiguous; both names may exist")

// newOpID mints the operation UUID identifying one publication or
// its durable record.
func newOpID() string {
	return uuid.NewString()
}

// maxRecordBytes bounds recovery-record reads. Records carry one key
// and a handful of artifact paths; the bound only rejects corruption,
// never a supported key length.
const maxRecordBytes = 1 << 20
