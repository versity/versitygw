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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"

	"github.com/google/uuid"
)

// Durable recovery records. A record is written before the first
// artifact or namespace mutation of an operation and survives until
// every artifact it names is gone or its ownership has moved to
// another record or generation. On restart the scan classifies
// records first and never restores anything: valid records quarantine
// their key, and artifacts without a readable record hold the whole
// bucket. See plans/2026-11-10-pr2484-r2-remediation-v4.md.

// record kinds.
const (
	recKindPut           = "put"
	recKindCopy          = "copy"
	recKindMPUPublish    = "mpu-publish"
	recKindDelete        = "delete"
	recKindUploadSession = "upload-session"
)

// opRecord is the JSON body of an op-<uuid> file. Fields are frozen
// at write time; amendments supersede rather than rewrite.
type opRecord struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Bucket    string   `json:"bucket"`
	Key       string   `json:"key"`
	Staging   string   `json:"staging,omitempty"`
	Retire    string   `json:"retire,omitempty"`
	UploadID  string   `json:"upload_id,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
}

// recordPath names the durable record of one operation. The file name
// is a fixed 44 bytes: the component limit never depends on the key.
func recordPath(bucket, id string) string {
	return objectPath(bucket, tmpDirName+"/op-"+id)
}

// retireName is the retire file name of one generation: a 16-hex key
// hash for scan grouping plus the full operation UUID, so two
// operations on the same key can never collide on one path.
func retireName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "retire-" + hex.EncodeToString(sum[:8]) + "-" + uuid.NewString()
}

// retirePath places a retire name under the bucket's temporary root.
func retirePathFor(bucket, key string) string {
	return objectPath(bucket, tmpDirName+"/"+retireName(key))
}

// writeRecord stores one complete record. The write must be
// acknowledged in full before any destructive or alias-producing
// operation runs; short or failed writes abort the operation.
func (d *Daos) writeRecord(r opRecord) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if err := d.mkdirParents(recordPath(r.Bucket, r.ID)); err != nil {
		return err
	}
	obj, err := d.fs.Open(recordPath(r.Bucket, r.ID), openWrite|openCreate|openExcl)
	if err != nil {
		return mapFS(err)
	}
	defer d.fs.Release(obj)
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := writeFull(d.fs, obj, raw, 0); err != nil {
		return mapFS(err)
	}
	return nil
}

// removeRecord drops a record once its artifacts are gone or their
// ownership has moved. Interruptions fall back to the restart scan.
func (d *Daos) removeRecord(bucket, id string) {
	_ = d.fs.Remove(recordPath(bucket, id), false)
}

// recordForUpload builds the session record created at
// CreateMultipartUpload time and amended before every alias-producing
// upload Move.
func recordForUpload(bucket, key, uploadID string) opRecord {
	return opRecord{
		ID:       uploadID,
		Kind:     recKindUploadSession,
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	}
}

// amendRecord supersedes one record with a fuller one. The successor
// carries the old ID in Artifacts so the pair stays linked until both
// are disposable; supersede-and-retain, never rewrite in place.
func (d *Daos) amendRecord(old opRecord, next opRecord) error {
	if next.ID == "" || next.ID == old.ID {
		next.ID = uuid.NewString()
	}
	next.Artifacts = append([]string{recordPath(old.Bucket, old.ID)}, next.Artifacts...)
	return d.writeRecord(next)
}

// claimUploadName returns the deterministic claim directory name of
// one upload completion, mirroring CompleteMultipartUpload.
func claimUploadName(uploadID, etag string) string {
	return uploadID + "." + trimETagQuotes(etag) + inProgressSuffix
}

func trimETagQuotes(etag string) string {
	if len(etag) >= 2 && etag[0] == '"' && etag[len(etag)-1] == '"' {
		return etag[1 : len(etag)-1]
	}
	return etag
}

// stagingName returns a fresh staging path under the bucket's
// temporary root.
func stagingName(bucket string) string {
	return objectPath(bucket, tmpDirName+"/put-"+uuid.NewString())
}

// partTmpName returns the hidden temporary name a part is written
// under before its publishing Move.
func partTmpName(uploadDir string) string {
	return path.Join(uploadDir, ".part-"+uuid.NewString())
}
