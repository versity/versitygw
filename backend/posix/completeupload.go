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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// Multipart upload completion
//
// The gateway is stateless and gateway processes may share a backend without
// a lock that excludes them, so CompleteMultipartUpload leaves nothing on disk
// that only a live owner could resolve. It doesn't claim the upload: the
// upload directory stays in place, listable, abortable and completable, while
// the object is assembled from its parts into a staging file of the call's
// own. The object is published by linking the staging file, and the upload is
// retired only after that. A completion that dies leaves either the upload as
// it was, or the published object, which carries the upload ID in its
// multipart metadata, and a retry recognizes it by that.
//
// Retiring renames the upload directory to <uploadId>.retired in one step,
// so the upload stops being listable, abortable and completable at once, and
// then removes it. Only the rename is done under the publish lock: removing
// the parts of a large upload takes long, and would hold back the other
// writers that share the lock. A retired upload only exists after its object
// was published, or after a completion moved its parts into an object that
// failed, so whatever is left of one is garbage, and any call that finds it
// removes it.
//
// Concurrent completions of an upload each assemble the object, and the
// first to publish it retires the upload. The others find the upload retired,
// when a part they open is gone or under the publish lock before they
// publish, and return the published object's ETag and VersionId. The publish
// lock makes that check and the publish one step only across the processes
// that its object lock mode excludes; processes it doesn't exclude can
// publish the same object twice, which on a versioned bucket leaves an extra
// version of the same data.
//
// A custom copy, such as the scoutfs move blocks, can move the data of the
// parts into the object, after which no other completion can use them. The
// completion that creates the consumed marker in the upload directory is the
// only one that may read the parts, and the others are told to retry until
// the object is published. If the completion fails after moving data the
// upload is retired. If it dies the data it moved is lost, and the upload
// stays listed and abortable with the marker, so completing it fails with
// SlowDown and its space can be reclaimed.

const (
	// retiredUploadSuffix names the directory of a retired upload.
	retiredUploadSuffix = ".retired"
	// uploadConsumedName marks an upload whose parts a completion may move
	// into the object it assembles.
	uploadConsumedName = ".consumed"
)

// publishedUpload reports whether the object at the key, given by its
// encoded name, was published by the upload, and returns the result of the
// completion that published it. A completion that lists other parts than the
// object was published with fails with NoSuchUpload. Multipart uploads are
// never created for keys with a trailing slash, and a directory at the object
// path is the object of such a key.
func (p *Posix) publishedUpload(bucket, object, key, uploadID, partsETag string) (bool, s3response.CompleteMultipartUploadResult, string, error) {
	var res s3response.CompleteMultipartUploadResult
	if strings.HasSuffix(object, "/") {
		return false, res, "", nil
	}
	fi, err := os.Stat(p.ObjectPath(bucket, object))
	if errors.Is(err, fs.ErrNotExist) || isErrNotDir(err) {
		return false, res, "", nil
	}
	if isErrNameTooLong(err) {
		return false, res, "", s3err.GetKeyTooLongErr(int64(len(key)), 1024)
	}
	if err != nil {
		return false, res, "", fmt.Errorf("stat object: %w", err)
	}
	if fi.IsDir() {
		return false, res, "", nil
	}

	mpMetaBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, mpMetaKey)
	if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
		return false, res, "", nil
	}
	if err != nil {
		return false, res, "", fmt.Errorf("get object multipart metadata: %w", err)
	}
	mpMeta, err := backend.UnmarshalMpUploadMetadata(mpMetaBytes, false)
	if err != nil {
		return false, res, "", fmt.Errorf("parse object multipart metadata: %w", err)
	}
	if mpMeta.UploadID != uploadID {
		return false, res, "", nil
	}

	etagBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, etagkey)
	if err != nil {
		return true, res, "", fmt.Errorf("get object etag: %w", err)
	}
	etag := string(etagBytes)
	// A retry has to list the parts the upload was completed with. The
	// data integrity ETag is the object checksum rather than the ETag of
	// the parts, so only the upload ID is checked in that mode.
	if !p.dataIntegrityEtag && etag != partsETag {
		return true, res, "", s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}

	versionID, err := p.meta.RetrieveAttribute(nil, bucket, object, versionIdKey)
	if err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
		return true, res, "", fmt.Errorf("get object version id: %w", err)
	}

	return true, s3response.CompleteMultipartUploadResult{
		Bucket: &bucket,
		ETag:   &etag,
		Key:    &key,
	}, string(versionID), nil
}

// retireUpload retires the upload by renaming its directory, in objdir of the
// bucket, out of the way. An upload already retired or aborted needs no
// rename. The caller removes what is left with removeRetiredUpload, which
// needn't hold the publish lock.
func (p *Posix) retireUpload(bucket, objdir, uploadID string) error {
	objdirFull := p.ObjectPath(bucket, objdir)
	err := os.Rename(filepath.Join(objdirFull, uploadID),
		filepath.Join(objdirFull, uploadID+retiredUploadSuffix))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rename upload: %w", err)
	}
	return nil
}

// removeAllRetired removes the directory of a retired upload. It is a
// variable so tests can observe the calls.
var removeAllRetired = os.RemoveAll

// removeRetiredUpload removes what is left of the retired upload in objdir of
// the bucket.
func (p *Posix) removeRetiredUpload(bucket, objdir, uploadID string) error {
	err := removeAllRetired(filepath.Join(p.ObjectPath(bucket, objdir), uploadID+retiredUploadSuffix))
	if err != nil {
		return fmt.Errorf("remove retired upload: %w", err)
	}
	// Sidecar metadata stays at the path of the upload. With xattr this is
	// a no-op.
	_ = p.meta.DeleteAttributes(bucket, filepath.Join(objdir, uploadID))
	return nil
}

// markUploadConsumed creates the consumed marker in the upload directory. It
// fails with fs.ErrExist when another completion created it.
func (p *Posix) markUploadConsumed(uploadDir string) error {
	marker := filepath.Join(uploadDir, uploadConsumedName)
	f, err := os.OpenFile(marker, os.O_RDWR|os.O_CREATE|os.O_EXCL, defaultNewFilePerm)
	if err != nil {
		return fmt.Errorf("create upload consumed marker: %w", err)
	}
	f.Close()
	if p.fsync {
		// the marker is durable before any part data is moved
		err = syncDir(uploadDir)
		if err != nil {
			os.Remove(marker)
			return fmt.Errorf("sync upload consumed marker: %w", err)
		}
	}
	return nil
}

// uploadConsumed reports whether the upload directory has the consumed
// marker.
func (p *Posix) uploadConsumed(uploadDir string) bool {
	_, err := os.Lstat(filepath.Join(uploadDir, uploadConsumedName))
	return err == nil
}
