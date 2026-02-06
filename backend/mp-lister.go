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

package backend

import (
	"strings"

	"github.com/google/uuid"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// ListMultipartUploads initializes a multipart upload lister and calls Run()
func ListMultipartUploads(uploads []s3response.Upload, prefix, delimiter, keyMarker, uploadIdMarker string, maxUploads int) (*ListMultipartUploadsPage, error) {
	lister := &MultipartUploadLister{
		Uploads:        uploads,
		Prefix:         prefix,
		Delimiter:      delimiter,
		KeyMarker:      keyMarker,
		UploadIDMarker: uploadIdMarker,
		MaxUploads:     maxUploads,
	}

	return lister.Run()
}

// MultipartUploadLister emits a ListMultipartUploads-compatible page from an
// already-sorted, already prefix- and key-marker-filtered upload list.
//
// Assumptions about input Uploads:
//   - Sorted by (Key asc, Initiated asc)
//   - Filtered by Prefix
//   - Filtered to start strictly after key-marker when key-marker was provided.
type MultipartUploadLister struct {
	Uploads        []s3response.Upload
	Prefix         string
	Delimiter      string
	MaxUploads     int
	KeyMarker      string
	UploadIDMarker string
}

// ListMultipartUploadsPage is the lister output
type ListMultipartUploadsPage struct {
	Uploads            []s3response.Upload
	CommonPrefixes     []s3response.CommonPrefix
	IsTruncated        bool
	NextKeyMarker      string
	NextUploadIDMarker string
}

// Run validates marker constraints, then performs a single-pass list that:
// - collapses uploads into CommonPrefixes when delimiter is set
// - enforces MaxUploads over (Uploads + CommonPrefixes)
// - computes truncation and next markers
func (l *MultipartUploadLister) Run() (*ListMultipartUploadsPage, error) {
	out := &ListMultipartUploadsPage{}

	var startIndex int

	// if upload-id-marker is provided without a corresponding key-marker, ignore it.
	uploadIDMarker := l.UploadIDMarker
	if l.KeyMarker == "" {
		uploadIDMarker = ""
	}

	if uploadIDMarker != "" {
		// any invalid uuid is considered as an invalid uploadIdMarker
		_, err := uuid.Parse(uploadIDMarker)
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidUploadIdMarker)
		}
		startIndex = l.findUploadIdMarkerIndex(uploadIDMarker)
		if startIndex == -1 {
			return nil, s3err.GetAPIError(s3err.ErrInvalidUploadIdMarker)
		}
		if startIndex >= len(l.Uploads) {
			return out, nil
		}
	}

	// Common prefix uniqueness tracking.
	seenCP := make(map[string]struct{})

	emitted := 0
	var lastKey string

	// emitUpload appends a new upload to out.Uplodas
	emitUpload := func(up s3response.Upload) bool {
		out.Uploads = append(out.Uploads, up)
		emitted++
		lastKey = up.Key
		return emitted == l.MaxUploads
	}
	// emitCp appends a new common prefix to out.CommonPrefixes
	emitCP := func(cpref string) bool {
		out.CommonPrefixes = append(out.CommonPrefixes, s3response.CommonPrefix{Prefix: cpref})
		emitted++
		lastKey = cpref
		return emitted == l.MaxUploads
	}

	for i, up := range l.Uploads[startIndex:] {
		if l.Delimiter != "" {
			// delimiter check
			suffix := strings.TrimPrefix(up.Key, l.Prefix)
			before, _, found := strings.Cut(suffix, l.Delimiter)
			if found {
				cpref := l.Prefix + before + l.Delimiter
				if _, ok := seenCP[cpref]; !ok {
					seenCP[cpref] = struct{}{}
					if emitCP(cpref) {
						out.IsTruncated = l.hasMoreAfter(i+1, seenCP)
						if out.IsTruncated {
							out.NextKeyMarker = lastKey
							out.NextUploadIDMarker = up.UploadID
						}
						return out, nil
					}
				}
				continue
			}
		}

		if emitUpload(up) {
			out.IsTruncated = l.hasMoreAfter(i+1, seenCP)
			if out.IsTruncated {
				out.NextKeyMarker = lastKey
				out.NextUploadIDMarker = up.UploadID
			}
			return out, nil
		}
	}

	return out, nil
}

// findUploadIdMarkerIndex finds the index of given uploadId marker in uploads
// uploadIDMarker must match an upload-id among uploads with the first key after KeyMarker.
// Since caller filtered to Key > KeyMarker and the list is sorted by key/time,
// the first key after KeyMarker is Uploads[0].Key (if any).
// -1 is returned if no uploadId is found
func (l *MultipartUploadLister) findUploadIdMarkerIndex(uploadIDMarker string) int {
	if len(l.Uploads) == 0 {
		// key-marker provided but nothing after it => upload-id-marker can never be valid.
		return -1
	}
	firstKey := l.Uploads[0].Key

	// it must match an upload-id under firstKey only.
	// If firstKey has multiple uploads, any of those IDs is valid.
	for i, up := range l.Uploads {
		if up.Key != firstKey {
			// sorted by key, so we're past firstKey group
			break
		}
		if up.UploadID == uploadIDMarker {
			// the listing should start from the next index
			// to skip the uploadId marker
			return i + 1
		}
	}
	return -1
}

// hasMoreAfter checks if there exists at least one more effective item after idx,
// considering delimiter collapse and already-emitted common prefixes.
func (l *MultipartUploadLister) hasMoreAfter(idx int, seenCP map[string]struct{}) bool {
	if idx >= len(l.Uploads) {
		return false
	}
	if l.Delimiter == "" {
		// any remaining upload would be emitted
		return true
	}

	for i := idx; i < len(l.Uploads); i++ {
		up := l.Uploads[i]
		suffix := strings.TrimPrefix(up.Key, l.Prefix)
		before, _, found := strings.Cut(suffix, l.Delimiter)
		if !found {
			// would emit an upload
			return true
		}
		cpref := l.Prefix + before + l.Delimiter
		if _, ok := seenCP[cpref]; ok {
			continue
		}
		// would emit a new common prefix
		return true
	}
	return false
}
