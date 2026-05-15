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
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/versity/versitygw/s3err"
)

func TestMpUploadMetadataRawGzipRoundTrip(t *testing.T) {
	want := MpUploadMetadata{
		UploadID: "upload-id",
		Parts:    []int64{5, 12, 12},
	}

	stored, err := MarshalMpUploadMetadata(want, false)
	if err != nil {
		t.Fatalf("MarshalMpUploadMetadata: %v", err)
	}
	if len(stored) < 2 || stored[0] != 0x1f || stored[1] != 0x8b {
		t.Fatalf("stored metadata should contain raw gzip payload: %q", stored)
	}
	if bytes.HasPrefix(stored, []byte("{")) {
		t.Fatalf("stored metadata should not be raw JSON: %q", stored)
	}

	got, err := UnmarshalMpUploadMetadata(stored, false)
	if err != nil {
		t.Fatalf("UnmarshalMpUploadMetadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata mismatch: got %+v want %+v", got, want)
	}
}

func TestMpUploadMetadataBase64RoundTrip(t *testing.T) {
	want := MpUploadMetadata{
		UploadID: "azure-upload-id",
		Parts:    []int64{10, 20, 35},
	}

	stored, err := MarshalMpUploadMetadata(want, true)
	if err != nil {
		t.Fatalf("MarshalMpUploadMetadata: %v", err)
	}
	if len(stored) >= 2 && stored[0] == 0x1f && stored[1] == 0x8b {
		t.Fatalf("stored metadata should not contain raw gzip bytes: %q", stored)
	}

	got, err := UnmarshalMpUploadMetadata(stored, true)
	if err != nil {
		t.Fatalf("UnmarshalMpUploadMetadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata mismatch: got %+v want %+v", got, want)
	}
}

func TestUnmarshalMpUploadMetadataLegacyJSON(t *testing.T) {
	want := MpUploadMetadata{
		UploadID: "legacy-upload-id",
		Parts:    []int64{1, 3, 6},
	}

	stored, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	got, err := UnmarshalMpUploadMetadata(stored, false)
	if err != nil {
		t.Fatalf("UnmarshalMpUploadMetadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata mismatch: got %+v want %+v", got, want)
	}
	got, err = UnmarshalMpUploadMetadata(stored, true)
	if err != nil {
		t.Fatalf("UnmarshalMpUploadMetadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata mismatch: got %+v want %+v", got, want)
	}
}

func TestUnmarshalMpUploadMetadataInvalid(t *testing.T) {
	_, err := UnmarshalMpUploadMetadata([]byte("not-gzip-or-json"), false)
	if err == nil {
		t.Fatal("expected invalid metadata error")
	}
}

func TestParseCopySource(t *testing.T) {
	tests := []struct {
		name             string
		copySourceHeader string
		wantBucket       string
		wantObject       string
		wantVersionId    string
		wantErr          bool
		wantErrCode      s3err.ErrorCode
	}{
		{
			name:             "simple path",
			copySourceHeader: "mybucket/myobject",
			wantBucket:       "mybucket",
			wantObject:       "myobject",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "path with leading slash",
			copySourceHeader: "/mybucket/myobject",
			wantBucket:       "mybucket",
			wantObject:       "myobject",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "path with versionId",
			copySourceHeader: "mybucket/myobject?versionId=abc123",
			wantBucket:       "mybucket",
			wantObject:       "myobject",
			wantVersionId:    "abc123",
			wantErr:          false,
		},
		{
			name:             "URL-encoded curly braces",
			copySourceHeader: "mybucket/myfolder/%7Be14c392b-09ad-4188-85f4-b779af00fb88%7D/testfile",
			wantBucket:       "mybucket",
			wantObject:       "myfolder/{e14c392b-09ad-4188-85f4-b779af00fb88}/testfile",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "URL-encoded space",
			copySourceHeader: "mybucket/my%20object",
			wantBucket:       "mybucket",
			wantObject:       "my object",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "URL-encoded special chars",
			copySourceHeader: "mybucket/obj%23%24%25%26",
			wantBucket:       "mybucket",
			wantObject:       "obj#$%&",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "URL-encoded path with versionId",
			copySourceHeader: "mybucket/my%20folder/my%20object?versionId=xyz789",
			wantBucket:       "mybucket",
			wantObject:       "my folder/my object",
			wantVersionId:    "xyz789",
			wantErr:          false,
		},
		{
			name:             "percent-encoded slash as bucket/key separator",
			copySourceHeader: "my-namespace-test-container%2Ftest-blob",
			wantBucket:       "my-namespace-test-container",
			wantObject:       "test-blob",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "percent-encoded slash separator with leading slash",
			copySourceHeader: "/my-namespace-test-container%2Ftest-blob",
			wantBucket:       "my-namespace-test-container",
			wantObject:       "test-blob",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "percent-encoded slash separator with versionId",
			copySourceHeader: "my-bucket%2Fmy-object?versionId=abc123",
			wantBucket:       "my-bucket",
			wantObject:       "my-object",
			wantVersionId:    "abc123",
			wantErr:          false,
		},
		{
			name:             "percent-encoded slash separator with encoded object key",
			copySourceHeader: "my-bucket%2Fmy%20folder%2Fmy%20object",
			wantBucket:       "my-bucket",
			wantObject:       "my folder/my object",
			wantVersionId:    "",
			wantErr:          false,
		},
		{
			name:             "invalid URL encoding - incomplete escape",
			copySourceHeader: "mybucket/object%",
			wantBucket:       "",
			wantObject:       "",
			wantVersionId:    "",
			wantErr:          true,
			wantErrCode:      s3err.ErrInvalidCopySourceEncoding,
		},
		{
			name:             "invalid URL encoding - invalid hex",
			copySourceHeader: "mybucket/object%ZZ",
			wantBucket:       "",
			wantObject:       "",
			wantVersionId:    "",
			wantErr:          true,
			wantErrCode:      s3err.ErrInvalidCopySourceEncoding,
		},
		{
			name:             "missing object",
			copySourceHeader: "mybucket",
			wantBucket:       "",
			wantObject:       "",
			wantVersionId:    "",
			wantErr:          true,
			wantErrCode:      s3err.ErrInvalidCopySourceBucket,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBucket, gotObject, gotVersionId, err := ParseCopySource(tt.copySourceHeader)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCopySource() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, s3err.GetAPIError(tt.wantErrCode)) {
					t.Errorf("ParseCopySource() error = %v, want error code %v", err, tt.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCopySource() unexpected error = %v", err)
				return
			}

			if gotBucket != tt.wantBucket {
				t.Errorf("ParseCopySource() gotBucket = %v, want %v", gotBucket, tt.wantBucket)
			}
			if gotObject != tt.wantObject {
				t.Errorf("ParseCopySource() gotObject = %v, want %v", gotObject, tt.wantObject)
			}
			if gotVersionId != tt.wantVersionId {
				t.Errorf("ParseCopySource() gotVersionId = %v, want %v", gotVersionId, tt.wantVersionId)
			}
		})
	}
}
