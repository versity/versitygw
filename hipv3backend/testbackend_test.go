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

package hipv3backend

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

// capturingBackend records what the adapter hands to the wrapped
// backend. Every method the adapter intercepts is captured; the rest
// panic via the unsupported base so an unexpected call is a test
// failure, not a silent pass.
type capturingBackend struct {
	backend.BackendUnsupported

	putCalls int
	putLen   int64
	putBody  []byte
	etag     string

	partLen  int64
	partBody []byte

	getObject    []byte
	getErr       error
	contentRange string // returned as Content-Range when non-empty
	declared     int64  // when nonzero, reported length differs from the stream
	getCalls     int
}

func (b *capturingBackend) PutObject(_ context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	b.putCalls++
	b.putLen = derefI64(po.ContentLength)
	body, _ := io.ReadAll(po.Body)
	b.putBody = body
	b.etag = "\"adapter-test-etag\""
	return s3response.PutObjectOutput{ETag: b.etag}, nil
}

func (b *capturingBackend) UploadPart(_ context.Context, up *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	b.partLen = derefI64(up.ContentLength)
	body, _ := io.ReadAll(up.Body)
	b.partBody = body
	return &s3.UploadPartOutput{}, nil
}

func (b *capturingBackend) GetObject(_ context.Context, _ *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	b.getCalls++
	if b.getErr != nil {
		return nil, b.getErr
	}
	n := int64(len(b.getObject))
	if b.declared != 0 {
		n = b.declared
	}
	out := &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(b.getObject)),
		ContentLength: &n,
	}
	if b.contentRange != "" {
		cr := b.contentRange
		out.ContentRange = &cr
	}
	return out, nil
}

func putInput(length int64) s3response.PutObjectInput {
	bucket, key := "b", "k"
	l := length
	return s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		ContentLength: &l,
		Body:          bytes.NewReader(nil),
	}
}

func partInput() *s3.UploadPartInput {
	bucket, key, upid := "b", "k", "upload-1"
	var part int32 = 1
	return &s3.UploadPartInput{
		Bucket:     &bucket,
		Key:        &key,
		UploadId:   &upid,
		PartNumber: &part,
	}
}

func getInput() *s3.GetObjectInput {
	bucket, key := "b", "k"
	return &s3.GetObjectInput{Bucket: &bucket, Key: &key}
}

var _ = errors.New
