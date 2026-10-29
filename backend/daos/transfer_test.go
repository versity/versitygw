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

package daos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

type cappedFS struct {
	FS
	n int
}

func (c cappedFS) Read(obj Object, buf []byte, off int64) (int, error) {
	if c.n > 0 && len(buf) > c.n {
		buf = buf[:c.n]
	}
	return c.FS.Read(obj, buf, off)
}

func (c cappedFS) Write(obj Object, buf []byte, off int64) (int, error) {
	if c.n > 0 && len(buf) > c.n {
		buf = buf[:c.n]
	}
	return c.FS.Write(obj, buf, off)
}

type stallReadFS struct{ FS }

func (s stallReadFS) Read(Object, []byte, int64) (int, error) {
	return 0, nil
}

func TestShortTransferStillMovesTheWholeObject(t *testing.T) {
	d, fs := newTest(t)
	d.fs = cappedFS{FS: fs, n: 4096}
	body := bytes.Repeat([]byte("abc"), 4000)

	if _, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
		Body:   bytes.NewReader(body),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, body) {
		t.Fatalf("get length %d, want %d", len(read), len(body))
	}
	if got.ContentLength == nil || *got.ContentLength != int64(len(body)) {
		t.Fatalf("content length %v", got.ContentLength)
	}

	if _, err := d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("copy"),
		CopySource: backend.GetPtrFromString("bucket/obj"),
	}); err != nil {
		t.Fatal(err)
	}
	copied, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("copy"),
	})
	if err != nil {
		t.Fatal(err)
	}
	read, err = io.ReadAll(copied.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, body) {
		t.Fatalf("copy length %d, want %d", len(read), len(body))
	}
}

func TestStalledReadIsNotAShortObject(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "obj", "hello", "text/plain", nil)
	d.fs = stallReadFS{fs}
	_, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
}
