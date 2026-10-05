// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

//go:build linux && cgo && daos

package daos

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

func TestXattrSurvivesMove(t *testing.T) {
	pool := os.Getenv("DAOS_POOL")
	cont := os.Getenv("DAOS_CONT")
	if pool == "" || cont == "" {
		t.Skip("DAOS_POOL and DAOS_CONT are required")
	}
	fs, err := openContainer(pool, os.Getenv("DAOS_SYS"), cont)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	dir := "vgw-gate-" + uuid.NewString()
	if err := fs.Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(dir, true)

	src := dir + "/tmp"
	dst := dir + "/final"
	obj, err := fs.Open(src, openWrite|openCreate|openExcl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(obj, []byte("hello"), 0); err != nil {
		fs.Release(obj)
		t.Fatal(err)
	}
	etag := []byte(`"etag-value"`)
	ctype := []byte("text/plain")
	meta := []byte(`{"origin":"lab"}`)
	for _, pair := range []struct {
		name string
		val  []byte
	}{
		{attrETag, etag},
		{attrContentType, ctype},
		{attrMetadata, meta},
	} {
		if err := fs.SetXattr(obj, pair.name, pair.val); err != nil {
			fs.Release(obj)
			t.Fatal(err)
		}
	}
	if err := fs.Release(obj); err != nil {
		t.Fatal(err)
	}
	if err := fs.Move(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Open(dst, openRead)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Release(got)
	buf := make([]byte, 5)
	n, err := fs.Read(got, buf, 0)
	if err != nil || n != 5 || string(buf) != "hello" {
		t.Fatalf("read %q n %d err %v", buf[:n], n, err)
	}
	for _, pair := range []struct {
		name string
		val  []byte
	}{
		{attrETag, etag},
		{attrContentType, ctype},
		{attrMetadata, meta},
	} {
		b, err := fs.GetXattr(got, pair.name)
		if err != nil {
			t.Fatal(pair.name, err)
		}
		if string(b) != string(pair.val) {
			t.Fatalf("%s = %q, want %q", pair.name, b, pair.val)
		}
	}
}

func TestServingPutReadsAttributes(t *testing.T) {
	pool := os.Getenv("DAOS_POOL")
	cont := os.Getenv("DAOS_CONT")
	if pool == "" || cont == "" {
		t.Skip("DAOS_POOL and DAOS_CONT are required")
	}
	sys := os.Getenv("DAOS_SYS")
	fs, err := openContainer(pool, sys, cont)
	if err != nil {
		t.Fatal(err)
	}
	bucket := "vgw-gate-" + uuid.NewString()
	if err := fs.Mkdir(bucket); err != nil {
		fs.Close()
		t.Fatal(err)
	}
	fs.Close()
	t.Cleanup(func() {
		fs, err := openContainer(pool, sys, cont)
		if err != nil {
			t.Errorf("cleanup open: %v", err)
			return
		}
		defer fs.Close()
		if err := fs.Remove(bucket, true); err != nil {
			t.Errorf("cleanup bucket: %v", err)
		}
	})

	be, err := New(pool, cont, sys)
	if err != nil {
		t.Fatal(err)
	}
	defer be.Shutdown()
	out, err := be.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:      backend.GetPtrFromString(bucket),
		Key:         backend.GetPtrFromString("dir/obj"),
		Body:        bytes.NewReader([]byte("hello")),
		ContentType: backend.GetPtrFromString("text/plain"),
		Metadata:    map[string]string{"origin": "lab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := be.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString(bucket),
		Key:    backend.GetPtrFromString("dir/obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	got.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" || awsString(got.ETag) != out.ETag || awsString(got.ContentType) != "text/plain" || got.Metadata["origin"] != "lab" {
		t.Fatalf("body %q etag %q type %q meta %v", body, awsString(got.ETag), awsString(got.ContentType), got.Metadata)
	}
}
