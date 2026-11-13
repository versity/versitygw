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
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Schedules for the coordinated publication path. Each asserts one
// property of the retire-then-publish ordering: a reader that already
// opened an object keeps streaming across overwrites and deletes, a
// failed publication rolls the previous object back, a conditional
// copy does not race an unconditional writer, a quarantined upload
// refuses further parts, and retire names never collide across
// operations.

func putBody(t *testing.T, d *Daos, key string, body []byte) {
	t.Helper()
	if _, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString(key),
		Body:   bytes.NewReader(body),
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOverwriteKeepsLazyReader: a GET body opened before an
// overwrite streams the old generation to the end.
func TestOverwriteKeepsLazyReader(t *testing.T) {
	d, _ := newTest(t)
	putBody(t, d, "obj", bytes.Repeat([]byte("a"), 1024))
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	putBody(t, d, "obj", bytes.Repeat([]byte("b"), 1024))
	got, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("a"), 1024)) {
		t.Fatalf("lazy reader saw %q after overwrite", string(got[:8]))
	}
	out.Body.Close()
}

// TestDeleteKeepsLazyReader: a delete retires rather than punches;
// the open body still streams.
func TestDeleteKeepsLazyReader(t *testing.T) {
	d, _ := newTest(t)
	putBody(t, d, "obj", bytes.Repeat([]byte("x"), 512))
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 512 {
		t.Fatalf("lazy reader got %d bytes after delete, want 512", len(got))
	}
	out.Body.Close()
}

// TestRetireeReclaimsAfterLastReader: once the last reader closes,
// the retire slot is gone (no unbounded residue).
func TestRetireeReclaimsAfterLastReader(t *testing.T) {
	d, fs := newTest(t)
	putBody(t, d, "obj", []byte("v1"))
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	putBody(t, d, "obj", []byte("v2"))
	out.Body.Close()
	ents, err := fs.ReadDir("bucket/.sgwtmp")
	if err == nil {
		for _, ent := range ents {
			if strings.HasPrefix(ent.Name, "retire-") {
				t.Fatalf("retiree %s survived its last reader", ent.Name)
			}
		}
	}
}

// TestCopyIfMatchMissingDestIsRejected: If-Match against a missing
// destination is NoSuchKey, evaluated inside the publish.
func TestCopyIfMatchMissingDestIsRejected(t *testing.T) {
	d, _ := newTest(t)
	putBody(t, d, "src", []byte("data"))
	m := `"deadbeef"`
	_, err := d.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("dst"),
		CopySource: backend.GetPtrFromString("/bucket/src"),
		IfMatch:    &m,
	})
	if err == nil || !strings.Contains(err.Error(), "NoSuchKey") {
		t.Fatalf("copy with If-Match on missing dest = %v, want NoSuchKey", err)
	}
}

// TestRetireNameCarriesFullUUID: two operations on one key produce
// distinct retire names; the second retire cannot punch the first.
func TestRetireNameCarriesFullUUID(t *testing.T) {
	a, b := retireName("obj"), retireName("obj")
	if a == b {
		t.Fatalf("two operations on one key share retire name %s", a)
	}
	if len(a) > 255 {
		t.Fatalf("retire name %d bytes exceeds component limit", len(a))
	}
}

// TestPublishFailurePreservesOldObject: a failed publish Move rolls
// the retire back; the old object stays readable.
func TestPublishFailurePreservesOldObject(t *testing.T) {
	d, fs := newTest(t)
	putBody(t, d, "obj", []byte("old"))
	// fail the second Move (the publish): the first (retire) ran.
	fs.FailMoveOn(2)
	_, err := d.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
		Body:   bytes.NewReader([]byte("new")),
	})
	if err == nil {
		t.Fatal("put unexpectedly succeeded with injected publish failure")
	}
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("obj"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if string(got) != "old" {
		t.Fatalf("destination holds %q after failed publish, want old", got)
	}
}

// TestConditionalCopyRacesOrdinaryPut: a conditional copy and an
// unconditional PUT to the same destination serialize through the
// publish guard; the copy's condition sees the PUT or precedes it,
// never a torn middle state.
func TestConditionalCopyRacesOrdinaryPut(t *testing.T) {
	d, _ := newTest(t)
	putBody(t, d, "src", []byte("copy-body"))
	nm := `"missing-etag"`
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := d.CopyObject(context.Background(), s3response.CopyObjectInput{
			Bucket:     backend.GetPtrFromString("bucket"),
			Key:        backend.GetPtrFromString("dst"),
			CopySource: backend.GetPtrFromString("/bucket/src"),
			IfMatch:    &nm,
		})
		errs <- err
	}()
	go func() {
		defer wg.Done()
		putBody(t, d, "dst", []byte("put-body"))
		errs <- nil
	}()
	wg.Wait()
	close(errs)
	// The copy may win the race (publish first) or lose it cleanly:
	// a lost race surfaces as NoSuchKey (If-Match against the
	// destination the PUT replaced) or PreconditionFailed. Any other
	// error - including the PUT's - fails the test.
	for err := range errs {
		if err == nil {
			continue
		}
		if !strings.Contains(err.Error(), "NoSuchKey") &&
			!strings.Contains(err.Error(), "PreconditionFailed") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("dst"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if string(got) != "copy-body" && string(got) != "put-body" {
		t.Fatalf("destination holds torn state %q", got)
	}
}

// TestQuarantinedSessionRefusesParts: after a claim alias failure
// the session rejects further part writes and completion.
func TestQuarantinedSessionRefusesParts(t *testing.T) {
	d, _ := newTest(t)
	created := startUpload(t, d, "obj")
	id := created.UploadId
	uploadPart(t, d, "obj", id, 1, "part-1")
	// Quarantine directly through the coordinator, mirroring what a
	// failed claim Move does.
	if err := d.coord.quarantineUpload("bucket", "obj", id, nil); err == nil {
		t.Fatal("quarantine did not report its recovery error")
	}
	if _, err := d.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:     backend.GetPtrFromString("bucket"),
		Key:        backend.GetPtrFromString("obj"),
		UploadId:   &id,
		PartNumber: int32ptr(2),
		Body:       bytes.NewReader([]byte("part-2")),
	}); err == nil {
		t.Fatal("quarantined session accepted a part write")
	}
	if _, _, err := d.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   backend.GetPtrFromString("bucket"),
		Key:      backend.GetPtrFromString("obj"),
		UploadId: &id,
	}); err == nil {
		t.Fatal("quarantined session accepted completion")
	}
}

// TestStartupScanQuarantinesResidue: residue classified at startup
// holds the bucket; the scan never restores anything.
func TestStartupScanQuarantinesResidue(t *testing.T) {
	_, fs := newTest(t)
	// Plant an orphan retire entry with no record. newTest already
	// created the bucket.
	if err := fs.Mkdir("bucket/.sgwtmp"); err != nil {
		t.Fatal(err)
	}
	// Plant the orphan through a plain create under an existing
	// temporary root; no record accompanies it.
	if err := plantFile(fs, "bucket/.sgwtmp/retire-orphand"); err != nil {
		t.Fatal(err)
	}
	c := newCoord()
	if err := c.classifyResidue(fs); err != nil {
		t.Fatal(err)
	}
	if !c.bucketHeld("bucket") {
		t.Fatal("orphan retire did not hold its bucket")
	}
}

// plantFile creates a plain file through the fake's create path.
func plantFile(fs FS, p string) error {
	obj, err := fs.Open(p, openWrite|openCreate|openExcl)
	if err != nil {
		return err
	}
	return fs.Release(obj)
}
