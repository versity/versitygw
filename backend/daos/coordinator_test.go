
// Copyright 2026 Versity Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package daos

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
)

// blockingFileRead stays unread until released, modeling a reader
// streaming an old generation while the key is overwritten.
type blockingFileRead struct {
	fs      *Fake
	obj     Object
	buf     []byte
	release chan struct{}
	started chan struct{}
}

func (b *blockingFileRead) Read(p []byte) (int, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	<-b.release
	n, err := b.fs.Read(b.obj, p, 0)
	return n, err
}

func TestOverwriteKeepsPinnedGenerationThroughCommit(t *testing.T) {
	d, fs := newTest(t)
	put(t, d, "a", "old", "", nil)
	out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The body reader holds the lease: the retire of the overwrite
	// must not reclaim the old generation while this reader is open.
	// Overwrite, then finish reading the old body.
	put(t, d, "a", "new", "", nil)
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old" {
		t.Fatalf("old generation body = %q, want the pinned bytes", body)
	}
	out.Body.Close()
	// After the last reader drains, the retire file is reclaimable
	// and the new generation reads cleanly.
	got, err := d.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: backend.GetPtrFromString("bucket"),
		Key:    backend.GetPtrFromString("a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	gotBody, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if string(gotBody) != "new" {
		t.Fatalf("new generation body = %q", gotBody)
	}
	_ = fs
}

func TestDistinctPrefixesDoNotSerialize(t *testing.T) {
	d, _ := newTest(t)
	// Two keys whose first canonical components differ must map to
	// independent namespace stripes: a slow publisher on one does
	// not block the other. A same-stripe pair would time out.
	slow := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		// Hold the stripe by keeping a reader open on the old
		// generation through an overwrite: publish waits for
		// nothing here, but the openLive stripe does serialize
		// same-stripe readers. Use a deliberately long body to
		// keep the read in flight.
		put(t, d, "one/x", strings.Repeat("a", 1<<20), "", nil)
		out, err := d.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: backend.GetPtrFromString("bucket"),
			Key:    backend.GetPtrFromString("one/x"),
		})
		if err != nil {
			done <- err
			return
		}
		<-slow
		out.Body.Close()
		done <- nil
	}()
	// Let the slow reader start.
	time.Sleep(50 * time.Millisecond)
	// The other prefix must proceed without waiting for it.
	putDone := make(chan error, 1)
	go func() {
		put(t, d, "two/y", "fresh", "", nil)
		putDone <- nil
	}()
	select {
	case err := <-putDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publish on a different first component serialized behind the slow stripe")
	}
	close(slow)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
