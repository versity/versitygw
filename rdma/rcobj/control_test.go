// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

//go:build linux && amd64 && cgo && !cuobjclient_host

package rcobj

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 answers the wire protocol the callbacks speak: a scripted
// PREPARE, a READY whose response is withheld until the test
// releases it, and CANCEL. It records every request it saw.
type fakeS3 struct {
	mu sync.Mutex
	ln net.Listener

	// Scripted outcomes.
	prepareStatus  int
	prepareHeaders http.Header
	withholdFinal  bool
	capabilities   string

	// Observations.
	prepareReqs  []recordedReq
	readyReqs    []recordedReq
	cancelReqs   []recordedReq
	finalRelease chan struct{}
	closeOnce    sync.Once
}

type recordedReq struct {
	path   string
	hdr    http.Header
	method string
}

func newFakeS3(t *testing.T, prepareStatus int, prepareHeaders http.Header) *fakeS3 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeS3{
		ln:             ln,
		prepareStatus:  prepareStatus,
		prepareHeaders: prepareHeaders,
		finalRelease:   make(chan struct{}),
	}
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *fakeS3) close() {
	f.closeOnce.Do(func() {
		close(f.finalRelease)
		f.ln.Close()
	})
}

func (f *fakeS3) endpoint() string {
	return "http://" + f.ln.Addr().String()
}

func (f *fakeS3) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeS3) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		f.mu.Lock()
		rec := recordedReq{
			path:   req.URL.Path,
			hdr:    req.Header.Clone(),
			method: req.Method,
		}
		switch req.URL.Path {
		case pathPrepare:
			f.prepareReqs = append(f.prepareReqs, rec)
		case pathReady:
			f.readyReqs = append(f.readyReqs, rec)
		case pathCancel:
			f.cancelReqs = append(f.cancelReqs, rec)
		}
		withhold := f.withholdFinal && req.URL.Path == pathReady
		pstatus := f.prepareStatus
		phdrs := f.prepareHeaders
		f.mu.Unlock()

		switch req.URL.Path {
		case pathPrepare:
			var b strings.Builder
			fmt.Fprintf(&b, "HTTP/1.1 %d x\r\n", pstatus)
			for k, v := range phdrs {
				for _, vv := range v {
					fmt.Fprintf(&b, "%s: %s\r\n", k, vv)
				}
			}
			b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
			conn.Write([]byte(b.String()))
			return
		case pathReady:
			if withhold {
				<-f.finalRelease
			}
			var b strings.Builder
			b.WriteString("HTTP/1.1 200 ok\r\n")
			b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
			conn.Write([]byte(b.String()))
			return
		case pathCancel:
			var b strings.Builder
			b.WriteString("HTTP/1.1 200 ok\r\n")
			b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
			conn.Write([]byte(b.String()))
			return
		default:
			conn.Write([]byte("HTTP/1.1 404 nf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return
		}
	}
}

// newTestCP builds a controlPlane against the fake endpoint.
func newTestCP(endpoint string) *controlPlane {
	cfg := Config{
		ControlEndpoint: endpoint,
		Credentials: Credentials{
			AccessKey: "AKIAFAKE",
			SecretKey: "secretfake",
			Region:    "us-east-1",
		},
	}
	return newControlPlane(cfg)
}

func testReq(remaining uint32) transferReq {
	return transferReq{
		Method:    "GET",
		Bucket:    "b",
		Key:       "k",
		Size:      1024,
		Cookie:    0xdeadbeef,
		ClientPsn: 7,
		Remaining: remaining,
		Endpoint:  "",
		Token:     "88hex-token",
		Session:   "32hexsession",
	}
}

// TestPrepareWireHeaders pins the PREPARE request's wire contract:
// method, path, protocol echo, token, psn, cookie, op, target,
// size headers, and SigV4 authorization presence.
func TestPrepareWireHeaders(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Amz-Rdma-Protocol", protocolV2)
	ph.Set("X-Amz-Rdma-Reply", "200 abc88")
	ph.Set("X-Amz-Rdma-Session", "32hexsession")
	ph.Set("X-Amz-Rdma-Psn", "000010")
	f := newFakeS3(t, 200, ph)
	cp := newTestCP(f.endpoint())

	r := testReq(1000)
	r.Endpoint = f.endpoint()
	r.Method = "GET"

	if rc := cp.prepareForTest(r); rc != 0 {
		t.Fatalf("prepare rc=%d", rc)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.prepareReqs) != 1 {
		t.Fatalf("prepare requests: %d", len(f.prepareReqs))
	}
	got := f.prepareReqs[0]
	if got.method != http.MethodPost || got.path != pathPrepare {
		t.Fatalf("prepare %s %s", got.method, got.path)
	}
	checkHdr := func(name, want string) {
		t.Helper()
		if got := got.hdr.Get(name); got != want {
			t.Fatalf("%s = %q want %q", name, got, want)
		}
	}
	checkHdr("X-Amz-Rdma-Protocol", protocolV2)
	checkHdr("X-Amz-Rdma-Token", "88hex-token")
	checkHdr("X-Amz-Rdma-Psn", "000007")
	checkHdr("X-Amz-Rdma-Cookie", "deadbeef")
	checkHdr("X-Amz-Rdma-Op", "GET")
	checkHdr("X-Amz-Rdma-Target", "/b/k")
	checkHdr("X-Amz-Rdma-Size", "1024")
	if !strings.HasPrefix(got.hdr.Get("Authorization"), "AWS4-HMAC-SHA256") {
		t.Fatalf("missing SigV4 authorization: %q", got.hdr.Get("Authorization"))
	}
}

// TestReadySplitExchange pins the split callback semantics: the
// READY request is written and sendReadyRequest returns before the
// response exists; finishReady reads it exactly once.
func TestReadySplitExchange(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Amz-Rdma-Protocol", protocolV2)
	f := newFakeS3(t, 200, ph)
	f.mu.Lock()
	f.withholdFinal = true
	f.mu.Unlock()
	cp := newTestCP(f.endpoint())

	r := testReq(2000)
	r.Endpoint = f.endpoint()

	if rc := cp.readyRequest(r); rc != 0 {
		t.Fatalf("readyRequest rc=%d", rc)
	}

	// The request must already be observed server-side while the
	// response is withheld.
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.readyReqs)
		f.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("READY request never reached the server")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Withhold, then release from another goroutine so finishReady
	// observes a complete response under its budget.
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.mu.Lock()
		f.withholdFinal = false
		f.mu.Unlock()
		select {
		case <-f.finalRelease:
		default:
			close(f.finalRelease)
		}
	}()
	if rc := cp.finishReadyForTest(r); rc != 0 {
		t.Fatalf("finishReady rc=%d", rc)
	}
}

// TestAbortClosesPendingExchange pins the abort rule: an exchange
// whose response was never read is closed, never pooled, and a
// second readyRequest may open a fresh one.
func TestAbortClosesPendingExchange(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Amz-Rdma-Protocol", protocolV2)
	f := newFakeS3(t, 200, ph)
	f.mu.Lock()
	f.withholdFinal = true
	f.mu.Unlock()
	cp := newTestCP(f.endpoint())

	r := testReq(2000)
	r.Endpoint = f.endpoint()
	if rc := cp.readyRequest(r); rc != 0 {
		t.Fatalf("readyRequest rc=%d", rc)
	}
	cp.abortPending()

	// A second exchange on a fresh connection must succeed.
	f.mu.Lock()
	f.withholdFinal = false
	f.mu.Unlock()
	r2 := testReq(2000)
	r2.Endpoint = f.endpoint()
	if rc := cp.readyRequest(r2); rc != 0 {
		t.Fatalf("second readyRequest rc=%d", rc)
	}
	if rc := cp.finishReadyForTest(r2); rc != 0 {
		t.Fatalf("finishReady rc=%d", rc)
	}
}

// TestZeroBudgetFailsFast pins the hipobj.h contract: a callback
// invoked with zero remaining budget fails fast without touching
// the wire.
func TestZeroBudgetFailsFast(t *testing.T) {
	ph := http.Header{}
	f := newFakeS3(t, 200, ph)
	cp := newTestCP(f.endpoint())
	r := testReq(0)
	r.Endpoint = f.endpoint()

	if rc := cp.prepareForTest(r); rc != -1 {
		t.Fatalf("prepare with zero budget rc=%d want -1", rc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.prepareReqs) != 0 {
		t.Fatalf("zero-budget prepare hit the wire: %d", len(f.prepareReqs))
	}
}

// TestCancelRoundTrip pins the CANCEL exchange: session and cookie
// headers, one round trip, idempotent shape (fresh connection).
func TestCancelRoundTrip(t *testing.T) {
	ph := http.Header{}
	f := newFakeS3(t, 200, ph)
	cp := newTestCP(f.endpoint())
	r := testReq(500)
	r.Endpoint = f.endpoint()

	if rc := cp.cancel(r); rc != 0 {
		t.Fatalf("cancel rc=%d", rc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cancelReqs) != 1 {
		t.Fatalf("cancel requests: %d", len(f.cancelReqs))
	}
	got := f.cancelReqs[0]
	if got.path != pathCancel {
		t.Fatalf("cancel path %s", got.path)
	}
	if got.hdr.Get("X-Amz-Rdma-Session") != "32hexsession" {
		t.Fatalf("cancel session %q", got.hdr.Get("X-Amz-Rdma-Session"))
	}
	if got.hdr.Get("X-Amz-Rdma-Cookie") != "deadbeef" {
		t.Fatalf("cancel cookie %q", got.hdr.Get("X-Amz-Rdma-Cookie"))
	}
}

// TestCapabilitiesRecorded pins the PREPARE-surface capability
// capture the admission layer consumes.
func TestCapabilitiesRecorded(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Amz-Rdma-Capabilities", "mp")
	f := newFakeS3(t, 200, ph)
	cp := newTestCP(f.endpoint())
	r := testReq(1000)
	r.Endpoint = f.endpoint()

	if rc := cp.prepareForTest(r); rc != 0 {
		t.Fatalf("prepare rc=%d", rc)
	}
	if got := cp.Capabilities(); got != "mp" {
		t.Fatalf("capabilities = %q want mp", got)
	}
}

// TestDialRejectsHTTPS pins the https rejection the bridge
// enforces on the control endpoint.
func TestDialRejectsHTTPS(t *testing.T) {
	cp := newTestCP("https://example.com:9000")
	r := testReq(1000)
	r.Endpoint = "https://example.com:9000"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := cp.dialControl(ctx, r); err == nil {
		t.Fatal("https control endpoint must be rejected")
	} else if !strings.Contains(err.Error(), "https") {
		t.Fatalf("unexpected dial error: %v", err)
	}
}
