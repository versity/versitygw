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
	"io"
	"net"
	"net/http"
	"os"
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
	connBytes    map[net.Conn]int
	connDone     map[net.Conn]chan struct{}
	finalRelease chan struct{}
	closeOnce    sync.Once
	releaseOnce  sync.Once
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
		connBytes:      make(map[net.Conn]int),
		connDone:       make(map[net.Conn]chan struct{}),
		finalRelease:   make(chan struct{}),
	}
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *fakeS3) close() {
	f.closeOnce.Do(func() {
		f.releaseOnce.Do(func() {
			close(f.finalRelease)
		})
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
		// Register the connection before dispatching its
		// handler, so a test can wait for acceptance and then
		// for handler completion instead of racing the
		// goroutine schedule.
		f.mu.Lock()
		if f.connBytes == nil {
			f.connBytes = make(map[net.Conn]int)
		}
		if f.connDone == nil {
			f.connDone = make(map[net.Conn]chan struct{})
		}
		f.connBytes[conn] = 0
		done := make(chan struct{})
		f.connDone[conn] = done
		f.mu.Unlock()
		go f.handle(conn, done)
	}
}

// countingReader tracks how many raw bytes a connection actually
// delivered, so a test can assert zero bytes were written before a
// rejection even when no request parses.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (f *fakeS3) handle(conn net.Conn, done chan struct{}) {
	defer close(done)
	defer conn.Close()
	cr := &countingReader{r: conn}
	defer func() {
		f.mu.Lock()
		f.connBytes[conn] = int(cr.n)
		f.mu.Unlock()
	}()
	br := bufio.NewReader(cr)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.connBytes[conn] = int(cr.n)
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
		case "/b/k":
			// The admission probe object: a one-byte ranged GET
			// answers 206 with a single byte, exactly what the
			// signed object probe treats as positive evidence.
			conn.Write([]byte("HTTP/1.1 206 partial\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"))
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
		ProbeBucket:     "b",
		ProbeKey:        "k",
		Credentials: Credentials{
			AccessKey: "AKIAFAKE",
			SecretKey: "secretfake",
			Region:    "us-east-1",
		},
	}
	cp := newControlPlane(cfg)
	// The wire tests exercise the exchange functions directly, so
	// no probe ever ran: pin the loopback form of the listener's
	// address as the admitted peer the way a successful probe
	// would (a probe connection's RemoteAddr is the dialer-side
	// view: 127.0.0.1:port for a loopback listener).
	if _, port, err := net.SplitHostPort(strings.TrimPrefix(
		endpoint, "http://")); err == nil {
		cp.probeMu.Lock()
		cp.probePeer = net.JoinHostPort("127.0.0.1", port)
		cp.probeMu.Unlock()
	}
	return cp
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
	ph.Set("X-Amz-Rdma-Reply", "200:"+strings.Repeat("ab", 44))
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
	f.releaseOnce.Do(func() {
		go func() {
			time.Sleep(50 * time.Millisecond)
			f.mu.Lock()
			f.withholdFinal = false
			f.mu.Unlock()
			close(f.finalRelease)
		}()
	})
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

// TestReplyTokenPayload pins the status-prefix contract: only
// "<three digits>:<token>" yields a payload.
func TestReplyTokenPayload(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"200:" + strings.Repeat("ab", 44), strings.Repeat("ab", 44)},
		{"204:tok", "tok"},
		{"garbage:tok", ""},
		{":tok", ""},
		{"2000:tok", ""},
		{"200:", ""},
		{"200", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := replyTokenPayload(c.in); got != c.want {
			t.Errorf("replyTokenPayload(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

// TestConnLost pins the transport-loss classification: the typed
// deadline errors are intentional local aborts and everything
// else is a lost connection, whenever it is observed.
func TestConnLost(t *testing.T) {
	if connLost(nil) {
		t.Error("nil error classified as lost")
	}
	if connLost(context.DeadlineExceeded) {
		t.Error("context deadline classified as lost")
	}
	if connLost(os.ErrDeadlineExceeded) {
		t.Error("os deadline classified as lost")
	}
	for _, e := range []error{
		fmt.Errorf("write tcp: broken pipe"),
		fmt.Errorf("unexpected EOF"),
		fmt.Errorf("read: connection reset by peer"),
		fmt.Errorf("http: unexpected EOF reading body"),
	} {
		if !connLost(e) {
			t.Errorf("%v classified as not lost", e)
		}
	}
}

// TestPrepareMismatchedPeerUnsent pins the admission contract for
// PREPARE: starting from asserted positive admission evidence, a
// freshly dialed peer that differs from the probe's pin sends
// nothing, the evidence is dropped, and the next transfer through
// the production valve re-probes against the replacement before
// any PREPARE flows.
func TestPrepareMismatchedPeerUnsent(t *testing.T) {
	ph := http.Header{}
	ph.Set("X-Amz-Rdma-Protocol", protocolV2)
	f := newFakeS3(t, 200, ph)
	cp := newTestCP(f.endpoint())
	// Establish positive evidence the way production does: the
	// signed object probe the valve runs, admitted state asserted
	// before the mismatch.
	r := testReq(2000)
	r.Endpoint = f.endpoint()
	r.Bucket = "b"
	r.Key = "k"
	cp.probeMu.Lock()
	cp.probeNic = r.Nic
	cp.probeNicPort = r.NicPort
	cp.probeNicGid = r.NicGid
	cp.probeMu.Unlock()
	pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pcancel()
	if perr := cp.elig.Probe(pctx); perr != nil {
		t.Fatalf("initial admission probe: %v", perr)
	}
	if !cp.elig.Admitted() {
		t.Fatal("admission not positive after successful probe")
	}

	// Snapshot the byte totals, then point the pin at a different
	// peer and dial again. The production valve must drop the new
	// connection before a single request byte is written: parse
	// failures cannot hide it because the fake counts raw bytes
	// per connection.
	f.mu.Lock()
	baseTotal := 0
	for _, b := range f.connBytes {
		baseTotal += b
	}
	basePrepares := len(f.prepareReqs)
	f.mu.Unlock()
	cp.probeMu.Lock()
	cp.probePeer = "127.0.0.1:1"
	cp.probeMu.Unlock()
	if rc := cp.prepareForTest(r); rc != -1 {
		t.Fatalf("prepare rc=%d, want -1", rc)
	}
	// The mismatch dial itself reaches the server (the valve
	// drops it after accept), so wait for every connection opened
	// after the snapshot to finish reading before asserting: an
	// early return could miss bytes still in flight.
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		total := 0
		pending := 0
		for c, b := range f.connBytes {
			total += b
			select {
			case <-f.connDone[c]:
			default:
				pending++
			}
		}
		prepares := len(f.prepareReqs)
		f.mu.Unlock()
		if pending == 0 && (total > baseTotal || prepares > basePrepares) {
			t.Fatalf("after mismatch: bytes %d->%d, PREPAREs %d->%d",
				baseTotal, total, basePrepares, prepares)
		}
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after mismatch: %d connection(s) still unread", pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cp.elig.Admitted() {
		t.Error("admission still positive after peer mismatch")
	}

	// The next production transfer re-probes through the valve
	// and succeeds against the replacement: PREPARE flows again.
	r2 := testReq(2000)
	r2.Endpoint = f.endpoint()
	r2.Bucket = "b"
	r2.Key = "k"
	if rc := cp.prepareValveForTest(r2); rc != 0 {
		t.Fatalf("post-mismatch prepare rc=%d, want 0", rc)
	}
	f.mu.Lock()
	n2 := len(f.prepareReqs)
	f.mu.Unlock()
	if n2 == 0 {
		t.Error("no PREPARE after re-probe against replacement")
	}
	if !cp.elig.Admitted() {
		t.Error("admission not positive after re-probe")
	}
}

// TestConnLostChains exercises wrapped and timeout-shaped errors
// the production transports can surface.
func TestConnLostChains(t *testing.T) {
	wrapped := fmt.Errorf("dial: %w", context.DeadlineExceeded)
	if connLost(wrapped) {
		t.Error("wrapped deadline classified as lost")
	}
	opErr := &net.OpError{Op: "read", Net: "tcp",
		Err: fmt.Errorf("connection reset by peer")}
	if !connLost(opErr) {
		t.Error("net.OpError reset classified as not lost")
	}
	if !connLost(io.EOF) {
		t.Error("io.EOF classified as not lost")
	}
	if !connLost(io.ErrUnexpectedEOF) {
		t.Error("unexpected EOF classified as not lost")
	}
}

// TestChecksumValid pins the wire checksum contract on the pure
// predicate form used before the C copy.
func TestChecksumValid(t *testing.T) {
	valid := []string{
		"CRC64NVME AQIDBAUGBwg=",
		"CRC64NVME AAAAAAAAAAA=",
		"CRC64NVME AAAAAAAAAAE=",
	}
	for _, v := range valid {
		if !checksumValid(v) {
			t.Errorf("checksumValid(%q) rejected", v)
		}
	}
	bad := []string{
		"CRC64NVME AAAAAAAAAAB=",
		"CRC64NVME ============",
		"CRC64NVME AQIDBAUGBwg",
		"CRC64NVMEAQIDBAUGBwg=",
		"crc64nvme AQIDBAUGBwg=",
		"CRC64NVME AQIDBAUGBw==",
		"CRC64NVME AQIDBAUGBwg=extra",
		"CRC64NVME AQ=DAUGBwg=",
		"",
	}
	for _, b := range bad {
		if checksumValid(b) {
			t.Errorf("checksumValid(%q) accepted", b)
		}
	}
}
