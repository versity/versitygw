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
	"testing"

	"github.com/valyala/fasthttp"

	"github.com/versity/versitygw/rdma/rcdial"
	"github.com/versity/versitygw/s3api/utils"
)

// fakeDialer records calls and can be told to fail at a stage.
type fakeDialer struct {
	dialErr  error
	readErr  error
	writeErr error
	shortIO  bool
	readBuf  []byte // what a READ "returns" from the client region
	written  []byte // what a WRITE pushed to the client region
	dials    int
	reads    int
	writes   int
}

func (f *fakeDialer) Dial(t rcdial.Token) (rcdial.Conn, error) {
	f.dials++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	return &fakeConn{d: f}, nil
}

func (f *fakeDialer) TransportSupported() bool { return true }

type fakeConn struct{ d *fakeDialer }

func (c *fakeConn) Read(length uint64, rkey uint32, remoteAddr uint64) ([]byte, func(), error) {
	c.d.reads++
	if c.d.readErr != nil {
		return nil, nil, c.d.readErr
	}
	n := int(length)
	if n > len(c.d.readBuf) {
		n = len(c.d.readBuf)
	}
	out := make([]byte, n)
	copy(out, c.d.readBuf[:n])
	if c.d.shortIO && n > 0 {
		out = out[:n-1]
	}
	return out, func() {}, nil
}

func (c *fakeConn) Write(data []byte, rkey uint32, remoteAddr uint64) (int, error) {
	c.d.writes++
	if c.d.writeErr != nil {
		return 0, c.d.writeErr
	}
	c.d.written = append(c.d.written[:0], data...)
	if c.d.shortIO && len(data) > 0 {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (c *fakeConn) Close() {}

// token builds a token over a fake region of the given length.
func token(length uint64) rcdial.Token {
	return rcdial.Token{
		ListenIP:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1},
		ListenPort: 18181,
		RKey:       0x1a2b3c4d,
		RemoteAddr: 0x400200,
		Length:     length,
	}
}

// v3ctx mimics the middleware's storage on the fasthttp context.
func v3ctx(t rcdial.Token) *fasthttp.RequestCtx {
	rc := &fasthttp.RequestCtx{}
	rc.SetUserValue("hipv3.rdma.descriptor", t)
	return rc
}

func plainCtx() *fasthttp.RequestCtx { return &fasthttp.RequestCtx{} }

// --- PUT ---

func TestPutStagesAndForwardsTokenLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 4096)
	fake := &fakeDialer{readBuf: payload}
	be := &capturingBackend{}
	srv := New(be, fake, Config{})

	out, err := srv.PutObject(v3ctx(token(4096)), putInput(4096))
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if out.ETag == "" && be.etag == "" {
		t.Error("no etag produced")
	}
	if be.putLen != 4096 {
		t.Errorf("backend ContentLength = %d, want 4096", be.putLen)
	}
	if !bytes.Equal(be.putBody, payload) {
		t.Errorf("backend body = %d bytes, want staged %d", len(be.putBody), len(payload))
	}
	if fake.reads != 1 {
		t.Errorf("reads = %d, want 1", fake.reads)
	}
}

func TestPutOversizeRejectedBeforeDial(t *testing.T) {
	fake := &fakeDialer{}
	be := &capturingBackend{}
	srv := New(be, fake, Config{MaxStaging: 1024})

	_, err := srv.PutObject(v3ctx(token(4096)), putInput(4096))
	if err == nil {
		t.Fatal("oversize accepted")
	}
	if fake.dials != 0 {
		t.Errorf("dialed %d times before rejection", fake.dials)
	}
	if be.putCalls != 0 {
		t.Error("backend invoked despite rejection")
	}
}

func TestPutChecksumMismatchFailsBeforeBackend(t *testing.T) {
	fake := &fakeDialer{readBuf: bytes.Repeat([]byte{0x00}, 64)}
	be := &capturingBackend{}
	srv := New(be, fake, Config{})

	po := putInput(64)
	bad := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	po.ChecksumSHA256 = &bad
	_, err := srv.PutObject(v3ctx(token(64)), po)
	if err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if be.putCalls != 0 {
		t.Error("backend invoked despite checksum failure")
	}
}

func TestPutDialFailureIs502RdmaTransferFailed(t *testing.T) {
	fake := &fakeDialer{dialErr: errors.New("no route")}
	be := &capturingBackend{}
	srv := New(be, fake, Config{})

	_, err := srv.PutObject(v3ctx(token(16)), putInput(16))
	if err == nil {
		t.Fatal("dial failure accepted")
	}
	if code, ok := err.(interface{ StatusCode() int }); !ok || code.StatusCode() != 502 {
		t.Errorf("err = %v, want 502 RdmaTransferFailed", err)
	}
	if got, ok := err.(interface{ Error() string }); !ok || !bytes.Contains([]byte(got.Error()), []byte("RdmaTransferFailed")) {
		t.Errorf("err text = %v", err)
	}
	if be.putCalls != 0 {
		t.Error("backend invoked despite dial failure")
	}
}

func TestPutWithoutDescriptorDelegates(t *testing.T) {
	fake := &fakeDialer{}
	be := &capturingBackend{}
	srv := New(be, fake, Config{})

	if _, err := srv.PutObject(plainCtx(), putInput(0)); err != nil {
		t.Fatalf("plain PutObject: %v", err)
	}
	if fake.dials != 0 || be.putLen != 0 {
		t.Error("plain path disturbed")
	}
}

// --- UploadPart ---

func TestUploadPartForwardsTokenLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	fake := &fakeDialer{readBuf: payload}
	be := &capturingBackend{}
	srv := New(be, fake, Config{})

	if _, err := srv.UploadPart(v3ctx(token(1024)), partInput()); err != nil {
		t.Fatalf("UploadPart: %v", err)
	}
	if be.partLen != 1024 {
		t.Errorf("backend part ContentLength = %d, want 1024", be.partLen)
	}
	if !bytes.Equal(be.partBody, payload) {
		t.Errorf("part body = %d bytes, want 1024", len(be.partBody))
	}
}

// --- GET ---

func TestGetWritesAndReturnsBodyless(t *testing.T) {
	obj := bytes.Repeat([]byte{0xc3}, 2048)
	fake := &fakeDialer{}
	be := &capturingBackend{getObject: obj}
	srv := New(be, fake, Config{})

	res, err := srv.GetObject(v3ctx(token(2048)), getInput())
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer res.Body.Close()
	if !bytes.Equal(fake.written, obj) {
		t.Errorf("RDMA WRITE payload = %d bytes, want %d", len(fake.written), len(obj))
	}
	body, _ := io.ReadAll(res.Body)
	if len(body) != 0 {
		t.Errorf("HTTP body = %d bytes, want 0", len(body))
	}
	if res.ContentLength == nil || *res.ContentLength != 0 {
		t.Errorf("ContentLength = %v, want 0", res.ContentLength)
	}
}

func TestGetLengthMismatchBothDirectionsFail(t *testing.T) {
	obj := bytes.Repeat([]byte{0x11}, 512)

	// token shorter than object: silent truncation risk
	fake := &fakeDialer{}
	be := &capturingBackend{getObject: obj}
	srv := New(be, fake, Config{})
	if _, err := srv.GetObject(v3ctx(token(256)), getInput()); err == nil {
		t.Error("short token accepted")
	}
	if fake.writes != 0 {
		t.Errorf("wrote %d times on mismatch", fake.writes)
	}

	// token longer than object: client rejects after the bytes moved
	fake2 := &fakeDialer{}
	be2 := &capturingBackend{getObject: obj}
	srv2 := New(be2, fake2, Config{})
	if _, err := srv2.GetObject(v3ctx(token(1024)), getInput()); err == nil {
		t.Error("long token accepted")
	}
	if fake2.writes != 0 {
		t.Errorf("wrote %d times on mismatch", fake2.writes)
	}
}

func TestGetBackendErrorPropagates(t *testing.T) {
	fake := &fakeDialer{}
	be := &capturingBackend{getErr: errors.New("not found")}
	srv := New(be, fake, Config{})
	if _, err := srv.GetObject(v3ctx(token(1)), getInput()); err == nil {
		t.Error("backend error swallowed")
	}
	if fake.dials != 0 {
		t.Error("dialed despite backend error")
	}
}

func TestGetTransportFailureIs502(t *testing.T) {
	obj := []byte{1, 2, 3, 4}
	fake := &fakeDialer{writeErr: errors.New("rnr exhaustion")}
	be := &capturingBackend{getObject: obj}
	srv := New(be, fake, Config{})
	_, err := srv.GetObject(v3ctx(token(4)), getInput())
	if err == nil {
		t.Fatal("write failure accepted")
	}
	if code, ok := err.(interface{ StatusCode() int }); !ok || code.StatusCode() != 502 {
		t.Errorf("err = %v, want 502", err)
	}
}

func TestV3LogicalLengthReadsStoredToken(t *testing.T) {
	if got, ok := utils.V3LogicalLength(v3ctx(token(777))); !ok || got != 777 {
		t.Errorf("V3LogicalLength = (%d, %v)", got, ok)
	}
	if _, ok := utils.V3LogicalLength(plainCtx()); ok {
		t.Error("plain context reported a length")
	}
	if _, ok := utils.V3LogicalLength(context.Background()); ok {
		t.Error("nil-ish context reported a length")
	}
}
