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
	"errors"
	"testing"

	"github.com/valyala/fasthttp"

	"github.com/versity/versitygw/rdma/rcdial"
)

// unsupportedDialer simulates a build without the rdma transport.
type unsupportedDialer struct{}

func (unsupportedDialer) TransportSupported() bool { return false }
func (unsupportedDialer) Dial(t rcdial.Token) (rcdial.Conn, error) {
	return nil, rcdial.ErrUnsupportedTransport
}

func TestReplyHeaderSuccessTable(t *testing.T) {
	cases := []struct {
		name    string
		length  uint64
		op      func(s *Server, ctx *fasthttp.RequestCtx) error
		backend func() *capturingBackend
		want    string
	}{
		{
			name: "put", length: 128,
			op: func(s *Server, ctx *fasthttp.RequestCtx) error {
				_, err := s.PutObject(ctx, putInput(0))
				return err
			},
			backend: func() *capturingBackend { return &capturingBackend{} },
			want:    "200:0000000000000080",
		},
		{
			name: "upload part", length: 64,
			op: func(s *Server, ctx *fasthttp.RequestCtx) error {
				_, err := s.UploadPart(ctx, partInput())
				return err
			},
			backend: func() *capturingBackend { return &capturingBackend{} },
			want:    "200:0000000000000040",
		},
		{
			name: "full get", length: 256,
			op: func(s *Server, ctx *fasthttp.RequestCtx) error {
				_, err := s.GetObject(ctx, getInput())
				return err
			},
			backend: func() *capturingBackend {
				return &capturingBackend{getObject: bytes.Repeat([]byte{3}, 256)}
			},
			want: "200:0000000000000100",
		},
		{
			name: "ranged get", length: 96,
			op: func(s *Server, ctx *fasthttp.RequestCtx) error {
				_, err := s.GetObject(ctx, getInput())
				return err
			},
			backend: func() *capturingBackend {
				return &capturingBackend{
					getObject:    bytes.Repeat([]byte{4}, 96),
					contentRange: "bytes 0-95/512",
				}
			},
			want: "206:0000000000000060",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := v3ctx(token(tc.length))
			fake := &fakeDialer{}
			if tc.name == "put" || tc.name == "upload part" {
				fake.readBuf = bytes.Repeat([]byte{1}, int(tc.length))
			}
			srv := New(tc.backend(), fake, Config{})
			if err := tc.op(srv, ctx); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got, ok := TakeReply(ctx)
			if !ok {
				t.Fatalf("%s: no reply recorded", tc.name)
			}
			if got != tc.want {
				t.Errorf("%s: reply = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestReplyHeaderAbsentOnFailures(t *testing.T) {
	// Dial failures on all three operations.
	for _, op := range []struct {
		name string
		fn   func(s *Server, ctx *fasthttp.RequestCtx) error
	}{
		{"put", func(s *Server, ctx *fasthttp.RequestCtx) error {
			_, err := s.PutObject(ctx, putInput(0))
			return err
		}},
		{"upload part", func(s *Server, ctx *fasthttp.RequestCtx) error {
			_, err := s.UploadPart(ctx, partInput())
			return err
		}},
		{"get", func(s *Server, ctx *fasthttp.RequestCtx) error {
			_, err := s.GetObject(ctx, getInput())
			return err
		}},
	} {
		ctx := v3ctx(token(32))
		srv := New(&capturingBackend{}, &fakeDialer{dialErr: errors.New("dead route")}, Config{})
		if err := op.fn(srv, ctx); err == nil {
			t.Fatalf("%s: dial failure accepted", op.name)
		}
		if _, ok := TakeReply(ctx); ok {
			t.Errorf("%s: reply recorded on dial failure", op.name)
		}
	}

	// Checksum failure.
	ctx := v3ctx(token(8))
	srv := New(&capturingBackend{}, &fakeDialer{readBuf: bytes.Repeat([]byte{9}, 8)}, Config{})
	po := putInput(0)
	bad := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	po.ChecksumSHA256 = &bad
	if _, err := srv.PutObject(ctx, po); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if _, ok := TakeReply(ctx); ok {
		t.Error("reply recorded on checksum failure")
	}

	// Backend failure on GET.
	ctx2 := v3ctx(token(8))
	srv2 := New(&capturingBackend{getErr: errors.New("nope")}, &fakeDialer{}, Config{})
	if _, err := srv2.GetObject(ctx2, getInput()); err == nil {
		t.Fatal("backend error swallowed")
	}
	if _, ok := TakeReply(ctx2); ok {
		t.Error("reply recorded on backend failure")
	}
}

func TestUploadPartChecksumRejectedBeforeBackend(t *testing.T) {
	be := &capturingBackend{}
	fake := &fakeDialer{readBuf: bytes.Repeat([]byte{7}, 32)}
	srv := New(be, fake, Config{})

	up := partInput()
	bad := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	up.ChecksumSHA256 = &bad
	if _, err := srv.UploadPart(v3ctx(token(32)), up); err == nil {
		t.Fatal("mismatching part checksum accepted")
	}
	if be.partLen != 0 {
		t.Errorf("backend saw part length %d despite checksum failure", be.partLen)
	}
}

func TestPutMD5ChecksumField(t *testing.T) {
	be := &capturingBackend{}
	fake := &fakeDialer{readBuf: bytes.Repeat([]byte{5}, 16)}
	srv := New(be, fake, Config{})

	po := putInput(0)
	bad := "AAAAAAAAAAAAAAAAAAAAAA=="
	po.ChecksumMD5 = &bad
	if _, err := srv.PutObject(v3ctx(token(16)), po); err == nil {
		t.Fatal("mismatching md5 accepted")
	}
	if be.putCalls != 0 {
		t.Error("backend invoked despite md5 failure")
	}
}

func TestUnsupportedTransportIs501(t *testing.T) {
	srv := New(&capturingBackend{}, unsupportedDialer{}, Config{})
	ctx := v3ctx(token(16))

	if _, err := srv.PutObject(ctx, putInput(0)); err == nil {
		t.Fatal("put accepted without transport")
	} else if code, ok := err.(interface{ StatusCode() int }); !ok || code.StatusCode() != 501 {
		t.Errorf("put err = %v, want 501", err)
	}
	if _, ok := TakeReply(ctx); ok {
		t.Error("reply recorded on 501")
	}

	if _, err := srv.UploadPart(ctx, partInput()); err == nil {
		t.Fatal("part accepted without transport")
	} else if code, ok := err.(interface{ StatusCode() int }); !ok || code.StatusCode() != 501 {
		t.Errorf("part err = %v, want 501", err)
	}

	// GET must refuse before staging the object.
	be := &capturingBackend{getObject: bytes.Repeat([]byte{6}, 16)}
	srv2 := New(be, unsupportedDialer{}, Config{})
	if _, err := srv2.GetObject(v3ctx(token(16)), getInput()); err == nil {
		t.Fatal("get accepted without transport")
	} else if code, ok := err.(interface{ StatusCode() int }); !ok || code.StatusCode() != 501 {
		t.Errorf("get err = %v, want 501", err)
	}
	if be.getCalls != 0 {
		t.Errorf("backend GetObject called %d times before the 501", be.getCalls)
	}
}

func TestGetStagingLimitBounded(t *testing.T) {
	be := &capturingBackend{getObject: bytes.Repeat([]byte{8}, 4096)}
	fake := &fakeDialer{}
	srv := New(be, fake, Config{MaxStaging: 1024})

	if _, err := srv.GetObject(v3ctx(token(4096)), getInput()); err == nil {
		t.Fatal("oversize GET accepted")
	} else if code, ok := err.(interface{ StatusCode() int }); !ok || code.StatusCode() != 400 {
		t.Errorf("err = %v, want 400", err)
	}
	if fake.dials != 0 {
		t.Errorf("dialed %d times before rejection", fake.dials)
	}
}

func TestGetInconsistentBackendStreamBounded(t *testing.T) {
	// The backend claims 64 bytes but streams 4096; the read cap
	// must surface the inconsistency instead of buffering it all.
	be := &capturingBackend{
		getObject: bytes.Repeat([]byte{1}, 4096),
		declared:  64,
	}
	fake := &fakeDialer{}
	srv := New(be, fake, Config{MaxStaging: 4096})

	if _, err := srv.GetObject(v3ctx(token(64)), getInput()); err == nil {
		t.Fatal("inconsistent stream accepted")
	}
	if fake.writes != 0 {
		t.Errorf("wrote %d times despite inconsistency", fake.writes)
	}
}

// TestGetForwardsVersionId proves the adapter passes the requested
// version through to the wrapped backend unchanged; a v3 GET must
// not drop it.
func TestGetForwardsVersionId(t *testing.T) {
	be := &capturingBackend{getObject: bytes.Repeat([]byte{2}, 32)}
	srv := New(be, &fakeDialer{}, Config{})
	in := getInput()
	ver := "VERSIONTOKEN"
	in.VersionId = &ver

	if _, err := srv.GetObject(v3ctx(token(32)), in); err != nil {
		t.Fatal(err)
	}
	if be.gotVersion == nil || *be.gotVersion != ver {
		t.Errorf("backend versionId = %v, want %q", be.gotVersion, ver)
	}
}

// TestPutContentMD5Rejected covers the legacy Content-MD5 header on
// the object PUT path: a valid-format digest that does not match
// the staged bytes must fail before the backend sees data.
func TestPutContentMD5Rejected(t *testing.T) {
	be := &capturingBackend{}
	fake := &fakeDialer{readBuf: bytes.Repeat([]byte{5}, 16)}
	srv := New(be, fake, Config{})

	po := putInput(0)
	bad := "AAAAAAAAAAAAAAAAAAAAAA=="
	po.ContentMD5 = &bad
	if _, err := srv.PutObject(v3ctx(token(16)), po); err == nil {
		t.Fatal("mismatching Content-MD5 accepted")
	}
	if be.putCalls != 0 {
		t.Error("backend invoked despite Content-MD5 failure")
	}
}
