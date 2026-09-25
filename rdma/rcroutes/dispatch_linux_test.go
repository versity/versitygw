// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

//go:build linux && amd64 && cgo && rdma

package rcroutes

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// fakeBackend records backend calls; unconfigured methods answer
// with unsupported (so only the dispatched surface is exercised).
type fakeBackend struct {
	backend.BackendUnsupported

	getObject  func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error)
	uploadPart func(ctx context.Context, in *s3.UploadPartInput) (*s3.UploadPartOutput, error)
}

// GetBucketAcl answers an empty ACL so wrapper-level tests that run
// the full Prepare route pass the authorization chain without a
// per-bucket policy.
func (f *fakeBackend) GetBucketAcl(ctx context.Context,
	in *s3.GetBucketAclInput) ([]byte, error) {
	return nil, nil
}

// GetBucketPolicy answers "no policy" so the resource-access branch
// of the authorization chain falls through to the ACL instead of the
// unsupported stub's 501.
func (f *fakeBackend) GetBucketPolicy(ctx context.Context,
	bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
}

// GetObjectLockConfiguration answers "not configured" so the PUT
// overwrite check in the authorization chain sees no retention
// rules instead of the unsupported stub's 501.
func (f *fakeBackend) GetObjectLockConfiguration(ctx context.Context,
	bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
}

func (f *fakeBackend) GetObject(ctx context.Context,
	in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	if f.getObject != nil {
		return f.getObject(ctx, in)
	}
	return nil, errors.New("unexpected GetObject")
}

func (f *fakeBackend) UploadPart(ctx context.Context,
	in *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	if f.uploadPart != nil {
		return f.uploadPart(ctx, in)
	}
	return nil, errors.New("unexpected UploadPart")
}

// fixedService is the rcService fixture base: admission and the
// service context over a plain background context.
type fixedService struct {
	rcService
	ctx context.Context
}

func newFixedService() *fixedService {
	return &fixedService{ctx: context.Background()}
}

func (f *fixedService) TryEnter() bool { return true }
func (f *fixedService) Leave()         {}
func (f *fixedService) Context() context.Context {
	return f.ctx
}

// leaseService answers one BorrowStaging over the fixed buffer.
type leaseService struct {
	*fixedService
	buf []byte
}

func (l *leaseService) BorrowStaging(sessionID string) (*rcserver.StagingLease, error) {
	return &rcserver.StagingLease{Buf: l.buf}, nil
}

func (l *leaseService) FinishStaging(lease rcserver.StagingLease, ok bool,
	written int, etag, version string) error {
	if !ok {
		return errors.New("staging not committed")
	}
	return nil
}

// viewService answers one GetPutData over the fixed buffer.
type viewService struct {
	*fixedService
	buf []byte
}

func (v *viewService) GetPutData(sessionID string) (*rcserver.PutView, error) {
	return &rcserver.PutView{Buf: v.buf}, nil
}

func (v *viewService) FinishPut(view rcserver.PutView, committed bool,
	etag, version string) error {
	return nil
}

// inHandler runs fn inside a live fiber handler so the fasthttp
// request context (whose Done channel svcCtx relies on) stays
// valid for the duration of the call.
func inHandler(t *testing.T, fn func(c fiber.Ctx)) {
	t.Helper()
	app := fiber.New()
	done := make(chan struct{})
	app.Get("/probe", func(c fiber.Ctx) error {
		fn(c)
		close(done)
		return nil
	})
	req, _ := http.NewRequest(fiber.MethodGet, "/probe", nil)
	go func() { _, _ = app.Test(req) }()
	<-done
}

// The part dispatch matrix: a part GET dispatches by PartNumber with
// no Range; a plain GET keeps its Range; the offset rule holds.
func TestStageGetPartDispatch(t *testing.T) {
	be := &fakeBackend{}
	h := &Handler{be: be, svc: newFixedService(), mpMaxParts: 100}

	// Part GET: backend sees PartNumber and no Range.
	var gotPart *int32
	var gotRange *string
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		gotPart = in.PartNumber
		gotRange = in.Range
		body := io.NopCloser(bytes.NewReader(make([]byte, 4)))
		return &s3.GetObjectOutput{Body: body}, nil
	}
	svc := h.svc.(*fixedService)
	h.svc = &leaseService{fixedService: svc, buf: make([]byte, 8)}

	var err error
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s1", "bkt", "obj", 0, 8,
			&partTransfer{PartNumber: 3})
	})
	if err != nil {
		t.Fatalf("part stageGet failed: %v", err)
	}
	if gotPart == nil || *gotPart != 3 {
		t.Fatalf("PartNumber = %v, want 3", gotPart)
	}
	if gotRange != nil {
		t.Fatalf("part GET carried Range %q, want none", *gotRange)
	}

	// Plain GET: backend sees Range and no PartNumber.
	gotPart = nil
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		gotPart = in.PartNumber
		gotRange = in.Range
		body := io.NopCloser(bytes.NewReader(make([]byte, 8)))
		return &s3.GetObjectOutput{Body: body}, nil
	}
	h.svc = &leaseService{fixedService: svc, buf: make([]byte, 8)}
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s2", "bkt", "obj", 16, 8, nil)
	})
	if err != nil {
		t.Fatalf("plain stageGet failed: %v", err)
	}
	if gotPart != nil {
		t.Fatalf("plain GET carried PartNumber %d", *gotPart)
	}
	if gotRange == nil || !strings.HasPrefix(*gotRange, "bytes=16-") {
		t.Fatalf("plain GET Range = %v", gotRange)
	}

	// Part GET longer than the announced size with a declared
	// content length is rejected.
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		body := io.NopCloser(bytes.NewReader(make([]byte, 9)))
		cl := int64(9)
		return &s3.GetObjectOutput{Body: body, ContentLength: &cl}, nil
	}
	h.svc = &leaseService{fixedService: svc, buf: make([]byte, 8)}
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s4", "bkt", "obj", 0, 8,
			&partTransfer{PartNumber: 3})
	})
	if err == nil {
		t.Fatal("oversized part with declared length accepted")
	}

	// Part GET longer than the announced size without a content
	// length is rejected by the probe read.
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		body := io.NopCloser(bytes.NewReader(make([]byte, 9)))
		return &s3.GetObjectOutput{Body: body}, nil
	}
	h.svc = &leaseService{fixedService: svc, buf: make([]byte, 8)}
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s5", "bkt", "obj", 0, 8,
			&partTransfer{PartNumber: 3})
	})
	if err == nil {
		t.Fatal("oversized part without declared length accepted")
	}

	// A transient zero-byte read before the extra byte is still
	// detected as an overrun once the byte arrives.
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		body := io.NopCloser(io.MultiReader(&zeroReader{}, bytes.NewReader(make([]byte, 1))))
		return &s3.GetObjectOutput{Body: body}, nil
	}
	h.svc = &leaseService{fixedService: svc, buf: make([]byte, 8)}
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s6", "bkt", "obj", 0, 8,
			&partTransfer{PartNumber: 3})
	})
	if err == nil {
		t.Fatal("overrun after transient zero-byte read accepted")
	}

	// An exactly sized part with no content length passes the probe.
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		body := io.NopCloser(bytes.NewReader(make([]byte, 8)))
		return &s3.GetObjectOutput{Body: body}, nil
	}
	h.svc = &leaseService{fixedService: svc, buf: make([]byte, 8)}
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s7", "bkt", "obj", 0, 8,
			&partTransfer{PartNumber: 3})
	})
	if err != nil {
		t.Fatalf("exact part without declared length rejected: %v", err)
	}

	// Part GET with nonzero offset is rejected before the backend.
	called := false
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		called = true
		return nil, nil
	}
	inHandler(t, func(c fiber.Ctx) {
		err = h.stageGet(c, "s3", "bkt", "obj", 4, 8,
			&partTransfer{PartNumber: 3})
	})
	if err == nil {
		t.Fatal("nonzero-offset part read accepted")
	}
	var bad errRouteBadRequest
	if !errors.As(err, &bad) {
		t.Fatalf("error class = %v", err)
	}
	if called {
		t.Fatal("backend called for an invalid part read")
	}
}

// The part upload dispatch: commitPut routes to UploadPart with the
// query's upload id and part number and reports the part ETag.
func TestCommitPutPartDispatch(t *testing.T) {
	be := &fakeBackend{}
	h := &Handler{be: be, svc: newFixedService(), mpMaxParts: 100}

	var gotUploadID, gotKey string
	var gotPartNumber int32
	var gotLen int64
	etag := "\"part-etag\""
	be.uploadPart = func(ctx context.Context, in *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
		gotUploadID = *in.UploadId
		gotKey = *in.Key
		gotPartNumber = *in.PartNumber
		gotLen = *in.ContentLength
		return &s3.UploadPartOutput{ETag: &etag}, nil
	}
	svc := h.svc.(*fixedService)
	h.svc = &viewService{fixedService: svc, buf: []byte("part-bytes")}

	var put *putObjectAlias
	var viewDone bool
	var committed int64
	var err error
	inHandler(t, func(c fiber.Ctx) {
		put, viewDone, committed, err = h.commitPut(c, "s1",
			"bkt", "obj", 10, &partTransfer{UploadID: "up-1", PartNumber: 2})
	})
	if err != nil {
		t.Fatalf("part commitPut failed: %v", err)
	}
	if !viewDone {
		t.Fatal("part commitPut reported view not done")
	}
	if committed != 10 {
		t.Fatalf("committed = %d, want 10", committed)
	}
	if put == nil || put.ETag != etag {
		t.Fatalf("put = %+v, want ETag %q", put, etag)
	}
	if gotUploadID != "up-1" || gotKey != "obj" || gotPartNumber != 2 {
		t.Fatalf("UploadPart args: id=%q key=%q part=%d",
			gotUploadID, gotKey, gotPartNumber)
	}
	if gotLen != 10 {
		t.Fatalf("ContentLength = %d, want 10", gotLen)
	}
}

// The commitPut return type, named for test readability.
type putObjectAlias = s3response.PutObjectOutput

var _ = auth.Account{}

// zeroReader returns (0, nil) once before delegating, mimicking a
// transient zero-progress read allowed by the io.Reader contract.
type zeroReader struct {
	served bool
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if !z.served {
		z.served = true
		return 0, nil
	}
	return len(p), nil
}
