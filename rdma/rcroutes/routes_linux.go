// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

//go:build linux && amd64 && cgo

// Package rcroutes serves the /.hipobj-rc/{prepare,ready,cancel}
// terminal routes of the hipobj-rc-v2 two-phase transfer protocol.
//
// The routes are the control plane only: routing, SigV4
// authentication, authorization, and the object backend stay on the
// Go side; the RC session, QP/CQ/MR lifetimes, and the data phase
// live in the C session server bound by rdma/rcserver.
package rcroutes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3response"
)

// Wire headers of the two-phase protocol (lowercase on the wire;
// Fiber's Get is case-insensitive). Names mirror the hipobj-rc-v2
// wire contract shared with the client library.
const (
	hdrProtocol = "x-amz-rdma-protocol"
	hdrToken    = "x-amz-rdma-token"
	hdrPsn      = "x-amz-rdma-psn"
	hdrCookie   = "x-amz-rdma-cookie"
	hdrOp       = "x-amz-rdma-op"
	hdrTarget   = "x-amz-rdma-target"
	hdrSize     = "x-amz-rdma-size"
	hdrOffset   = "x-amz-rdma-offset"
	hdrSession  = "x-amz-rdma-session"
	hdrQpn      = "x-amz-rdma-qpn"
	hdrMrAddr   = "x-amz-rdma-mr-addr"
	hdrMrRkey   = "x-amz-rdma-mr-rkey"

	protocolValue = "hipobj-rc-v2"

	hdrReply     = "x-amz-rdma-reply"
	hdrBytes     = "x-amz-rdma-bytes-transferred"
	hdrEtag      = "x-amz-rdma-etag"
	hdrVersionID = "x-amz-rdma-version-id"
)

// Handler serves the three control routes.
type Handler struct {
	svc        *rcserver.RCSvc
	be         backend.Backend
	iam        auth.IAMService
	readonly   bool
	disableACL bool
}

// New builds the route handler around a started RC service.
func New(svc *rcserver.RCSvc, be backend.Backend, iam auth.IAMService,
	readonly, disableACL bool) *Handler {
	return &Handler{svc: svc, be: be, iam: iam,
		readonly: readonly, disableACL: disableACL}
}

// principalID derives the session identity digest from the
// authenticated account: SHA-256 over the access key and secret, so
// READY/CANCEL owner checks compare the credential, not a display
// name.
func principalID(acct auth.Account) rcserver.PrincipalID {
	h := sha256.Sum256([]byte(acct.Access + ":" + acct.Secret))
	var p rcserver.PrincipalID
	copy(p[:], h[:])
	return p
}

func errNotAdmitted() error {
	return errRouteUnavailable{}
}

func invalidHeader(name, value string) error {
	return fmt.Errorf("invalid %s header: %q: %w",
		name, value, errRouteBadRequest{})
}

// Prepare handles PREPARE: authorize the object access, create the
// session, and (GET) stage the object into the session buffer.
func (h *Handler) Prepare(ctx fiber.Ctx) error {
	// Serialize any error at the route boundary: the
	// production S3 error handler turns ordinary Fiber
	// errors into a generic 500 response.
	if err := h.prepareCore(ctx); err != nil {
		return WriteRouteError(ctx, err)
	}
	return nil
}

func (h *Handler) prepareCore(ctx fiber.Ctx) error {
	if !h.svc.TryEnter() {
		return errNotAdmitted()
	}
	defer h.svc.Leave()

	if proto := ctx.Get(hdrProtocol); proto != protocolValue {
		return invalidHeader(hdrProtocol, proto)
	}

	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)

	op := strings.ToUpper(ctx.Get(hdrOp))
	if op != "GET" && op != "PUT" {
		return invalidHeader(hdrOp, ctx.Get(hdrOp))
	}
	target := ctx.Get(hdrTarget)
	bucket, key, ok := splitTarget(target)
	if !ok {
		return invalidHeader(hdrTarget, target)
	}
	size, err := parseUint(ctx.Get(hdrSize), 10, 64)
	if err != nil || size == 0 {
		return invalidHeader(hdrSize, ctx.Get(hdrSize))
	}
	offset, err := parseUint(ctx.Get(hdrOffset), 10, 64)
	if err != nil {
		return invalidHeader(hdrOffset, ctx.Get(hdrOffset))
	}
	psn, err := parseUint(ctx.Get(hdrPsn), 16, 32)
	if err != nil || psn == 0 || psn > 0xffffff {
		return invalidHeader(hdrPsn, ctx.Get(hdrPsn))
	}
	cookie, err := parseUint(ctx.Get(hdrCookie), 16, 32)
	if err != nil || cookie == 0 {
		return invalidHeader(hdrCookie, ctx.Get(hdrCookie))
	}
	isPut := op == "PUT"

	// Authorize through the regular object-access chain.
	if err := h.authorize(ctx, acct, isRoot, bucket, key, isPut); err != nil {
		return err
	}

	resp, err := h.svc.Prepare(rcserver.PrepareRequest{
		Principal:   principalID(acct),
		Op:          map[bool]uint8{false: 0, true: 1}[isPut],
		Target:      target,
		Offset:      offset,
		Size:        size,
		ClientPsn:   uint32(psn),
		Cookie:      uint32(cookie),
		ClientToken: ctx.Get(hdrToken),
	})
	if err != nil {
		return mapRcError(err)
	}

	// GET: stage the object into the session buffer before the
	// PREPARE response commits the session.
	if !isPut {
		if err := h.stageGet(ctx, resp.SessionID, bucket, key, offset, size); err != nil {
			_ = h.svc.FinishPrepare(resp.SessionID, false)
			return err
		}
	}
	if err := h.svc.FinishPrepare(resp.SessionID, true); err != nil {
		return mapRcError(err)
	}

	// Wire reply per the hipobj-rc-v2 contract: protocol echo,
	// the server endpoint as "200:<token>", session id, and PSN.
	ctx.Set(hdrProtocol, protocolValue)
	if resp.ReplyToken != "" {
		ctx.Set(hdrReply, "200:"+resp.ReplyToken)
	} else {
		ctx.Set(hdrReply, "200:"+strings.Repeat("0", 88))
	}
	ctx.Set(hdrSession, resp.SessionID)
	ctx.Set(hdrPsn, formatPsn(resp.ServerPsn))
	if resp.ServerQpn != 0 {
		ctx.Set(hdrQpn, formatHex(uint64(resp.ServerQpn)))
	}
	if resp.StagingAddr != 0 {
		ctx.Set(hdrMrAddr, formatHex(resp.StagingAddr))
		ctx.Set(hdrMrRkey, formatHex(uint64(resp.StagingRkey)))
	}
	return ctx.SendStatus(fiber.StatusOK)
}

// stageGet reads the object range into the session staging buffer
// and records the staged length on the session.
func (h *Handler) stageGet(ctx fiber.Ctx, sessionID, bucket, key string,
	offset, size uint64) error {
	lease, err := h.svc.BorrowStaging(sessionID)
	if err != nil {
		return mapRcError(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = h.svc.FinishStaging(*lease, false, 0, "", "")
		}
	}()

	acceptRange := fmt.Sprintf("bytes=%d-%d", offset, offset+size-1)
	// Bind the object read to the service context so gateway
	// shutdown cancels it through RCSvc.Close instead of letting
	// the ops wait spin on a stalled backend.
	objCtx, stopSvc := svcCtx(ctx.RequestCtx(), h.svc.Context())
	defer stopSvc()
	res, err := h.be.GetObject(objCtx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Range:  &acceptRange,
	})
	if err != nil {
		return err
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	written, rerr := io.ReadFull(res.Body, lease.Buf)
	if errors.Is(rerr, io.ErrUnexpectedEOF) || errors.Is(rerr, io.EOF) {
		rerr = nil
	}
	if rerr != nil {
		return rerr
	}
	etag, version := "", ""
	if res.ETag != nil {
		etag = *res.ETag
	}
	if res.VersionId != nil {
		version = *res.VersionId
	}
	if err := h.svc.FinishStaging(*lease, true, int(written), etag, version); err != nil {
		return mapRcError(err)
	}
	committed = true
	return nil
}

// Ready handles READY: re-authenticate, re-check authorization for
// the session's target, then run the transfer. PUT picks up the
// received data and hands it to the object backend.
func (h *Handler) Ready(ctx fiber.Ctx) error {
	// Serialize any error at the route boundary: the
	// production S3 error handler turns ordinary Fiber
	// errors into a generic 500 response.
	if err := h.readyCore(ctx); err != nil {
		return WriteRouteError(ctx, err)
	}
	return nil
}

func (h *Handler) readyCore(ctx fiber.Ctx) error {
	if !h.svc.TryEnter() {
		return errNotAdmitted()
	}
	defer h.svc.Leave()

	if proto := ctx.Get(hdrProtocol); proto != protocolValue {
		return invalidHeader(hdrProtocol, proto)
	}

	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)

	principal := principalID(acct)

	sessionID := ctx.Get(hdrSession)
	if sessionID == "" {
		return invalidHeader(hdrSession, "")
	}
	cookie, err := parseUint(ctx.Get(hdrCookie), 16, 32)
	if err != nil || cookie == 0 {
		return invalidHeader(hdrCookie, ctx.Get(hdrCookie))
	}
	qpn, err := parseUint(ctx.Get(hdrQpn), 16, 32)
	if err != nil || qpn == 0 {
		return invalidHeader(hdrQpn, ctx.Get(hdrQpn))
	}
	mrAddr, err := parseUint(ctx.Get(hdrMrAddr), 16, 64)
	if err != nil {
		return invalidHeader(hdrMrAddr, ctx.Get(hdrMrAddr))
	}
	mrRkey, err := parseUint(ctx.Get(hdrMrRkey), 16, 32)
	if err != nil {
		return invalidHeader(hdrMrRkey, ctx.Get(hdrMrRkey))
	}

	info, err := h.svc.SessionInfo(sessionID, principal)
	if err != nil {
		// Owner mismatch and unknown session both answer 404 so
		// the session id is not disclosed cross-principal.
		return mapRcError(err)
	}

	// Re-run authorization for the session's stored target and
	// operation using the account authenticated for this READY
	// request.
	bucket, key, ok := splitTarget(info.Target)
	if !ok {
		return errors.New("invalid session target")
	}
	if err := h.authorize(ctx, acct, isRoot, bucket, key, info.Op == 1); err != nil {
		// Permission revoked mid-session: cancel the session.
		_ = h.svc.Cancel(sessionID, principal)
		return err
	}

	resp, err := h.svc.ReadyTransfer(rcserver.ReadyRequest{
		Principal:    principal,
		SessionID:    sessionID,
		Cookie:       uint32(cookie),
		ClientQpn:    uint32(qpn),
		ClientMrAddr: mrAddr,
		ClientMrRkey: uint32(mrRkey),
	})
	if err != nil {
		// The transfer claim rolled back server-side (wire
		// failure or duplicate READY): this request holds no
		// completion ref, so no local finalizer may run
		// either. A second concurrent READY must not be able
		// to reap a session the first one is still
		// transferring on.
		return mapRcError(err)
	}

	// Busy reports as RC_OK with a retryable outcome carried in
	// the same response (atomic with the transfer result, so a
	// concurrent READY cannot rewrite it); the server already
	// rolled the claim back (state Prepared, no completion ref),
	// so answer 409 without any finalizer.
	if resp.Outcome == rcserver.ReadyBusy {
		return fmt.Errorf("peer busy: %w", rcserver.ErrDouble)
	}

	// The claim succeeded: from here until the response commits,
	// this handler owns the completion ref. A panic or early
	// unwind must still release it so the session can be reaped.
	finalized := false
	defer func() {
		if !finalized {
			_ = h.svc.FinishFinal(sessionID)
		}
	}()

	if info.Op == 1 {
		// PUT: pick up the received bytes and store them.
		// Once GetPutData succeeds the completion ref belongs
		// to the put view and FPU is its only owner (v0.13: no
		// FF after GD, success or failure), so the outer
		// finalizer retires exactly at that point; a failure
		// *before* the borrow still falls back to the
		// finalizer path below.
		put, gd, err := h.commitPut(ctx, sessionID, bucket, key, sizeOf(resp))
		if gd {
			finalized = true
		}
		if err != nil {
			return err
		}
		// The FINAL wire reply carries the stored object's
		// metadata, which the backend assigned at commit time.
		resp.Etag = put.ETag
		resp.VersionID = put.VersionID
	} else if err := h.svc.FinishFinal(sessionID); err != nil {
		return mapRcError(err)
	} else {
		finalized = true
	}

	// Wire reply per the hipobj-rc-v2 contract: protocol echo,
	// cookie echo, transferred bytes, and object metadata.
	ctx.Set(hdrProtocol, protocolValue)
	ctx.Set(hdrBytes, strconv.FormatUint(resp.BytesTransferred, 10))
	ctx.Set(hdrCookie, formatCookie(resp.CookieEcho))
	if resp.Etag != "" {
		ctx.Set(hdrEtag, resp.Etag)
	}
	if resp.VersionID != "" {
		ctx.Set(hdrVersionID, resp.VersionID)
	}
	return ctx.SendStatus(fiber.StatusOK)
}

func sizeOf(resp *rcserver.ReadyResponse) uint64 {
	if resp == nil {
		return 0
	}
	return resp.BytesTransferred
}

// commitPut borrows the PUT view and stores it through the regular
// object-put backend path. The second return value reports whether
// the borrow (GetPutData) succeeded: from that point the put view
// owns the completion ref and FinishPut is its only release, so
// the caller must not run the session finalizer anymore. A
// panic-safe defer releases the view if the handler unwinds before
// FinishPut runs.
func (h *Handler) commitPut(ctx fiber.Ctx, sessionID, bucket, key string,
	size uint64) (*s3response.PutObjectOutput, bool, error) {
	view, err := h.svc.GetPutData(sessionID)
	if err != nil {
		return nil, false, mapRcError(err)
	}
	// Panic-safe ownership: if anything below unwinds, the view is
	// still returned exactly once (the ABI consumes the handle a
	// single time; a redundant FinishPut after a commit is a
	// no-op STALE).
	committed := false
	defer func() {
		if !committed {
			_ = h.svc.FinishPut(*view, false, "", "")
		}
	}()

	contentLength := int64(len(view.Buf))
	putCtx, stopSvc := svcCtx(ctx.RequestCtx(), h.svc.Context())
	defer stopSvc()
	res, err := h.be.PutObject(putCtx, s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		ContentLength: &contentLength,
		Body:          bytes.NewReader(view.Buf),
	})
	if err != nil {
		return nil, true, err
	}
	if err := h.svc.FinishPut(*view, true, res.ETag, res.VersionID); err != nil {
		return nil, true, mapRcError(err)
	}
	committed = true
	return &res, true, nil
}

// Cancel handles CANCEL: authenticated owner tears the session down.
func (h *Handler) Cancel(ctx fiber.Ctx) error {
	// Serialize any error at the route boundary: the
	// production S3 error handler turns ordinary Fiber
	// errors into a generic 500 response.
	if err := h.cancelCore(ctx); err != nil {
		return WriteRouteError(ctx, err)
	}
	return nil
}

func (h *Handler) cancelCore(ctx fiber.Ctx) error {
	if !h.svc.TryEnter() {
		return errNotAdmitted()
	}
	defer h.svc.Leave()

	if proto := ctx.Get(hdrProtocol); proto != protocolValue {
		return invalidHeader(hdrProtocol, proto)
	}

	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	sessionID := ctx.Get(hdrSession)
	if sessionID == "" {
		return invalidHeader(hdrSession, "")
	}
	if err := h.svc.Cancel(sessionID, principalID(acct)); err != nil {
		if errors.Is(err, rcserver.ErrStale) {
			// Already gone: idempotent success for the owner.
			return ctx.SendStatus(fiber.StatusOK)
		}
		return mapRcError(err)
	}
	ctx.Set(hdrProtocol, protocolValue)
	return ctx.SendStatus(fiber.StatusOK)
}

// authorize runs the object access checks (ACL + policy), plus the
// retention/object-lock re-check for PUT, mirroring the regular
// object controllers. The backend lookups run under a context
// merged with the RC service context so gateway shutdown cancels
// them too.
func (h *Handler) authorize(ctx fiber.Ctx, acct auth.Account, isRoot bool,
	bucket, key string, isPut bool) error {
	authCtx, stopSvc := svcCtx(ctx.RequestCtx(), h.svc.Context())
	defer stopSvc()
	acl, err := h.be.GetBucketAcl(authCtx,
		&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return err
	}
	parsedAcl, err := auth.ParseACL(acl)
	if err != nil {
		return err
	}
	action := auth.GetObjectAction
	perm := auth.PermissionRead
	if isPut {
		action = auth.PutObjectAction
		perm = auth.PermissionWrite
	}
	if err := auth.VerifyAccess(ctx, h.be, auth.AccessOptions{
		Acl:           parsedAcl,
		AclPermission: perm,
		IsRoot:        isRoot,
		Acc:           acct,
		Bucket:        bucket,
		Object:        key,
		Actions:       []auth.Action{action},
		Readonly:      h.readonly,
		DisableACL:    h.disableACL,
		Iam:           h.iam,
	}); err != nil {
		return err
	}
	if isPut {
		if err := auth.CheckObjectAccess(ctx, bucket, acct,
			[]types.ObjectIdentifier{{Key: &key}}, auth.BypassOverwrite,
			false, h.be, h.iam, true); err != nil {
			return err
		}
	}
	return nil
}

// svcCtx returns a context bound to both the request and the RC
// service lifetime. Callers must defer the returned stop function
// so the watcher registered on the service context detaches when
// the backend call completes normally, instead of accumulating
// one per request until shutdown.
func svcCtx(request context.Context, svc context.Context) (context.Context, func()) {
	merged, cancel := context.WithCancel(request)
	stop := context.AfterFunc(svc, cancel)
	return merged, func() {
		stop()
		cancel()
	}
}

// splitTarget splits "/bucket/key[?query]" (the canonical wire
// form; a leading slash separates the bucket from the key) and
// percent-decodes each segment: the wire form is the canonical
// percent-encoded path, so the decoded bucket/key must feed the
// authorization and object I/O, not the raw encoding.
func splitTarget(target string) (bucket, key string, ok bool) {
	if target == "" || !strings.HasPrefix(target, "/") {
		return "", "", false
	}
	target = target[1:]
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	bucket, key, found := strings.Cut(target, "/")
	if !found || bucket == "" || key == "" {
		return "", "", false
	}
	bucket, err := url.PathUnescape(bucket)
	if err != nil {
		return "", "", false
	}
	key, err = url.PathUnescape(key)
	if err != nil || key == "" {
		return "", "", false
	}
	return bucket, key, true
}

// parseUint parses a decimal or bare-hex (wire) unsigned value.
// base selects the interpretation: hex fields (PSN, cookie, QPN,
// MR addr/rkey) arrive as bare hex without a 0x prefix; size and
// offset are decimal.
func parseUint(s string, base, bits int) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	return strconv.ParseUint(s, base, bits)
}

// formatPsn renders a PSN as 6 uppercase zero-padded hex chars.
func formatPsn(psn uint32) string {
	return fmt.Sprintf("%06X", psn)
}

// formatCookie renders a cookie as 8 uppercase zero-padded hex
// chars (the wire echo form).
func formatCookie(c uint32) string {
	return fmt.Sprintf("%08X", c)
}

// formatHex renders a value as bare lowercase hex (no 0x prefix),
// the wire form for QPN/MR fields.
func formatHex(v uint64) string {
	return strconv.FormatUint(v, 16)
}

// mapRcError translates ABI statuses into HTTP-shaped failures.
// mapRcError wraps a session-server error so the shared terminal
// serializer in errors.go can classify it. Owner mismatch answers
// the same 404 as an unknown session so a session id is never
// disclosed across principals.
func mapRcError(err error) error {
	switch {
	case errors.Is(err, rcserver.ErrSession):
		return fmt.Errorf("session owner mismatch: %w",
			rcserver.ErrNoSession)
	}
	return err
}
