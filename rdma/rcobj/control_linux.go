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

/*
#include <hipobj.h>
*/
import "C"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/versity/versitygw/internal/sigv4auth"
)

// Wire constants, shared with the reference bridge (hipobj_minio/rdma.h).
const (
	hdrProtocol       = "x-amz-rdma-protocol"
	protocolV2        = "hipobj-rc-v2"
	hdrToken          = "x-amz-rdma-token"
	hdrReply          = "x-amz-rdma-reply"
	hdrSession        = "x-amz-rdma-session"
	hdrCookie         = "x-amz-rdma-cookie"
	hdrPsn            = "x-amz-rdma-psn"
	hdrOp             = "x-amz-rdma-op"
	hdrSize           = "x-amz-rdma-size"
	hdrOffset         = "x-amz-rdma-offset"
	hdrTarget         = "x-amz-rdma-target"
	hdrQpn            = "x-amz-rdma-qpn"
	hdrMrAddr         = "x-amz-rdma-mr-addr"
	hdrMrRkey         = "x-amz-rdma-mr-rkey"
	hdrBytes          = "x-amz-rdma-bytes-transferred"
	hdrEtag           = "x-amz-rdma-etag"
	hdrChecksum       = "x-amz-rdma-checksum"
	hdrProtocolStatus = "x-amz-rdma-protocol-status"
	hdrCapabilities   = "x-amz-rdma-capabilities"

	pathPrepare = "/.hipobj-rc/prepare"
	pathReady   = "/.hipobj-rc/ready"
	pathCancel  = "/.hipobj-rc/cancel"

	// Per the plan (section 4, C2): the Go wrapper signs the
	// empty-body SHA256; the bridge's UNSIGNED-PAYLOAD stays
	// bridge-only.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Credentials supplies the SigV4 identity for control requests. It
// must be cached or otherwise bounded: the transfer deadline covers
// credential acquisition, and the library cannot interrupt a
// synchronous fetch from inside a callback (hipobj.h contract).
type Credentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Region       string
}

// controlPlane implements the four hipobj-rc-v2 callbacks over one
// net/http transport. The READY exchange keeps a dedicated
// connection: sendReadyRequest writes the request bytes and returns,
// the data phase runs while the response is pending, and finishReady
// reads it. An aborted exchange closes that connection and never
// reuses it.
type controlPlane struct {
	creds Credentials

	dialer *net.Dialer
	// base holds the one-shot (PREPARE/CANCEL) connections.
	base *http.Client

	// The pending READY exchange, set by sendReadyRequest and
	// consumed exactly once by finishReady or an abort.
	pendingMu sync.Mutex
	pending   *readyExchange

	// elig is the admission layer; nil disables the fail-closed
	// gating (probeless operation, e.g. tests driving the
	// callbacks directly).
	elig *Eligibility

	// lastCaps memoizes the capability advertisement the last
	// PREPARE response carried (probe evidence for the caller).
	capsMu   sync.Mutex
	lastCaps string
}

// recordCapabilities stores the advertisement observed on the
// PREPARE surface so the admission layer and callers can inspect
// it after a transfer.
func (cp *controlPlane) recordCapabilities(resp *http.Response) {
	caps := resp.Header.Get(hdrCapabilities)
	cp.capsMu.Lock()
	cp.lastCaps = caps
	cp.capsMu.Unlock()
}

// Capabilities returns the capability advertisement observed by the
// most recent PREPARE exchange, or "" when none was carried.
func (cp *controlPlane) Capabilities() string {
	cp.capsMu.Lock()
	defer cp.capsMu.Unlock()
	return cp.lastCaps
}

type readyExchange struct {
	conn net.Conn
	bw   *bufio.Writer
	br   *bufio.Reader
	req  *http.Request
}

func newControlPlane(cfg Config) *controlPlane {
	d := &net.Dialer{Timeout: 30 * time.Second}
	return &controlPlane{
		creds:  cfg.Credentials,
		dialer: d,
		base: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return d.DialContext(ctx, "tcp", addr)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// budget converts the callback's remaining budget into a context
// deadline; zero means the budget is exhausted and the call fails
// fast (hipobj.h contract).
func budget(r transferReq) (time.Time, bool) {
	if r.Remaining == 0 {
		return time.Time{}, false
	}
	return time.Now().Add(time.Duration(r.Remaining) * time.Millisecond), true
}

// dialControl dials the control authority, binding to the netdev
// that backs the data plane's selected GID when one is known (the
// same multi-port safety the bridge enforces).
func (cp *controlPlane) dialControl(ctx context.Context, r transferReq) (net.Conn, error) {
	uri := r.Endpoint
	if uri == "" {
		return nil, errors.New("no control endpoint")
	}
	if strings.HasPrefix(uri, "https://") {
		return nil, errors.New("https control endpoint is not supported")
	}
	host := uri
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	if r.Nic != "" {
		if dev, ok := netdevForGid(r.Nic, r.NicPort, r.NicGid); ok {
			if la, err := linkAddr(dev); err == nil {
				cp.dialer.LocalAddr = &net.TCPAddr{IP: la}
			}
		}
	}
	return cp.dialer.DialContext(ctx, "tcp", host)
}

// signAndWrite signs the request per SigV4 (host, x-amz-date,
// x-amz-content-sha256 of the empty body, Content-Length: 0, plus
// the rdma headers) and writes it to conn without reading the
// response.
func (cp *controlPlane) signAndWrite(conn net.Conn, r transferReq,
	path string, extra http.Header) error {

	host := hostOf(conn.RemoteAddr())
	hdr := http.Header{}
	hdr.Set("Host", host)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	hdr.Set("x-amz-date", amzDate)
	hdr.Set("x-amz-content-sha256", emptySHA256)
	hdr.Set("Content-Length", "0")
	for k, v := range extra {
		for _, vv := range v {
			hdr.Add(k, vv)
		}
	}
	if cp.creds.SessionToken != "" {
		hdr.Set("X-Amz-Security-Token", cp.creds.SessionToken)
	}

	signedHdrs := make([]string, 0, len(hdr))
	for k := range hdr {
		signedHdrs = append(signedHdrs, strings.ToLower(k))
	}
	sort.Strings(signedHdrs)

	scope := sigv4auth.BuildCredentialScope(now.Format("20060102"),
		cp.creds.Region, sigv4auth.ServiceS3)
	key := sigv4auth.DeriveKey(cp.creds.SecretKey, now.Format("20060102"),
		cp.creds.Region, sigv4auth.ServiceS3)
	res := sigv4auth.BuildAndSign(key, sigv4auth.SigningInput{
		Method:          http.MethodPost,
		Host:            host,
		URIPath:         path,
		Query:           nil,
		Header:          hdr,
		ContentLength:   0,
		AccessKeyID:     cp.creds.AccessKey,
		CredentialScope: scope,
		SignedHdrs:      signedHdrs,
		PayloadHash:     emptySHA256,
		SigningTime:     now,
	})

	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	for k, v := range res.SignedHeaders {
		for _, vv := range v {
			b.WriteString(k + ": " + vv + "\r\n")
		}
	}
	b.WriteString("Authorization: " + res.AuthorizationHeader + "\r\n")
	b.WriteString("Connection: keep-alive\r\n\r\n")
	_, err := io.WriteString(conn, b.String())
	return err
}

func hostOf(addr net.Addr) string {
	h := addr.String()
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h
}

// prepare implements sendPrepare: one complete round trip.
func (cp *controlPlane) prepare(r transferReq,
	out *C.hipObjPrepareReplyV2_t) int {

	deadline, ok := budget(r)
	if !ok {
		return -1
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	conn, err := cp.dialControl(ctx, r)
	if err != nil {
		return -1
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return -1
	}

	extra := http.Header{}
	extra.Set(hdrProtocol, protocolV2)
	extra.Set(hdrToken, r.Token)
	extra.Set(hdrPsn, hex24(r.ClientPsn))
	extra.Set(hdrCookie, hex32(r.Cookie))
	extra.Set(hdrOp, r.Method)
	extra.Set(hdrTarget, targetOf(r))
	extra.Set(hdrSize, strconv.FormatUint(r.Size, 10))
	if r.Offset != 0 {
		extra.Set(hdrOffset, strconv.FormatUint(r.Offset, 10))
	}

	if err := cp.signAndWrite(conn, r, pathPrepare, extra); err != nil {
		return -1
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	fillPrepareReply(cp, out, resp)
	return 0
}

// readyRequest implements sendReadyRequest: dial a dedicated
// connection, write the signed request, return without reading.
func (cp *controlPlane) readyRequest(r transferReq) int {
	deadline, ok := budget(r)
	if !ok {
		return -1
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	conn, err := cp.dialControl(ctx, r)
	if err != nil {
		return -1
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		conn.Close()
		return -1
	}

	extra := http.Header{}
	extra.Set(hdrProtocol, protocolV2)
	extra.Set(hdrSession, r.Session)
	extra.Set(hdrCookie, hex32(r.Cookie))
	extra.Set(hdrQpn, hex64(uint64(r.ClientQpn)))
	extra.Set(hdrMrAddr, hex64(r.ClientMrAddr))
	extra.Set(hdrMrRkey, hex32(r.ClientMrRkey))

	if err := cp.signAndWrite(conn, r, pathReady, extra); err != nil {
		conn.Close()
		return -1
	}
	cp.pendingMu.Lock()
	defer cp.pendingMu.Unlock()
	if cp.pending != nil {
		conn.Close()
		return -1 // one exchange at a time
	}
	cp.pending = &readyExchange{conn: conn, br: bufio.NewReader(conn)}
	return 0
}

// finishReady implements finishReady: read the FINAL response off
// the pending exchange and consume it exactly once.
func (cp *controlPlane) finishReady(r transferReq,
	out *C.hipObjFinalReplyV2_t) int {

	deadline, ok := budget(r)
	if !ok {
		cp.abortPending()
		return -1
	}
	cp.pendingMu.Lock()
	ex := cp.pending
	cp.pending = nil
	cp.pendingMu.Unlock()
	if ex == nil {
		return -1
	}
	if err := ex.conn.SetReadDeadline(deadline); err != nil {
		ex.conn.Close()
		return -1
	}
	resp, err := http.ReadResponse(ex.br, &http.Request{Method: http.MethodPost})
	if err != nil {
		ex.conn.Close()
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	ex.conn.Close()
	fillFinalReply(out, resp)
	return 0
}

// abortPending closes the pending exchange without reading (the
// transfer deadline is spent or the data phase failed).
func (cp *controlPlane) abortPending() {
	cp.pendingMu.Lock()
	ex := cp.pending
	cp.pending = nil
	cp.pendingMu.Unlock()
	if ex != nil {
		ex.conn.Close()
	}
}

// cancel implements sendCancel: one idempotent round trip on a
// fresh connection under the cleanup budget.
func (cp *controlPlane) cancel(r transferReq) int {
	deadline, ok := budget(r)
	if !ok {
		return -1
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	conn, err := cp.dialControl(ctx, r)
	if err != nil {
		return -1
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return -1
	}

	extra := http.Header{}
	extra.Set(hdrProtocol, protocolV2)
	extra.Set(hdrSession, r.Session)
	extra.Set(hdrCookie, hex32(r.Cookie))

	if err := cp.signAndWrite(conn, r, pathCancel, extra); err != nil {
		return -1
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	return 0
}

func fillPrepareReply(cp *controlPlane, out *C.hipObjPrepareReplyV2_t, resp *http.Response) {
	out.httpStatus = C.int(resp.StatusCode)
	if strings.EqualFold(resp.Header.Get(hdrProtocol), protocolV2) {
		out.protocolEcho = 1
	}
	// Capability advertisement observed on the PREPARE surface is
	// recorded on the control plane for the admission layer; the
	// C reply carries only the wire contract fields.
	cp.recordCapabilities(resp)
	if strings.EqualFold(resp.Header.Get(hdrProtocolStatus), "unsupported") {
		out.unsupportedMarker = 1
	}
	if tok := replyTokenPayload(resp.Header.Get(hdrReply)); tok != "" {
		setCStr(&out.serverToken[0], tok)
	}
	if s := resp.Header.Get(hdrSession); s != "" {
		setCStr(&out.session[0], s)
	}
	if psn := resp.Header.Get(hdrPsn); psn != "" {
		if n, err := strconv.ParseUint(psn, 16, 32); err == nil && n <= 0xffffff {
			out.serverPsn = C.uint32_t(n)
		}
	}
	saddr := resp.Header.Get(hdrMrAddr)
	srkey := resp.Header.Get(hdrMrRkey)
	if saddr != "" || srkey != "" {
		a, aerr := strconv.ParseUint(saddr, 16, 64)
		rk, rerr := strconv.ParseUint(srkey, 16, 32)
		if aerr != nil || rerr != nil {
			// Malformed or partial staging is reported as absent so
			// the core classifies the reply as InvalidValue for PUT.
			out.stagingPresent = 0
			return
		}
		out.stagingAddr = C.uint64_t(a)
		out.stagingRkey = C.uint32_t(rk)
		out.stagingPresent = 1
	}
}

func fillFinalReply(out *C.hipObjFinalReplyV2_t, resp *http.Response) {
	out.httpStatus = C.int(resp.StatusCode)
	if strings.EqualFold(resp.Header.Get(hdrProtocol), protocolV2) {
		out.protocolEcho = 1
	}
	if b := resp.Header.Get(hdrBytes); b != "" {
		if n, err := strconv.ParseUint(b, 10, 64); err == nil {
			out.bytes = C.uint64_t(n)
		}
	}
	if c := resp.Header.Get(hdrCookie); c != "" {
		out.cookiePresent = 1
		if n, err := strconv.ParseUint(c, 16, 32); err == nil {
			out.cookieEcho = C.uint32_t(n)
		}
	}
	if e := resp.Header.Get(hdrEtag); e != "" {
		setCStr(&out.etag[0], e)
	}
	if v := resp.Header.Get("x-amz-version-id"); v != "" {
		setCStr(&out.versionId[0], v)
	}
	if cs := resp.Header.Get(hdrChecksum); cs != "" {
		setCStr(&out.checksumB64[0], cs)
	}
}

// replyTokenPayload strips the status prefix the x-amz-rdma-reply
// header carries ("200 <token>").
func replyTokenPayload(v string) string {
	if i := strings.IndexByte(v, ' '); i >= 0 {
		return v[i+1:]
	}
	return ""
}

// setCStr copies s into a fixed C char array (NUL-terminated,
// truncated to fit).
func setCStr(dst *C.char, s string) {
	b := []byte(s)
	n := len(b)
	for i := 0; i < n; i++ {
		*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(dst)) + uintptr(i))) = C.char(b[i])
	}
	*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(dst)) + uintptr(n))) = 0
}

func hex24(v uint32) string { return fmt.Sprintf("%06x", v) }
func hex32(v uint32) string { return fmt.Sprintf("%08x", v) }
func hex64(v uint64) string { return fmt.Sprintf("%016x", v) }

func targetOf(r transferReq) string {
	if r.Target != "" {
		return r.Target
	}
	t := "/" + r.Bucket + "/" + r.Key
	if r.Query != "" {
		t += "?" + r.Query
	}
	return t
}

// netdevForGid reads the sysfs ndevs entry backing the data plane's
// selected GID, so the control connection binds the same interface
// the RDMA address handle uses.
func netdevForGid(dev string, port, gid int) (string, bool) {
	if dev == "" || port <= 0 || gid < 0 {
		return "", false
	}
	p := fmt.Sprintf("/sys/class/infiniband/%s/ports/%d/gid_attrs/ndevs/%d", dev, port, gid)
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	name := strings.TrimSpace(string(b))
	return name, name != ""
}

// linkAddr picks a source address on the named interface so the
// control TCP connection egresses through it.
func linkAddr(dev string) (net.IP, error) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return ipn.IP, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on %s", dev)
}
