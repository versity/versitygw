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
	"sync/atomic"
	"syscall"
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

	// probeGen numbers physical probe exchanges so Admit can bind
	// evidence to the transport generation that produced it.
	probeGen atomic.Uint64

	// endpoint is the configured control authority (host[:port]).
	endpoint string

	// probeBucket/probeKey name the admission probe object, set by
	// the owner before the first transfer.
	probeMu      sync.Mutex
	probeBucket  string
	probeKey     string
	probeNic     string
	probeNicPort int
	probeNicGid  int
	probePeer    string

	// lastCaps memoizes the capability advertisement the last
	// PREPARE response carried (probe evidence for the caller).
	capsMu   sync.Mutex
	lastCaps string
}

// SetProbeObject names the object the admission probe reads.
func (cp *controlPlane) SetProbeObject(bucket, key string) {
	cp.probeMu.Lock()
	cp.probeBucket = bucket
	cp.probeKey = key
	cp.probeMu.Unlock()
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
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
		DisableKeepAlives: true,
	}
	cp := &controlPlane{
		creds:  cfg.Credentials,
		dialer: d,
		base: &http.Client{
			Transport: tr,
			// The probe must observe the endpoint's own verdict,
			// not a redirect chain that ends in a 2xx elsewhere.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	// The admission probe rides the same signed request shape the
	// transfer callbacks use, against the real object API. An
	// empty probe object leaves the layer negative: PREPARE fails
	// closed until SetProbeObject supplies one.
	cp.endpoint = cfg.ControlEndpoint
	cp.probeBucket = cfg.ProbeBucket
	cp.probeKey = cfg.ProbeKey
	cp.elig = NewEligibility(cp.signedObjectProbe)
	return cp
}

// signedObjectProbe issues the admission evidence request: a
// one-byte ranged GET of the probe object, signed with the
// configured credentials. Only a direct 2xx answer is positive.
func (cp *controlPlane) signedObjectProbe(ctx context.Context) (uint64, bool, error) {
	// Snapshot the whole probe input under one lock hold: the
	// object identity and the transport selection are captured
	// together, so the request the probe sends is exactly the one
	// the triggering PREPARE configured.
	cp.probeMu.Lock()
	bucket, key := cp.probeBucket, cp.probeKey
	nic, nicPort, nicGid := cp.probeNic, cp.probeNicPort, cp.probeNicGid
	cp.probeMu.Unlock()
	if key == "" {
		return 0, false, errors.New("rcobj: no probe object")
	}
	// The probe rides the same transport selection the transfer
	// callbacks use: the selected NIC, port, and GID that the C
	// core reported for the data plane bind the probe socket too,
	// so admission evidence reflects the interface that will
	// actually carry the exchange. (The C core invokes the
	// callbacks serially under apiLock; the snapshot above keeps
	// the fields self-consistent even if that ever changes.)
	r := transferReq{Bucket: bucket, Key: key, Endpoint: cp.endpoint,
		Nic: nic, NicPort: nicPort, NicGid: nicGid}
	// The probe rides the caller's deadline: PREPARE handed its
	// remaining budget to the admission layer, so dial, write,
	// and read all share one absolute cutoff. A context without a
	// deadline means the caller bypassed the budget contract;
	// fail closed rather than inventing time the transfer does
	// not have.
	dl, has := ctx.Deadline()
	if !has {
		return 0, false, errors.New("rcobj: probe without deadline")
	}
	ctx2, cancel := context.WithDeadline(ctx, dl)
	defer cancel()
	conn, err := cp.dialControl(ctx2, r)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(dl); err != nil {
		return 0, false, err
	}
	extra := http.Header{}
	extra.Set("Range", "bytes=0-0")
	path := probeObjectPath(bucket, key)
	if err := cp.signAndWrite(conn, r, http.MethodGet, path, extra); err != nil {
		return 0, false, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return 0, false, err
	}
	// A direct 2xx from the object API is positive admission
	// evidence: the credentials work and the endpoint serves
	// object traffic on this transport. Whether it speaks the v2
	// protocol is PREPARE's negotiation; a legacy gateway that
	// answers the probe but declines PREPARE with NotSupported
	// lets the CLI fall back without admission blocking it first.
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	// Pin the evidence to the peer that actually answered: every
	// later admitted exchange re-resolves the authority, so a
	// different reachable peer means the evidence no longer
	// describes where the bytes would go.
	if ok {
		cp.probeMu.Lock()
		cp.probePeer = conn.RemoteAddr().String()
		cp.probeMu.Unlock()
	}
	gen := cp.probeGen.Add(1)
	return gen, ok, nil
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
	d := cp.dialer
	if r.Nic != "" {
		dev, ok := netdevForGidLookup(r.Nic, r.NicPort, r.NicGid)
		if !ok {
			// The bridge refuses the connection when it cannot
			// resolve the selected netdev; so does the wrapper.
			return nil, fmt.Errorf("selected interface %q (port %d, gid %d) not found",
				r.Nic, r.NicPort, r.NicGid)
		}
		// Bind the socket to the selected interface and let the
		// kernel choose the source address from its routes, the
		// same policy the reference bridge uses. Pinning a
		// source ourselves cannot see routing domains (ULA vs
		// global) and picks addresses the return route cannot
		// reach; SO_BINDTODEVICE keeps the traffic on the
		// selected device while the kernel applies source
		// selection per candidate. A hostname (or scoped
		// literal) is resolved here under the same deadline,
		// and the dial retries across families so an
		// unreachable route falls back like an ordinary dial
		// would.
		cands, rerr := resolveDest(ctx, host)
		if rerr != nil {
			return nil, rerr
		}
		// Divide the remaining budget evenly across the
		// candidates: one blackholed route must not consume
		// the whole deadline before the other family is
		// tried. The per-attempt timeout also stays capped by
		// that share.
		remaining := time.Until(cp.deadlineFor(ctx))
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		per := remaining / time.Duration(len(cands))
		var lastErr error
		// The fallback source is discovered at most once per
		// dial (including a failed lookup), but eligibility is
		// evaluated per candidate: a refused first destination
		// must not disable the fallback for a later reachable
		// one.
		var v4Src *net.TCPAddr
		v4Resolved := false
		for _, c := range cands {
			perTimeout := per
			if t := cp.dialer.Timeout; t > 0 && t < per {
				perTimeout = t
			}
			nd := net.Dialer{Timeout: perTimeout,
				DualStack: cp.dialer.DualStack,
				KeepAlive: cp.dialer.KeepAlive,
				Control:   bindToDevice(dev)}
			actx, acancel := context.WithTimeout(ctx, per)
			conn, derr := nd.DialContext(actx, "tcp", c)
			acancel()
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
			// Older kernels refuse SO_BINDTODEVICE without
			// CAP_NET_RAW on every socket: degrade to the
			// interface's IPv4 address binding, the fallback
			// the reference bridge ships, instead of failing
			// the whole transfer path.
			if errors.Is(derr, syscall.EPERM) {
				is4 := false
				if chost, _, serr := net.SplitHostPort(c); serr == nil {
					if ip := net.ParseIP(chost); ip != nil && ip.To4() != nil {
						is4 = true
					}
				}
				if is4 {
					if !v4Resolved {
						v4Resolved = true
						if la, aerr := devIPv4Addr(dev); aerr == nil {
							v4Src = &net.TCPAddr{IP: la}
						}
					}
					if v4Src != nil {
						fd := net.Dialer{Timeout: perTimeout,
							DualStack: cp.dialer.DualStack,
							KeepAlive: cp.dialer.KeepAlive}
						fd.LocalAddr = v4Src
						fctx, fcancel := context.WithTimeout(ctx, per)
						conn, ferr := fd.DialContext(fctx, "tcp", c)
						fcancel()
						if ferr == nil {
							return conn, nil
						}
						lastErr = ferr
					}
				}
			}
			if ctx.Err() != nil {
				// The shared budget is gone; later candidates
				// cannot succeed either.
				break
			}
		}
		return nil, lastErr
	}
	return d.DialContext(ctx, "tcp", host)
}

// bindToDevice returns a socket control function that binds new
// sockets to the named interface (SO_BINDTODEVICE) so the kernel
// routes and picks source addresses within that device alone.
// The control function returns EPERM unchanged: older kernels
// (before 5.7) require CAP_NET_RAW for every SO_BINDTODEVICE set,
// and the reference bridge degrades to binding the interface's
// IPv4 address instead of failing the connection. The dial loop
// observes that permission error through the failed candidate and
// retries IPv4 destinations from the interface address, so
// unprivileged deployments on those kernels keep the IPv4 path
// the bridge supports.
// bindToDevice builds the socket control function binding sockets
// to the named interface; tests replace it to force EPERM.
var bindToDevice = func(dev string) func(string, string, syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		if errors.Is(serr, syscall.EPERM) {
			// Signal the dial loop through the error value; the
			// candidate dial fails and the loop falls back.
			return serr
		}
		return serr
	}
}

// devIPv4Addr reports the first IPv4 address on the named
// interface, for the permission-denied fallback.
// devIPv4Addr reports the first IPv4 address on the named
// interface, for the permission-denied fallback; tests replace it.
var devIPv4Addr = func(dev string) (net.IP, error) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipn.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on %s", dev)
}

// deadlineFor reports the cutoff the caller's context carries, or
// the zero time when it has none.
func (cp *controlPlane) deadlineFor(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Time{}
}

// resolveDest expands the endpoint host into dial candidates in
// preference order. A literal (with or without a zone) is its own
// single candidate; a hostname is resolved through the resolver
// the context allows, preserving address order and zones. The
// candidates are still host:port strings so a zone survives into
// the dial.
// resolveDest expands a host or scoped literal into dial
// candidates; tests replace it to control candidate order.
var resolveDest = func(ctx context.Context, hostport string) ([]string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = "80"
	}
	// A scoped literal keeps its zone through ParseIP? No: the
	// net package rejects zoned literals in ParseIP but SplitHostPort
	// preserves the zone in the host string, so treat it as an
	// IPv6 literal and dial it verbatim.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip := net.ParseIP(strings.SplitN(host, "%", 2)[0]); ip != nil {
		return []string{net.JoinHostPort(host, port)}, nil
	}
	addrs, rerr := net.DefaultResolver.LookupIPAddr(ctx, host)
	if rerr != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, rerr)
	}
	cands := make([]string, 0, len(addrs))
	for _, a := range addrs {
		cands = append(cands, net.JoinHostPort(a.IP.String(), port))
	}
	return cands, nil
}

// signAndWrite signs the control-plane request per SigV4 (host,
// x-amz-date, x-amz-content-sha256 of the empty body,
// Content-Length: 0, plus the rdma headers) and writes it to conn
// without reading the response. The control exchanges are POSTs;
// pass method http.MethodGet for the admission probe.
func (cp *controlPlane) signAndWrite(conn net.Conn, r transferReq,
	method, path string, extra http.Header) error {

	host := authorityOf(r.Endpoint)
	if host == ":80" {
		host = hostOf(conn.RemoteAddr())
	}
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
		Method:          method,
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
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	// The Host header is written exactly once: Go's http.Header
	// canonicalization would emit a duplicate if it were also in
	// the signed set (the signer lowercases into the same slot,
	// so the map held two values under one key).
	b.WriteString("Host: " + host + "\r\n")
	for k, v := range res.SignedHeaders {
		if strings.EqualFold(k, "Host") {
			continue
		}
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

// authorityOf extracts the host[:port] the endpoint URL names, the
// authority that must appear in the signed and transmitted Host
// header. It defaults the port to :80 exactly like dialControl.
func authorityOf(endpoint string) string {
	h := endpoint
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	if !strings.Contains(h, ":") {
		h += ":80"
	}
	return h
}

// prepare implements sendPrepare: the admission valve first, then
// one complete round trip.
func (cp *controlPlane) prepare(r transferReq,
	out *C.hipObjPrepareReplyV2_t) int {

	// One absolute deadline governs the whole callback: the
	// admission probe (when needed) and the PREPARE exchange share
	// the remaining budget, and an exhausted budget fails before
	// anything touches the wire.
	deadline, ok := budget(r)
	if !ok {
		return -1
	}

	// Admission valve: when the layer is negative (first use, or a
	// transport replacement invalidated the evidence) a fresh probe
	// must succeed before this transfer touches the wire.
	if cp.elig != nil && !cp.elig.Admitted() {
		cp.probeMu.Lock()
		cp.probeNic = r.Nic
		cp.probeNicPort = r.NicPort
		cp.probeNicGid = r.NicGid
		cp.probeMu.Unlock()
		// The probe shares the callback's budget: it runs under
		// the same absolute deadline PREPARE will use, so it can
		// never outlive the transfer it is admitting.
		pctx, pcancel := context.WithDeadline(context.Background(), deadline)
		perr := cp.elig.Probe(pctx)
		pcancel()
		if perr != nil || !cp.elig.Admitted() {
			return -1
		}
	}

	return cp.prepareWire(r, out, deadline)
}

// connLost reports whether err is an actual transport failure
// rather than the callback budget expiring: the typed deadline
// errors are intentional local aborts, while everything else -
// resets, EOFs, refused writes, truncated bodies - means the
// connection the admission evidence rode on is gone, whether the
// failure was observed before or after the cutoff.
func connLost(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return true
}

// peerMatches reports whether the freshly dialed connection
// reaches the peer the admission evidence was pinned to. An empty
// pin (no successful probe yet) never matches: the valve in
// prepare has already re-probed by then, so this only guards the
// window between the probe and this dial.
func (cp *controlPlane) peerMatches(conn net.Conn) bool {
	cp.probeMu.Lock()
	pin := cp.probePeer
	cp.probeMu.Unlock()
	return pin != "" && pin == conn.RemoteAddr().String()
}

// invalidate drops the admission evidence when the transport it
// was gathered on has observably broken mid-exchange.
func (cp *controlPlane) invalidate() {
	if cp.elig != nil {
		cp.elig.OnConnectionChange(0)
	}
}

// prepareWire is the PREPARE round trip without the valve.
func (cp *controlPlane) prepareWire(r transferReq,
	out *C.hipObjPrepareReplyV2_t, deadline time.Time) int {

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	conn, err := cp.dialControl(ctx, r)
	if err != nil {
		// The transport the admission evidence was gathered on
		// refused the dial (or the budget expired first, which is
		// an intentional local abort): only a real refusal
		// invalidates the evidence.
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return -1
	}
	// The admitted exchange must reach the same peer the probe
	// pinned: a re-resolution that landed elsewhere means the
	// evidence authorizes the wrong server, so fail closed and
	// re-probe rather than sending.
	if !cp.peerMatches(conn) {
		cp.invalidate()
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

	if err := cp.signAndWrite(conn, r, http.MethodPost, pathPrepare, extra); err != nil {
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	defer resp.Body.Close()

	// A redirect on a control exchange replaces the transport the
	// admission evidence was gathered on. Invalidate immediately
	// after the status line: a stalled or truncated body must not
	// leave the stale positive decision in place.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		cp.invalidate()
	}

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}

	if !fillPrepareReply(cp, out, resp) {
		return -1
	}
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
		// The transport the admission evidence was gathered on
		// refused the dial (or the budget expired first, which is
		// an intentional local abort): only a real refusal
		// invalidates the evidence.
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		conn.Close()
		return -1
	}
	// READY rides its own dial: the same pinned peer must answer
	// before the admitted bytes flow.
	if !cp.peerMatches(conn) {
		conn.Close()
		cp.invalidate()
		return -1
	}

	extra := http.Header{}
	extra.Set(hdrProtocol, protocolV2)
	extra.Set(hdrSession, r.Session)
	extra.Set(hdrCookie, hex32(r.Cookie))
	extra.Set(hdrQpn, hex64(uint64(r.ClientQpn)))
	extra.Set(hdrMrAddr, hex64(r.ClientMrAddr))
	extra.Set(hdrMrRkey, hex32(r.ClientMrRkey))

	if err := cp.signAndWrite(conn, r, http.MethodPost, pathReady, extra); err != nil {
		conn.Close()
		if connLost(err) {
			cp.invalidate()
		}
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
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	// Invalidate on the status line, before any fallible body
	// work can strand the stale admission decision.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		cp.invalidate()
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		ex.conn.Close()
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	ex.conn.Close()
	if !fillFinalReply(out, resp) {
		return -1
	}
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
	// The library calls CANCEL without a prior finishReady whenever
	// the data phase failed or expired, so the pending READY
	// exchange is released here first: its socket must be closed,
	// not pooled, and the slot must be free for the next transfer.
	cp.abortPending()

	deadline, ok := budget(r)
	if !ok {
		return -1
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	conn, err := cp.dialControl(ctx, r)
	if err != nil {
		// The transport the admission evidence was gathered on
		// refused the dial (or the budget expired first, which is
		// an intentional local abort): only a real refusal
		// invalidates the evidence.
		if connLost(err) {
			cp.invalidate()
		}
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

	if err := cp.signAndWrite(conn, r, http.MethodPost, pathCancel, extra); err != nil {
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	// A redirect on the cleanup exchange replaces the transport
	// the admission evidence rode on; invalidate on the status
	// line as on every other admitted exchange.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		cp.invalidate()
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		if connLost(err) {
			cp.invalidate()
		}
		return -1
	}
	return 0
}

func fillPrepareReply(cp *controlPlane, out *C.hipObjPrepareReplyV2_t, resp *http.Response) bool {
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
		if !setCStr(&out.serverToken[0], tok, 97) {
			return false
		}
	}
	if s := resp.Header.Get(hdrSession); s != "" {
		if !setCStr(&out.session[0], s, 65) {
			return false
		}
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
			return true
		}
		out.stagingAddr = C.uint64_t(a)
		out.stagingRkey = C.uint32_t(rk)
		out.stagingPresent = 1
	}
	return true
}

func fillFinalReply(out *C.hipObjFinalReplyV2_t, resp *http.Response) bool {
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
		if !setCStr(&out.etag[0], e, 128) {
			return false
		}
	}
	if v := resp.Header.Get("x-amz-version-id"); v != "" {
		if !setCStr(&out.versionId[0], v, 128) {
			return false
		}
	}
	if cs := resp.Header.Get(hdrChecksum); cs != "" {
		if !copyChecksum(&out.checksumB64[0], cs) {
			return false
		}
	}
	return true
}

// prepareForTest drives one PREPARE exchange and reports only the
// return code; test builds cannot import "C" directly, so the C
// reply struct stays inside the cgo build. It drives the wire
// exchange directly so wire-level tests need no probe object.
func (cp *controlPlane) prepareForTest(r transferReq) int {
	deadline, ok := budget(r)
	if !ok {
		return -1
	}
	var out C.hipObjPrepareReplyV2_t
	return cp.prepareWire(r, &out, deadline)
}

// prepareValveForTest drives the production entry point in full:
// the admission valve (probe when negative) then the PREPARE
// exchange, writing the reply into a real cgo struct so tests can
// assert the re-probe and recovery path end to end.
func (cp *controlPlane) prepareValveForTest(r transferReq) int {
	var out C.hipObjPrepareReplyV2_t
	return cp.prepare(r, &out)
}

// finishReadyForTest drives the FINAL read and reports only the
// return code.
func (cp *controlPlane) finishReadyForTest(r transferReq) int {
	var out C.hipObjFinalReplyV2_t
	return cp.finishReady(r, &out)
}

// replyTokenPayload strips the status prefix the x-amz-rdma-reply
// header carries ("<three digits>:<token>" from the bridge and
// gateway). Only that shape yields a payload;
// a bare token without the prefix, a malformed prefix, or an empty
// suffix all return empty so the caller treats the header as
// absent rather than fabricating a token.
func replyTokenPayload(v string) string {
	if len(v) < 4 || v[3] != ':' {
		return ""
	}
	for i := 0; i < 3; i++ {
		if v[i] < '0' || v[i] > '9' {
			return ""
		}
	}
	return v[4:]
}

// setCStr copies s into a fixed C char array of cap bytes,
// NUL-terminated. It returns false when s does not fit; the
// destination stays empty in that case so an oversized protocol
// field is rejected rather than silently truncating or spilling
// into adjacent struct memory.
func setCStr(dst *C.char, s string, cap int) bool {
	if len(s) >= cap {
		return false
	}
	for i := 0; i < len(s); i++ {
		*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(dst)) + uintptr(i))) = C.char(s[i])
	}
	*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(dst)) + uintptr(len(s)))) = 0
	return true
}

// copyChecksum validates the "CRC64NVME <base64>" form and copies
// only the 12-character canonical base64 payload.
// copyChecksum validates the wire checksum against the bridge
// contract: exactly "CRC64NVME " followed by the canonical base64
// of eight bytes - eleven data characters and one '=' pad, with
// the pad in the final position only. Anything else (unknown
// algorithm, wrong length, misplaced or repeated padding) is
// rejected rather than stored as if it were a valid value.
func copyChecksum(dst *C.char, v string) bool {
	if !checksumValid(v) {
		return false
	}
	return setCStr(dst, v[len("CRC64NVME "):], 13)
}

// checksumValid is the pure predicate for the wire checksum
// contract, so tests can pin it without cgo.
func checksumValid(v string) bool {
	const prefix = "CRC64NVME "
	if !strings.HasPrefix(v, prefix) {
		return false
	}
	payload := v[len(prefix):]
	if len(payload) != 12 || payload[11] != '=' {
		return false
	}
	for i := 0; i < 11; i++ {
		c := payload[i]
		isB64 := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/'
		if !isB64 {
			return false
		}
	}
	// The final data character carries two padding bits that must
	// be zero (the bridge rejects b64v(payload[10]) & 0x3), so a
	// syntactically valid string with set padding bits is not a
	// canonical encoding the gateway would have produced.
	return b64v(payload[10])&0x3 == 0
}

// b64v decodes one base64 character to its six-bit value.
func b64v(c byte) byte {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A'
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26
	case c >= '0' && c <= '9':
		return c - '0' + 52
	case c == '+':
		return 62
	default: // '/'
		return 63
	}
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
// netdevForGidLookup resolves the netdev backing an RDMA port/GID;
// tests replace it to exercise the fallback paths deterministically.
var netdevForGidLookup = netdevForGid

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
