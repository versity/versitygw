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

//go:build !(linux && amd64 && cgo)

// Package rcserver binds the RC session server implementing the
// hipobj-rc-v2 two-phase transfer protocol. This file is a stub for
// platforms without RDMA support.
package rcserver

import "errors"

var errNotSupported = errors.New("rcserver: not supported on this platform")

// DeviceOpts configures device selection and resource limits.
type DeviceOpts struct {
	GidHint             string
	Port                uint8
	GidIdx              int
	MaxSessions         uint32
	MaxStagingBytes     uint64
	MaxQPs              uint32
	MaxUserSessions     uint32
	MaxUserStagingBytes uint64
	MaxUserQPs          uint32
	TPrepMs             uint64
	TExecMs             uint64
	MaxReadySlots       uint32
	MaxStageSlots       uint32
}

// PrincipalID is the SHA-256 digest identifying the requester.
type PrincipalID [32]byte

// PrepareRequest carries the PREPARE wire parameters.
type PrepareRequest struct {
	Principal   PrincipalID
	Op          uint8
	Target      string
	Offset      uint64
	Size        uint64
	ClientPsn   uint32
	Cookie      uint32
	ClientToken string
}

// PrepareResponse is the PREPARE reply.
type PrepareResponse struct {
	SessionID   string
	ServerQpn   uint32
	ServerPsn   uint32
	StagingAddr uint64
	StagingRkey uint32
	ReplyToken  string
}

// Handle is an opaque consume-once lease identifier.
type Handle struct {
	Epoch uint64
	Nonce uint64
}

// StagingLease is a borrowed GET staging buffer.
type StagingLease struct {
	Buf      []byte
	Capacity int
	Handle   Handle
}

// PutView is a borrowed PUT data view.
type PutView struct {
	Buf    []byte
	Len    int
	Handle Handle
}

// ReadyRequest carries the READY wire parameters.
type ReadyRequest struct {
	Principal    PrincipalID
	SessionID    string
	Cookie       uint32
	ClientQpn    uint32
	ClientMrAddr uint64
	ClientMrRkey uint32
}

// ReadyResponse is the READY reply.
type ReadyResponse struct {
	BytesTransferred uint64
	CookieEcho       uint32
	// Outcome mirrors the RC_READY_* enum.
	Outcome   int
	Etag      string
	VersionID string
}

// SessionInfo describes a session for READY re-authorization.
type SessionInfo struct {
	Op     uint8
	Target string
}

// RCSvc owns the RC session server (stub).
type RCSvc struct{}

// Init is a stub that always fails.
func Init(opts DeviceOpts) (*RCSvc, error) { return nil, errNotSupported }

// TryEnter is a stub.
func (s *RCSvc) TryEnter() bool { return false }

// Leave is a stub.
func (s *RCSvc) Leave() {}

// Close is a stub.
func (s *RCSvc) Close() {}

// Prepare is a stub.
func (s *RCSvc) Prepare(req PrepareRequest) (*PrepareResponse, error) {
	return nil, errNotSupported
}

// FinishPrepare is a stub.
func (s *RCSvc) FinishPrepare(sessionID string, committed bool) error {
	return errNotSupported
}

// BorrowStaging is a stub.
func (s *RCSvc) BorrowStaging(sessionID string) (*StagingLease, error) {
	return nil, errNotSupported
}

// FinishStaging is a stub.
func (s *RCSvc) FinishStaging(lease StagingLease, ok bool,
	written int, etag, versionID string) error {
	return errNotSupported
}

// SessionInfo is a stub.
func (s *RCSvc) SessionInfo(sessionID string, who PrincipalID) (*SessionInfo, error) {
	return nil, errNotSupported
}

// ReadyTransfer is a stub.
func (s *RCSvc) ReadyTransfer(req ReadyRequest) (*ReadyResponse, error) {
	return nil, errNotSupported
}

// GetPutData is a stub.
func (s *RCSvc) GetPutData(sessionID string) (*PutView, error) {
	return nil, errNotSupported
}

// FinishPut is a stub.
func (s *RCSvc) FinishPut(view PutView, committed bool,
	etag, versionID string) error {
	return errNotSupported
}

// FinishFinal is a stub.
func (s *RCSvc) FinishFinal(sessionID string) error {
	return errNotSupported
}

// Cancel is a stub.
func (s *RCSvc) Cancel(sessionID string, who PrincipalID) error {
	return errNotSupported
}

// Ready outcome detail codes (see the linux build).
const (
	ReadyOK         = 0
	ReadyBusy       = 1
	ReadyTimeout    = 2
	ReadyVerifyFail = 3
	ReadyWireFail   = 4
)
