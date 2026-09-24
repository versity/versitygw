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
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/versity/versitygw/rdma/rcserver"
)

// Semantic operation parsed from the transfer target's query. The
// transport op (GET/PUT header) plus the query decide the backend
// operation; the semantic op is stored with the session so the
// READY phase re-authorizes with the same identity the PREPARE
// phase checked.
type semanticOp int

const (
	// opPlainGet is a plain object read (no query).
	opPlainGet semanticOp = iota
	// opPlainPut is a plain object write (no query).
	opPlainPut
	// opUploadPart is a multipart part upload (uploadId+partNumber).
	opUploadPart
	// opGetPart is a multipart part read (partNumber only).
	opGetPart
)

// String renders the semantic operation for operational records.
func (s semanticOp) String() string {
	switch s {
	case opPlainGet:
		return "GET"
	case opPlainPut:
		return "PUT"
	case opUploadPart:
		return "UploadPart"
	case opGetPart:
		return "GetPart"
	}
	return "Unknown"
}

// isPut reports whether the semantic operation writes data.
func (s semanticOp) isPut() bool {
	return s == opPlainPut || s == opUploadPart
}

// partTransfer describes the part coordinates of a part transfer.
type partTransfer struct {
	// UploadID is set for opUploadPart only.
	UploadID string
	// PartNumber is 1-based; validated against the effective limit.
	PartNumber int
}

// parseSemanticOp derives the semantic operation from the transport
// op (wire GET/PUT) and the raw target query, validating the
// query's shape per the operation matrix. The limit caps accepted
// part numbers (the same configured value the S3 surface enforces).
//
// op follows the wire encoding: 0 = GET, 1 = PUT.
func parseSemanticOp(op uint8, query string, limit int) (semanticOp, *partTransfer, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf(format+": %w", append(args, errRouteBadRequest{})...)
	}
	if query == "" {
		if op == 1 {
			return opPlainPut, nil, nil
		}
		return opPlainGet, nil, nil
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return 0, nil, bad("invalid target query %q", query)
	}
	if op == 1 {
		// PUT: uploadId + partNumber, both required, nothing else.
		// Query keys are case-sensitive, matching the S3 surface.
		if len(vals) != 2 {
			return 0, nil, bad("unsupported target query %q", query)
		}
		uploadID, hasUpload := vals["uploadId"]
		part, hasPart := vals["partNumber"]
		if !hasUpload || !hasPart || len(vals) != 2 {
			return 0, nil, bad("unsupported target query %q", query)
		}
		if len(uploadID) != 1 || uploadID[0] == "" {
			return 0, nil, bad("invalid uploadId in %q", query)
		}
		if len(part) != 1 {
			return 0, nil, bad("invalid partNumber in %q", query)
		}
		n, err := strconv.Atoi(part[0])
		if err != nil || n < 1 || n > limit {
			return 0, nil, bad("invalid partNumber %q", part[0])
		}
		return opUploadPart, &partTransfer{UploadID: uploadID[0], PartNumber: n}, nil
	}
	// GET: partNumber only; uploadId is ListParts semantics and is
	// rejected here.
	if len(vals) != 1 {
		return 0, nil, bad("unsupported target query %q", query)
	}
	part, hasPart := vals["partNumber"]
	if !hasPart || len(part) != 1 {
		return 0, nil, bad("unsupported target query %q", query)
	}
	n, err := strconv.Atoi(part[0])
	if err != nil || n < 1 || n > limit {
		return 0, nil, bad("invalid partNumber %q", part[0])
	}
	return opGetPart, &partTransfer{PartNumber: n}, nil
}

// rcService is the injectable service seam the handler tests use:
// the subset of RCSvc the routes call. Production wires the real
// *rcserver.RCSvc; tests provide a fixture.
type rcService interface {
	TryEnter() bool
	Leave()
	Context() context.Context
	Prepare(rcserver.PrepareRequest) (*rcserver.PrepareResponse, error)
	FinishPrepare(sessionID string, committed bool) error
	BorrowStaging(sessionID string) (*rcserver.StagingLease, error)
	FinishStaging(lease rcserver.StagingLease, ok bool,
		written int, etag, version string) error
	SessionInfo(sessionID string, who rcserver.PrincipalID) (*rcserver.SessionInfo, error)
	ReadyTransfer(rcserver.ReadyRequest) (*rcserver.ReadyResponse, error)
	GetPutData(sessionID string) (*rcserver.PutView, error)
	FinishPut(view rcserver.PutView, committed bool,
		etag, version string) error
	FinishFinal(sessionID string) error
	Cancel(sessionID string, who rcserver.PrincipalID) error
	SetTerminalNotify(fn func(rcserver.TerminalEvent))
	SessionsSnapshot() ([]rcserver.SessionSnapshot, error)
}
