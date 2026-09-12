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

//go:build linux && amd64 && cgo

package rcroutes

import (
	"errors"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

func TestParseSemanticOp(t *testing.T) {
	const defLimit = 10000
	cases := []struct {
		name    string
		op      uint8
		query   string
		limit   int
		want    semanticOp
		part    *partTransfer
		wantErr bool
	}{
		{"plain get", 0, "", defLimit, opPlainGet, nil, false},
		{"plain put", 1, "", defLimit, opPlainPut, nil, false},
		{"upload part", 1, "uploadId=abc&partNumber=3", defLimit,
			opUploadPart, &partTransfer{UploadID: "abc", PartNumber: 3}, false},
		{"get part", 0, "partNumber=7", defLimit, opGetPart,
			&partTransfer{PartNumber: 7}, false},
		{"part at limit", 0, "partNumber=10000", defLimit, opGetPart,
			&partTransfer{PartNumber: 10000}, false},
		{"non-default limit pass", 0, "partNumber=5", 7, opGetPart,
			&partTransfer{PartNumber: 5}, false},
		{"non-default limit fail", 0, "partNumber=8", 7, 0, nil, true},
		{"get with uploadId", 0, "uploadId=abc", defLimit, 0, nil, true},
		{"put partNumber only", 1, "partNumber=3", defLimit, 0, nil, true},
		{"put uploadId only", 1, "uploadId=abc", defLimit, 0, nil, true},
		{"unknown key", 0, "foo=1", defLimit, 0, nil, true},
		{"checksum key", 1, "uploadId=a&partNumber=1&checksumCRC32=x",
			defLimit, 0, nil, true},
		{"empty uploadId", 1, "uploadId=&partNumber=1", defLimit, 0, nil, true},
		{"non-numeric part", 0, "partNumber=1x", defLimit, 0, nil, true},
		{"zero part", 0, "partNumber=0", defLimit, 0, nil, true},
		{"negative part", 0, "partNumber=-2", defLimit, 0, nil, true},
		{"above limit", 0, "partNumber=10001", defLimit, 0, nil, true},
		{"duplicate key", 0, "partNumber=1&partNumber=2", defLimit, 0, nil, true},
		{"malformed encoding", 0, "partNumber=%zz", defLimit, 0, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, part, err := parseSemanticOp(tc.op, tc.query, tc.limit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted query %q", tc.query)
				}
				var bad errRouteBadRequest
				if !errors.As(err, &bad) {
					t.Fatalf("error not bad-request class: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected query %q: %v", tc.query, err)
			}
			if got != tc.want {
				t.Fatalf("op = %v, want %v", got, tc.want)
			}
			if tc.part == nil {
				if part != nil {
					t.Fatalf("part = %+v, want nil", part)
				}
				return
			}
			if part == nil {
				t.Fatalf("part = nil, want %+v", tc.part)
			}
			if *part != *tc.part {
				t.Fatalf("part = %+v, want %+v", part, tc.part)
			}
		})
	}
}

// captureSink records every sink emission the ops emitter makes.
type captureSink struct {
	actions []actionCall
	events  []s3event.EventMeta
	logs    []logCall
}

type actionCall struct {
	action string
	status int
	bytes  int64
}

type logCall struct {
	action string
	size   int64
}

type capMetrics struct {
	sink *captureSink
}

func (m *capMetrics) Send(ctx fiber.Ctx, err error, action string,
	count int64, status int) {
}
func (m *capMetrics) SendWithBucket(ctx fiber.Ctx, err error,
	action string, count int64, status int, bucket string) {
	m.sink.actions = append(m.sink.actions,
		actionCall{action: action, status: status, bytes: count})
}
func (m *capMetrics) Shutdown() error { return nil }
func (m *capMetrics) Close()          {}

var _ metrics.Manager = (*capMetrics)(nil)

type capEvents struct {
	sink *captureSink
}

func (e *capEvents) SendEvent(ctx fiber.Ctx, meta s3event.EventMeta) {
	e.sink.events = append(e.sink.events, meta)
}
func (e *capEvents) Shutdown() error { return nil }
func (e *capEvents) Close() error    { return nil }

var _ s3event.S3EventSender = (*capEvents)(nil)

type capLogger struct {
	sink *captureSink
}

func (l *capLogger) Log(ctx fiber.Ctx, err error, body []byte,
	meta s3log.LogMeta) {
	l.sink.logs = append(l.sink.logs,
		logCall{action: meta.Action, size: meta.ObjectSize})
}
func (l *capLogger) HangUp() error   { return nil }
func (l *capLogger) Shutdown() error { return nil }

var _ s3log.AuditLogger = (*capLogger)(nil)

// newCaptureEmitter builds an emitter wired to the capture sink.
func newCaptureEmitter(semantic semanticOp, query string, isPut bool) (
	*opsEmitter, *captureSink) {
	sink := &captureSink{}
	emit := &opsEmitter{
		app:      fiber.New(fiber.Config{Immutable: true}),
		isPut:    isPut,
		semantic: semantic,
		query:    query,
		ops: OpsServices{
			Logger:  &capLogger{sink: sink},
			Metrics: &capMetrics{sink: sink},
			Events:  &capEvents{sink: sink},
		},
	}
	return emit, sink
}

// A part upload must label records UploadPart and never emit the
// object-created event, even after the backend commit fact was
// recorded; a plain PUT keeps the PutObject label and the event.
func TestOpsEmitterPartUploadSuppression(t *testing.T) {
	part, sink := newCaptureEmitter(opUploadPart, "uploadId=a&partNumber=2", true)
	part.markCommitted("\"etag\"", "")
	part.publish(nil, 1024)

	if len(sink.actions) != 1 ||
		sink.actions[0].action != metrics.ActionUploadPart {
		t.Fatalf("actions = %+v, want one UploadPart", sink.actions)
	}
	if len(sink.logs) != 1 ||
		sink.logs[0].action != metrics.ActionUploadPart {
		t.Fatalf("logs = %+v, want one UploadPart", sink.logs)
	}
	if len(sink.events) != 0 {
		t.Fatalf("part upload emitted creation events: %+v", sink.events)
	}

	plain, sink2 := newCaptureEmitter(opPlainPut, "", true)
	plain.markCommitted("\"etag\"", "")
	plain.publish(nil, 512)

	if len(sink2.actions) != 1 ||
		sink2.actions[0].action != metrics.ActionPutObject {
		t.Fatalf("actions = %+v, want one PutObject", sink2.actions)
	}
	if len(sink2.events) != 1 {
		t.Fatalf("plain PUT lost its creation event: %+v", sink2.events)
	}
}

// Commit-fact retention: a plain PUT whose publication arrives as an
// error (native finalizer failed after the backend commit) still
// emits the creation event with the recorded ETag.
func TestOpsEmitterCommitFactRetentionUnderFailure(t *testing.T) {
	emit, sink := newCaptureEmitter(opPlainPut, "", true)
	emit.markCommitted("\"etag-x\"", "v1")
	emit.publish(errRouteBadRequest{}, 256)

	if len(sink.events) != 1 {
		t.Fatalf("committed PUT under failure lost its event: %+v",
			sink.events)
	}
	if sink.events[0].ObjectETag == nil || *sink.events[0].ObjectETag != "\"etag-x\"" {
		t.Fatalf("event ETag = %+v, want the recorded one",
			sink.events[0].ObjectETag)
	}
}

// A part read's synthesized path keeps the query so the audit
// record shows part semantics.
func TestOpsEmitterPartGetPathRetention(t *testing.T) {
	sink := &captureSink{}
	emit := &opsEmitter{
		app:      fiber.New(fiber.Config{Immutable: true}),
		bucket:   "bkt",
		key:      "obj",
		isPut:    false,
		semantic: opGetPart,
		query:    "partNumber=3",
		ops: OpsServices{
			Logger:  &capLogger{sink: sink},
			Metrics: &capMetrics{sink: sink},
			Events:  &capEvents{sink: sink},
		},
	}

	ctx, release := emit.synthesize()
	full := string(ctx.Request().URI().Path())
	query := string(ctx.Request().URI().QueryString())
	release()
	// fiber keeps the query inside the URI path when set through
	// Path(); both forms carry the part coordinates into the audit
	// record, which is what the logger splits.
	wantPath := "/bkt/obj"
	wantQuery := "partNumber=3"
	if full != wantPath && full != wantPath+"?"+wantQuery {
		t.Fatalf("path = %q, want %q (optionally with query)", full, wantPath)
	}
	if query != "" && query != wantQuery {
		t.Fatalf("query = %q, want %q or empty", query, wantQuery)
	}
	if full == wantPath && query != wantQuery {
		t.Fatalf("query = %q, want %q", query, wantQuery)
	}
}

// getPart label: a part read records as a GetObject-labeled read.
func TestOpsEmitterPartGetLabel(t *testing.T) {
	emit, sink := newCaptureEmitter(opGetPart, "partNumber=3", false)
	emit.publish(nil, 100)
	if len(sink.actions) != 1 ||
		sink.actions[0].action != metrics.ActionGetObject {
		t.Fatalf("actions = %+v, want one GetObject", sink.actions)
	}
	if len(sink.events) != 0 {
		t.Fatalf("part read emitted events: %+v", sink.events)
	}
}
