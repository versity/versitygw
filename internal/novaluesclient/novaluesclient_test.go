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

package novaluesclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"
)

type ctxKey struct{}

func TestWithoutValues(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	parent, cancel := context.WithDeadline(context.WithValue(context.Background(), ctxKey{}, "v"), deadline)
	defer cancel()

	ctx := withoutValues(parent)
	if got := ctx.Value(ctxKey{}); got != nil {
		t.Fatalf("Value = %v, want nil", got)
	}
	if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
		t.Fatalf("Deadline = %v, %v, want %v, true", got, ok, deadline)
	}
	if ctx.Done() != parent.Done() {
		t.Fatal("Done is not the parent's channel")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("Err = %v before cancel", err)
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", ctx.Err())
	}
}

func TestWithoutValuesKeepsClientTrace(t *testing.T) {
	tr := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {}}
	parent := httptrace.WithClientTrace(context.WithValue(context.Background(), ctxKey{}, "v"), tr)

	ctx := withoutValues(parent)
	if got := httptrace.ContextClientTrace(ctx); got == nil || got.GotConn == nil {
		t.Fatalf("ContextClientTrace = %v, want the parent's trace", got)
	}
	if got := ctx.Value(ctxKey{}); got != nil {
		t.Fatalf("Value = %v, want nil", got)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type closeIdleDoer struct {
	Doer
	closed *bool
}

func (d closeIdleDoer) CloseIdleConnections() { *d.closed = true }

func TestWrapCloseIdleConnections(t *testing.T) {
	var closed bool
	Wrap(closeIdleDoer{closed: &closed}).(interface{ CloseIdleConnections() }).CloseIdleConnections()
	if !closed {
		t.Fatal("CloseIdleConnections did not reach the wrapped client")
	}
	// A wrapped client without it is left alone.
	Wrap(doerFunc(nil)).(interface{ CloseIdleConnections() }).CloseIdleConnections()
}
