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

// Package novaluesclient wraps the HTTP client of a backend SDK so that
// net/http never reads values from the context of a backend call.
//
// The gateway hands backends the *fasthttp.RequestCtx of the request, and
// fasthttp resets and reuses it for the next request once the handler
// returns, so its Value must not be called after that (#2309). net/http
// reads the request's context on connection goroutines that can outlive the
// call: the read loop unregisters the request's context from its parent
// after the response body is done, which looks the parent up with Value,
// and a dial it started keeps going after another connection served the
// request.
//
// The wrapper relies on the following:
//
//   - Done and Err of the parent still reach the RequestCtx after the call
//     returns. That is safe only because fasthttp never resets ctx.s and
//     s.done is atomic (fasthttp v1.77 server.go); re-check this when
//     bumping fasthttp.
//   - The context net/http derives for a request cannot find a cancelable
//     ancestor through Value, so it does not register with one and
//     context.Cause of the parent is not propagated to it. Neither changes
//     anything today: the root is the RequestCtx, which is not a cancelCtx,
//     so net/http already forwarded cancellation with a goroutine.
//   - Request-context values are not needed inside net/http. The one
//     exception, an httptrace.ClientTrace, is carried over. If SDK metrics
//     are ever enabled, smithy-go's trace hooks capture the request context
//     and fire from transport goroutines, so that case would race again.
package novaluesclient

import (
	"context"
	"net/http"
	"net/http/httptrace"
)

// Doer is the Do method shared by *http.Client, the AWS SDK's
// s3.HTTPClient and the Azure SDK's policy.Transporter.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Wrap returns a Doer that sends requests with d under a context that has
// the deadline and cancellation of the request's context, but no values.
func Wrap(d Doer) Doer {
	return client{d}
}

type client struct {
	Doer
}

func (c client) Do(req *http.Request) (*http.Response, error) {
	return c.Doer.Do(req.WithContext(withoutValues(req.Context())))
}

// CloseIdleConnections forwards to the wrapped client, if it has it.
func (c client) CloseIdleConnections() {
	if ci, ok := c.Doer.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
}

func withoutValues(parent context.Context) context.Context {
	var ctx context.Context = noValuesContext{parent}
	if tr := httptrace.ContextClientTrace(parent); tr != nil {
		ctx = httptrace.WithClientTrace(ctx, tr)
	}
	return ctx
}

// noValuesContext has the deadline and cancellation of its parent and no
// values.
type noValuesContext struct {
	context.Context
}

func (noValuesContext) Value(any) any { return nil }
