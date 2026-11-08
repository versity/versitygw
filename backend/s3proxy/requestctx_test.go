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

package s3proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
)

// requestCtx stands in for the *fasthttp.RequestCtx the gateway hands a
// backend: Done is never nil (fasthttp returns the server's shutdown
// channel), and Value reads storage that fasthttp resets and reuses for the
// next request once the handler returns. Lookups made on other goroutines
// are slowed down, so one that overlaps the return of the backend call is
// still running when released is set, and is counted.
type requestCtx struct {
	context.Context
	done     chan struct{}
	owner    uint64
	released atomic.Bool
	late     atomic.Int32
}

func newRequestCtx() *requestCtx {
	return &requestCtx{
		Context: context.Background(),
		done:    make(chan struct{}),
		owner:   goroutineID(),
	}
}

func (c *requestCtx) Done() <-chan struct{} { return c.done }

func (c *requestCtx) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func (c *requestCtx) Value(key any) any {
	if goroutineID() != c.owner {
		time.Sleep(5 * time.Millisecond)
	}
	if c.released.Load() {
		c.late.Add(1)
	}
	if key == "account" {
		return auth.Account{Access: "access"}
	}
	return nil
}

// goroutineID parses the current goroutine's id from its stack header,
// "goroutine N [running]:".
func goroutineID() uint64 {
	var buf [64]byte
	f := strings.Fields(string(buf[:runtime.Stack(buf[:], false)]))
	id, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		panic(err)
	}
	return id
}

func newUpstreamProxy(t *testing.T, h http.HandlerFunc) *S3Proxy {
	t.Helper()
	upstream := httptest.NewServer(h)
	t.Cleanup(upstream.Close)
	s, err := New(context.Background(), "access", "secret", upstream.URL,
		"us-east-1", "", false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// net/http reads the request's context on connection goroutines, and
// unregisters it from its parent there after the response body is done,
// looking the parent up with Value. None of that may reach the request
// context the backend was handed once the backend call has returned.
func TestRequestContextNotReadAfterReturn(t *testing.T) {
	s := newUpstreamProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	baseline := runtime.NumGoroutine()
	const calls = 20
	ctxs := make([]*requestCtx, 0, calls)
	for range calls {
		ctx := newRequestCtx()
		if _, err := s.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("bucket")}); err != nil {
			t.Fatalf("HeadBucket: %v", err)
		}
		ctx.released.Store(true)
		ctxs = append(ctxs, ctx)
	}
	// Close the connections and wait for their goroutines, client and
	// server side, to exit, so every lookup they make has been counted.
	s.client.Options().HTTPClient.(*http.Client).CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines left, want %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}

	var late int32
	for _, ctx := range ctxs {
		late += ctx.late.Load()
	}
	if late != 0 {
		t.Fatalf("request context read %d times after HeadBucket returned", late)
	}
}

// The upstream request still ends with the context it was made with.
func TestRequestContextCancelReachesUpstream(t *testing.T) {
	inflight := make(chan struct{})
	s := newUpstreamProxy(t, func(w http.ResponseWriter, r *http.Request) {
		close(inflight)
		<-r.Context().Done()
	})

	ctx := newRequestCtx()
	errc := make(chan error, 1)
	go func() {
		_, err := s.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("bucket")})
		errc <- err
	}()
	<-inflight
	close(ctx.done)

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HeadBucket error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("HeadBucket did not return after its context was canceled")
	}
}

type ctxKey struct{}

// http.Client.CloseIdleConnections still reaches the transport.
func TestRequestContextTransportCloseIdle(t *testing.T) {
	var closed bool
	rt := requestContextTransport{closeIdleTransport{closed: &closed}}
	(&http.Client{Transport: rt}).CloseIdleConnections()
	if !closed {
		t.Fatal("CloseIdleConnections did not reach the wrapped transport")
	}
	// A wrapped RoundTripper without it is left alone.
	requestContextTransport{http.NewFileTransport(http.Dir("."))}.CloseIdleConnections()
}

type closeIdleTransport struct {
	http.RoundTripper
	closed *bool
}

func (t closeIdleTransport) CloseIdleConnections() { *t.closed = true }

func TestRoundTripContext(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	parent, cancel := context.WithDeadline(context.WithValue(context.Background(), ctxKey{}, "v"), deadline)
	defer cancel()

	ctx := &roundTripContext{Context: parent, values: context.WithoutCancel(parent)}
	if got := ctx.Value(ctxKey{}); got != "v" {
		t.Fatalf("Value = %v, want v", got)
	}
	if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
		t.Fatalf("Deadline = %v, %v, want %v, true", got, ok, deadline)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("Err = %v before cancel", err)
	}

	// A context derived from it, as net/http derives one per request, is
	// canceled with the parent, also after end.
	child, stop := context.WithCancel(ctx)
	defer stop()
	ctx.end()
	if got := ctx.Value(ctxKey{}); got != nil {
		t.Fatalf("Value after end = %v, want nil", got)
	}
	cancel()
	select {
	case <-child.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("derived context not canceled with the parent")
	}
	if !errors.Is(child.Err(), context.Canceled) {
		t.Fatalf("derived Err = %v, want context.Canceled", child.Err())
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", ctx.Err())
	}
}

// blockingCtx blocks a Value lookup until release is closed.
type blockingCtx struct {
	context.Context
	entered chan struct{}
	release chan struct{}
}

func (c *blockingCtx) Value(key any) any {
	close(c.entered)
	<-c.release
	return "v"
}

// end returns only after a lookup in progress has finished.
func TestRoundTripContextEndWaitsForLookup(t *testing.T) {
	parent := &blockingCtx{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	ctx := &roundTripContext{Context: parent, values: context.WithoutCancel(parent)}

	got := make(chan any, 1)
	go func() { got <- ctx.Value(ctxKey{}) }()
	<-parent.entered

	ended := make(chan struct{})
	go func() {
		ctx.end()
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("end returned while a lookup was in progress")
	case <-time.After(50 * time.Millisecond):
	}
	close(parent.release)
	<-ended
	if v := <-got; v != "v" {
		t.Fatalf("Value = %v, want v", v)
	}
}

// TestChainedGatewayRace chains a gateway to an S3 endpoint through this
// backend, as in #2309, and sends HeadBucket requests on keep-alive
// connections, so fasthttp reuses each request context while net/http
// still finishes the previous round trip with it. Run with -race.
func TestChainedGatewayRace(t *testing.T) {
	be := newUpstreamProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addrs := make(chan []net.Addr, 1)
	sa, err := s3api.New(
		be,
		middlewares.RootUserConfig{Access: "access", Secret: "secret"},
		"us-east-1",
		auth.NewIAMServiceSingle(auth.Account{Access: "access", Secret: "secret"}),
		nil, nil, nil, nil,
		s3api.WithConcurrencyLimiter(64, 64),
		s3api.WithOnListenAddrs(func(a []net.Addr) { addrs <- a }),
	)
	if err != nil {
		t.Fatalf("s3api.New: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- sa.ServeMultiPort([]string{"127.0.0.1:0"}) }()
	var gw net.Addr
	select {
	case a := <-addrs:
		gw = a[0]
	case err := <-served:
		t.Fatalf("ServeMultiPort: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not start")
	}
	t.Cleanup(func() {
		_ = sa.ShutDown()
		<-served
	})

	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://" + gw.String()),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("access", "secret", ""),
	})

	const workers, perWorker = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for range workers {
		wg.Go(func() {
			for range perWorker {
				_, err := client.HeadBucket(context.Background(),
					&s3.HeadBucketInput{Bucket: aws.String("bucket")})
				if err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("HeadBucket: %v", err)
	}
}
