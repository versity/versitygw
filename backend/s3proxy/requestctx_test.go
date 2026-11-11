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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type ctxKey struct{}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// NewWithClient also keeps the caller's HTTP client from seeing values of
// the backend call's context.
func TestNewWithClientHidesContextValues(t *testing.T) {
	var got any
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://127.0.0.1"),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("access", "secret", ""),
		HTTPClient: doerFunc(func(req *http.Request) (*http.Response, error) {
			got = req.Context().Value(ctxKey{})
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}, nil
		}),
	})
	s, err := NewWithClient(context.Background(), client, "")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, "v")
	if _, err := s.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("bucket")}); err != nil {
		t.Fatalf("HeadBucket: %v", err)
	}
	if got != nil {
		t.Fatalf("HTTP client saw Value = %v, want nil", got)
	}
}

// The upstream request still ends with the context it was made with.
func TestRequestContextCancelReachesUpstream(t *testing.T) {
	inflight := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(inflight)
		<-r.Context().Done()
	}))
	t.Cleanup(upstream.Close)
	s, err := New(context.Background(), "access", "secret", upstream.URL,
		"us-east-1", "", false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := s.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("bucket")})
		errc <- err
	}()
	<-inflight
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HeadBucket error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("HeadBucket did not return after its context was canceled")
	}
}
