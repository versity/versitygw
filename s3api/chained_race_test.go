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

package s3api

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/azure"
	"github.com/versity/versitygw/backend/s3proxy"
	"github.com/versity/versitygw/s3api/middlewares"
)

// TestChainedGatewayRace chains a gateway to an S3 endpoint through the
// s3proxy backend, as in #2309, and sends HeadBucket requests on keep-alive
// connections, so fasthttp reuses each request context while net/http
// still finishes the previous round trip with it. Run with -race.
func TestChainedGatewayRace(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	be, err := s3proxy.New(context.Background(), "access", "secret", upstream.URL,
		"us-east-1", "", false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("s3proxy.New: %v", err)
	}

	client := serveGateway(t, be)
	sendConcurrently(t, "HeadBucket", func() error {
		_, err := client.HeadBucket(context.Background(),
			&s3.HeadBucketInput{Bucket: aws.String("bucket")})
		return err
	})
}

// TestChainedAzureGatewayRace is TestChainedGatewayRace with the azure
// backend in front of a fake Blob endpoint (#2641). GetObject streams the
// blob's body to the client after the handler returns, so net/http finishes
// the round trip later than for HeadBucket. Run with -race.
func TestChainedAzureGatewayRace(t *testing.T) {
	body := []byte("chained gateway race")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// a HEAD gets the headers without the body
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("ETag", `"0x8DCB1C2D3E4F5A6"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		_, _ = w.Write(body)
	}))
	t.Cleanup(upstream.Close)
	key := base64.StdEncoding.EncodeToString([]byte("key"))
	be, err := azure.New(context.Background(), "account", key, upstream.URL+"/account", "", 0, "", "")
	if err != nil {
		t.Fatalf("azure.New: %v", err)
	}

	client := serveGateway(t, be)
	sendConcurrently(t, "HeadBucket", func() error {
		_, err := client.HeadBucket(context.Background(),
			&s3.HeadBucketInput{Bucket: aws.String("bucket")})
		return err
	})
	sendConcurrently(t, "GetObject", func() error {
		out, err := client.GetObject(context.Background(),
			&s3.GetObjectInput{Bucket: aws.String("bucket"), Key: aws.String("key")})
		if err != nil {
			return err
		}
		defer out.Body.Close()
		got, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		if string(got) != string(body) {
			return fmt.Errorf("body = %q, want %q", got, body)
		}
		return nil
	})
}

// serveGateway serves be on a gateway and returns an S3 client for it.
func serveGateway(t *testing.T, be backend.Backend) *s3.Client {
	t.Helper()
	addrs := make(chan []net.Addr, 1)
	sa, err := New(
		be,
		middlewares.RootUserConfig{Access: "access", Secret: "secret"},
		"us-east-1",
		auth.NewIAMServiceSingle(auth.Account{Access: "access", Secret: "secret"}),
		nil, nil, nil, nil,
		WithConcurrencyLimiter(64, 64),
		WithOnListenAddrs(func(a []net.Addr) { addrs <- a }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
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

	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://" + gw.String()),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("access", "secret", ""),
	})
}

// sendConcurrently runs call from several workers, which reuse the
// client's keep-alive connections.
func sendConcurrently(t *testing.T, name string, call func() error) {
	t.Helper()
	const workers, perWorker = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for range workers {
		wg.Go(func() {
			for range perWorker {
				if err := call(); err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("%s: %v", name, err)
	}
}
