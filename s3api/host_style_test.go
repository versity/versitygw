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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// hostStyleBackend serves any existing bucket, answering GetObject with the
// bucket and key it was asked for, so a test sees which object was served.
type hostStyleBackend struct {
	backend.BackendUnsupported
}

func (hostStyleBackend) GetBucketAcl(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
	return []byte("{}"), nil
}

func (hostStyleBackend) GetObject(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	body := *input.Bucket + "/" + *input.Key
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: aws.Int64(int64(len(body))),
	}, nil
}

// uploadBackend serves uploads to any bucket without object lock, reading
// the whole body, so one consumed before the handler fails the payload hash
// check.
type uploadBackend struct {
	hostStyleBackend
}

func (uploadBackend) GetObjectLockConfiguration(context.Context, string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
}

func (uploadBackend) ValidateUploadID(string) error { return nil }

func (uploadBackend) PutObject(_ context.Context, input s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	_, err := io.Copy(io.Discard, input.Body)
	return s3response.PutObjectOutput{}, err
}

func (uploadBackend) UploadPart(_ context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	_, err := io.Copy(io.Discard, input.Body)
	return &s3.UploadPartOutput{}, err
}

// The debug logger must leave a virtual-hosted-style upload's body to the
// handler, as it does a path-style one's.
func TestHostStyleUploadWithDebugLogger(t *testing.T) {
	const (
		domain = "s3.example.test"
		region = "us-east-1"
		body   = "hello\n"
	)
	debuglogger.SetLevel(debuglogger.LevelDebug)
	defer debuglogger.SetLevel(debuglogger.LevelSilent)

	root := testAdminRoot
	srv, err := New(uploadBackend{}, root, region,
		auth.NewIAMServiceSingle(auth.Account{Access: root.Access, Secret: root.Secret}),
		nil, nil, nil, nil,
		WithConcurrencyLimiter(10, 10),
		WithQuiet(),
		WithHostStyle(domain),
	)
	if err != nil {
		t.Fatalf("new s3 server: %v", err)
	}

	sum := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(sum[:])
	creds := aws.Credentials{AccessKeyID: root.Access, SecretAccessKey: root.Secret}

	for _, target := range []string{
		"http://" + domain + "/bucketa/key",
		"http://bucketa." + domain + "/key",
		"http://bucketa." + domain + "/key?partNumber=1&uploadId=id",
	} {
		t.Run(target, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPut, target, strings.NewReader(body))
			req.Header.Set("X-Amz-Content-Sha256", payloadHash)
			if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, payloadHash, "s3", region, time.Now()); err != nil {
				t.Fatalf("sign request: %v", err)
			}
			resp, err := srv.app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, got)
			}
		})
	}
}

// A virtual-hosted-style gateway must route a request to the bucket of the
// very host it verifies the signature with, the way S3 does, so a signed
// request can't be pointed at another bucket than the one signed for: not by
// an absolute-form request-target ("GET http://host/path HTTP/1.1") naming
// another host than the Host header, nor by an origin-form one that fasthttp
// would take a host out of ("//host/path#://").
func TestHostStyleRoutesSignedHost(t *testing.T) {
	const (
		domain = "s3.example.test:7070"
		region = "us-east-1"
	)
	root := testAdminRoot

	srv, err := New(hostStyleBackend{}, root, region,
		auth.NewIAMServiceSingle(auth.Account{Access: root.Access, Secret: root.Secret}),
		nil, nil, nil, nil,
		WithConcurrencyLimiter(10, 10),
		WithQuiet(),
		WithHostStyle("s3.example.test"),
	)
	if err != nil {
		t.Fatalf("new s3 server: %v", err)
	}
	handler := srv.app.Handler()

	creds := aws.Credentials{AccessKeyID: root.Access, SecretAccessKey: root.Secret}

	// presign GetObject bucketa/key, path-style and virtual-hosted-style
	presign := func(pathStyle bool) string {
		t.Helper()
		client := s3.New(s3.Options{
			Region:       region,
			BaseEndpoint: aws.String("http://" + domain),
			UsePathStyle: pathStyle,
			Credentials:  credentials.StaticCredentialsProvider{Value: creds},
		})
		req, err := s3.NewPresignClient(client).PresignGetObject(context.Background(),
			&s3.GetObjectInput{Bucket: aws.String("bucketa"), Key: aws.String("key")})
		if err != nil {
			t.Fatalf("presign: %v", err)
		}
		u, err := url.Parse(req.URL)
		if err != nil {
			t.Fatalf("parse presigned url: %v", err)
		}
		return u.RawQuery
	}
	pathQuery := presign(true)
	vhostQuery := presign(false)

	// header-sign GetObject bucketa/key, path-style
	emptySum := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(emptySum[:])
	signed, _ := http.NewRequest(http.MethodGet, "http://"+domain+"/bucketa/key", nil)
	signed.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, signed, payloadHash, "s3", region, time.Now()); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	signedHeaders := "Authorization: " + signed.Header.Get("Authorization") + "\r\n" +
		"X-Amz-Date: " + signed.Header.Get("X-Amz-Date") + "\r\n" +
		"X-Amz-Content-Sha256: " + payloadHash + "\r\n"

	tests := []struct {
		name       string
		target     string
		host       string
		headers    string
		wantStatus int
		// the object served, or the error code returned
		want string
	}{
		{
			name:       "path-style presigned",
			target:     "/bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "path-style presigned, absolute-form",
			target:     "http://" + domain + "/bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "path-style presigned, absolute-form naming another bucket's host",
			target:     "http://bucketb." + domain + "/bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusForbidden,
			want:       "SignatureDoesNotMatch",
		},
		{
			name:       "path-style presigned, absolute-form naming another host",
			target:     "http://other.example.test/bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusForbidden,
			want:       "SignatureDoesNotMatch",
		},
		{
			name:       "path-style presigned, absolute-form with another bucket's host after a userinfo",
			target:     "http://" + domain + "@bucketb." + domain + "/bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusBadRequest,
			want:       "InvalidBucketName",
		},
		{
			name:       "path-style presigned, absolute-form with an empty host",
			target:     "http:///bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "path-style presigned, absolute-form of a non-http scheme",
			target:     "ftp://" + domain + "/bucketa/key?" + pathQuery,
			host:       domain,
			wantStatus: http.StatusBadRequest,
			want:       "InvalidURI",
		},
		{
			// fasthttp takes bucketb's host out of this target, but the
			// request goes to the Host header's, with the path left after it
			name:       "path-style presigned, origin-form starting with another bucket's host",
			target:     "//bucketb." + domain + "/bucketa/key?" + pathQuery + "#://",
			host:       domain,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "virtual-hosted-style presigned",
			target:     "/key?" + vhostQuery,
			host:       "bucketa." + domain,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "virtual-hosted-style presigned, absolute-form",
			target:     "http://bucketa." + domain + "/key?" + vhostQuery,
			host:       "bucketa." + domain,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "virtual-hosted-style presigned, absolute-form naming another bucket's host",
			target:     "http://bucketb." + domain + "/key?" + vhostQuery,
			host:       "bucketa." + domain,
			wantStatus: http.StatusForbidden,
			want:       "SignatureDoesNotMatch",
		},
		{
			name:       "header-signed",
			target:     "/bucketa/key",
			host:       domain,
			headers:    signedHeaders,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
		{
			name:       "header-signed, absolute-form naming another bucket's host",
			target:     "http://bucketb." + domain + "/bucketa/key",
			host:       domain,
			headers:    signedHeaders,
			wantStatus: http.StatusForbidden,
			want:       "SignatureDoesNotMatch",
		},
		{
			name:       "header-signed, origin-form starting with another bucket's host",
			target:     "//bucketb." + domain + "/bucketa/key#://",
			host:       domain,
			headers:    signedHeaders,
			wantStatus: http.StatusOK,
			want:       "bucketa/key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "GET " + tt.target + " HTTP/1.1\r\nHost: " + tt.host + "\r\n" + tt.headers + "\r\n"
			var fctx fasthttp.RequestCtx
			if err := fctx.Request.Read(bufio.NewReader(strings.NewReader(raw))); err != nil {
				t.Fatalf("read request: %v", err)
			}
			handler(&fctx)

			body := string(fctx.Response.Body())
			if status := fctx.Response.StatusCode(); status != tt.wantStatus {
				t.Fatalf("status %d, want %d: %s", status, tt.wantStatus, body)
			}
			if tt.wantStatus == http.StatusOK {
				if body != tt.want {
					t.Fatalf("served %q, want %q", body, tt.want)
				}
				return
			}
			if !strings.Contains(body, "<Code>"+tt.want+"</Code>") {
				t.Fatalf("response %s, want error code %s", body, tt.want)
			}
		})
	}
}
