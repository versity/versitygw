// Copyright 2023 Versity Software
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
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// captureHTTPClient records the request the aws sdk sends and answers 200,
// so tests can assert on the wire format without a real backend.
type captureHTTPClient struct {
	body          []byte
	contentLength int64
}

func (c *captureHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.contentLength = req.ContentLength
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		c.body = b
	} else {
		c.body = nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func newCaptureProxy(t *testing.T) (*S3Proxy, *captureHTTPClient) {
	t.Helper()
	capture := &captureHTTPClient{}
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://backend.test"),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("access", "secret", ""),
		HTTPClient:   capture,
	})
	p, err := NewWithClient(context.Background(), client, "")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}
	return p, capture
}

// The api layer always populates CreateBucketConfiguration (it carries the
// bucket tags), so the backend must drop it when empty: strict backends such
// as Ceph RGW reject an empty <CreateBucketConfiguration/> element with
// 400 InvalidArgument, while a bodyless CreateBucket is accepted by all
// tested backends for this no-location case.
func TestCreateBucketOmitsEmptyConfiguration(t *testing.T) {
	p, capture := newCaptureProxy(t)

	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket:                    aws.String("test-bucket"),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if len(capture.body) != 0 {
		t.Errorf("CreateBucket without tags must send no body, got %q", capture.body)
	}
	if capture.contentLength != 0 {
		t.Errorf("CreateBucket without tags must send Content-Length 0, got %d", capture.contentLength)
	}
}

func TestCreateBucketKeepsTaggedConfiguration(t *testing.T) {
	p, capture := newCaptureProxy(t)

	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String("test-bucket"),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			Tags: []types.Tag{
				{Key: aws.String("env"), Value: aws.String("test")},
			},
		},
	}, []byte{})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	body := string(capture.body)
	if !strings.Contains(body, "<Key>env</Key>") || !strings.Contains(body, "<Value>test</Value>") {
		t.Errorf("CreateBucket with tags must forward the configuration, got %q", body)
	}
}

func TestCreateBucketKeepsLocationConstraint(t *testing.T) {
	p, capture := newCaptureProxy(t)

	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String("test-bucket"),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint("eu-west-1"),
		},
	}, []byte{})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if !strings.Contains(string(capture.body), "<LocationConstraint>eu-west-1</LocationConstraint>") {
		t.Errorf("CreateBucket with a location constraint must forward the configuration, got %q", capture.body)
	}
}

func TestCreateBucketKeepsLocationInfo(t *testing.T) {
	p, capture := newCaptureProxy(t)

	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String("test-bucket"),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			Location: &types.LocationInfo{
				Name: aws.String("usw2-az1"),
				Type: types.LocationTypeAvailabilityZone,
			},
		},
	}, []byte{})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if !strings.Contains(string(capture.body), "usw2-az1") {
		t.Errorf("CreateBucket with location info must forward the configuration, got %q", capture.body)
	}
}

func TestCreateBucketKeepsBucketInfo(t *testing.T) {
	p, capture := newCaptureProxy(t)

	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String("test-bucket"),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			Bucket: &types.BucketInfo{
				DataRedundancy: types.DataRedundancySingleAvailabilityZone,
				Type:           types.BucketTypeDirectory,
			},
		},
	}, []byte{})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if !strings.Contains(string(capture.body), "Directory") {
		t.Errorf("CreateBucket with bucket info must forward the configuration, got %q", capture.body)
	}
}
