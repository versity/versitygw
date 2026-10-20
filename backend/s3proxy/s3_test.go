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

// captureHTTPClient records the request the aws sdk sends and answers 200
// with respHeader and respBody, so tests can assert on the wire format and
// on how responses are mapped without a real backend.
type captureHTTPClient struct {
	respHeader    http.Header
	respBody      string
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
		Header:     c.respHeader,
		Body:       io.NopCloser(strings.NewReader(c.respBody)),
		Request:    req,
	}, nil
}

func newCaptureProxy(t *testing.T) (*S3Proxy, *captureHTTPClient) {
	t.Helper()
	return newCaptureProxyWithRegion(t, "us-east-1")
}

func newCaptureProxyWithRegion(t *testing.T, region string) (*S3Proxy, *captureHTTPClient) {
	t.Helper()
	capture := &captureHTTPClient{respHeader: http.Header{}}
	client := s3.New(s3.Options{
		Region:       region,
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

// The bucket is created in the backend region, not the gateway region the
// api layer validated the client's constraint against. A regional endpoint
// outside us-east-1 rejects a CreateBucket that carries no constraint, so the
// backend has to add its own even when the api layer sent none.
func TestCreateBucketSetsBackendRegionConstraint(t *testing.T) {
	p, capture := newCaptureProxyWithRegion(t, "eu-west-1")

	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket:                    aws.String("test-bucket"),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if !strings.Contains(string(capture.body), "<LocationConstraint>eu-west-1</LocationConstraint>") {
		t.Errorf("CreateBucket against a regional backend must carry the backend region constraint, got %q", capture.body)
	}
}

func TestCreateBucketKeepsTagsAndSetsBackendRegionConstraint(t *testing.T) {
	p, capture := newCaptureProxyWithRegion(t, "eu-west-1")

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
	if !strings.Contains(body, "<LocationConstraint>eu-west-1</LocationConstraint>") {
		t.Errorf("CreateBucket against a regional backend must carry the backend region constraint, got %q", body)
	}
	if !strings.Contains(body, "<Key>env</Key>") || !strings.Contains(body, "<Value>test</Value>") {
		t.Errorf("CreateBucket must keep the requested tags, got %q", body)
	}
}

func TestGetObjectAttributesMapsResponse(t *testing.T) {
	p, capture := newCaptureProxy(t)
	capture.respHeader.Set("x-amz-version-id", "v1")
	capture.respHeader.Set("x-amz-delete-marker", "false")
	capture.respBody = `<?xml version="1.0" encoding="UTF-8"?>
<GetObjectAttributesResponse>
  <ETag>abc-3</ETag>
  <ObjectParts>
    <PartNumberMarker>1</PartNumberMarker>
    <NextPartNumberMarker>2</NextPartNumberMarker>
    <MaxParts>1</MaxParts>
    <IsTruncated>true</IsTruncated>
    <PartsCount>3</PartsCount>
  </ObjectParts>
  <ObjectSize>30</ObjectSize>
</GetObjectAttributesResponse>`

	out, err := p.GetObjectAttributes(context.Background(), &s3.GetObjectAttributesInput{
		Bucket:           aws.String("test-bucket"),
		Key:              aws.String("obj"),
		ObjectAttributes: []types.ObjectAttributes{types.ObjectAttributesObjectParts},
	})
	if err != nil {
		t.Fatalf("GetObjectAttributes: %v", err)
	}
	if got := aws.ToString(out.VersionId); got != "v1" {
		t.Errorf("expected version id v1, got %q", got)
	}
	if out.DeleteMarker == nil || *out.DeleteMarker {
		t.Errorf("expected delete marker false, got %v", out.DeleteMarker)
	}
	parts := out.ObjectParts
	if parts == nil {
		t.Fatal("expected object parts")
	}
	if got := aws.ToInt32(parts.PartsCount); got != 3 {
		t.Errorf("expected parts count 3, got %d", got)
	}
	if parts.PartNumberMarker != 1 || parts.NextPartNumberMarker != 2 ||
		parts.MaxParts != 1 || !parts.IsTruncated {
		t.Errorf("unexpected object parts %+v", *parts)
	}
}

func TestGetObjectAttributesNoObjectParts(t *testing.T) {
	p, capture := newCaptureProxy(t)
	capture.respBody = `<?xml version="1.0" encoding="UTF-8"?>
<GetObjectAttributesResponse>
  <ETag>abc</ETag>
  <ObjectSize>10</ObjectSize>
</GetObjectAttributesResponse>`

	out, err := p.GetObjectAttributes(context.Background(), &s3.GetObjectAttributesInput{
		Bucket:           aws.String("test-bucket"),
		Key:              aws.String("obj"),
		ObjectAttributes: []types.ObjectAttributes{types.ObjectAttributesObjectParts},
	})
	if err != nil {
		t.Fatalf("GetObjectAttributes: %v", err)
	}
	if out.ObjectParts != nil {
		t.Errorf("expected no object parts, got %+v", *out.ObjectParts)
	}
}
