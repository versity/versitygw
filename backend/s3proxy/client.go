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
	"crypto/tls"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
)

func (s *S3be) getClientFromCtx(ctx context.Context) (*s3.Client, error) {
	cfg, err := s.getConfig(ctx, s.access, s.secret)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg), nil
}

func (s *S3be) getConfig(ctx context.Context, access, secret string) (aws.Config, error) {
	creds := credentials.NewStaticCredentialsProvider(access, secret, "")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.sslSkipVerify},
	}
	client := &http.Client{Transport: tr}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(s.awsRegion),
		config.WithCredentialsProvider(creds),
		config.WithHTTPClient(client),
	}

	if s.endpoint != "" {
		opts = append(opts,
			config.WithEndpointResolverWithOptions(s))
	}

	if s.disableChecksum {
		opts = append(opts,
			config.WithAPIOptions([]func(*middleware.Stack) error{v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware}))
	}

	if s.debug {
		opts = append(opts,
			config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogResponse|aws.LogRequestEventMessage|aws.LogResponseEventMessage))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

// ResolveEndpoint is used for on prem or non-aws endpoints
func (s *S3be) ResolveEndpoint(service, region string, options ...interface{}) (aws.Endpoint, error) {
	return aws.Endpoint{
		PartitionID:       "aws",
		URL:               s.endpoint,
		SigningRegion:     s.awsRegion,
		HostnameImmutable: true,
	}, nil
}
