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
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func (s *S3Proxy) getClientWithCtx(ctx context.Context) (*s3.Client, error) {
	cfg, err := s.getConfig(ctx, s.access, s.secret)
	if err != nil {
		return nil, err
	}

	if s.endpoint != "" {
		return s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = &s.endpoint
			o.UsePathStyle = s.usePathStyle
			// The http body stream is not seekable, so most operations cannot
			// be retried. The error returned to the original client may be
			// retried by the client.
			o.Retryer = aws.NopRetryer{}
		}), nil
	}

	return s3.NewFromConfig(cfg), nil
}

func (s *S3Proxy) getConfig(ctx context.Context, access, secret string) (aws.Config, error) {
	if (access != "" && secret == "") || (access == "" && secret != "") {
		return aws.Config{}, fmt.Errorf("both access and secret must be set or none at all")
	}
	if s.anonymousCredentials && access != "" {
		return aws.Config{}, fmt.Errorf("anonymous credentials cannot be used with access and secret")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.sslSkipVerify},
	}
	client := &http.Client{Transport: tr}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(s.awsRegion),
		config.WithHTTPClient(client),
	}

	if access != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(access, secret, "")))
	} else if s.anonymousCredentials {
		opts = append(opts, config.WithCredentialsProvider(aws.AnonymousCredentials{}))
	}

	if s.disableChecksum {
		opts = append(opts,
			config.WithAPIOptions([]func(*middleware.Stack) error{v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware}))
	}

	if s.disableDataIntegrityCheck {
		opts = append(opts,
			config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired))
	}

	if s.gcsCompatibility {
		opts = append(opts, config.WithAPIOptions([]func(*middleware.Stack) error{
			func(stack *middleware.Stack) error {
				if err := stack.Finalize.Insert(gcsIgnoreHeadersMiddleware(), "Signing", middleware.Before); err != nil {
					return err
				}
				return stack.Finalize.Insert(gcsRestoreHeadersMiddleware(), "Signing", middleware.After)
			},
		}))
	}

	if s.debug {
		opts = append(opts,
			config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogResponse|aws.LogRequestEventMessage|aws.LogResponseEventMessage))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

// gcsIgnoredHeadersKey is the context key for headers temporarily removed
// before signing to work around GCS SigV4 compatibility issue.
// See: https://github.com/aws/aws-sdk-go-v2/issues/1816
type gcsIgnoredHeadersKey struct{}

// gcsIgnoreHeadersMiddleware removes Accept-Encoding from the request before
// the Signing step so it is not included in signed headers. GCS rejects
// requests where Accept-Encoding is part of the signature because it rewrites
// that header internally.
func gcsIgnoreHeadersMiddleware() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc("GCSIgnoreHeaders",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
			out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
		) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{
					Err: fmt.Errorf("(GCSIgnoreHeaders) unexpected request type %T", in.Request),
				}
			}

			const hdr = "Accept-Encoding"
			saved := req.Header.Get(hdr)
			req.Header.Del(hdr)
			ctx = middleware.WithStackValue(ctx, gcsIgnoredHeadersKey{}, saved)

			return next.HandleFinalize(ctx, in)
		},
	)
}

// gcsRestoreHeadersMiddleware restores the Accept-Encoding header that was
// removed by gcsIgnoreHeadersMiddleware so it is still sent on the wire.
func gcsRestoreHeadersMiddleware() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc("GCSRestoreHeaders",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
			out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
		) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{
					Err: fmt.Errorf("(GCSRestoreHeaders) unexpected request type %T", in.Request),
				}
			}

			if saved, _ := middleware.GetStackValue(ctx, gcsIgnoredHeadersKey{}).(string); saved != "" {
				req.Header.Set("Accept-Encoding", saved)
			}

			return next.HandleFinalize(ctx, in)
		},
	)
}
