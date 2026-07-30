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

//go:build linux && amd64 && cgo

// This file holds the S3 request plumbing shared by the GPU (session_linux.go)
// and host-memory (session_host_linux.go) session implementations: both issue
// a zero-byte PUT/GET carrying the cuObject RDMA descriptor headers, and let
// the gateway perform the actual transfer via RDMA.
package cuobjclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	s3lib "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/versity/versitygw/cumiddleware"
)

func doPut(base *s3lib.Client, bucket, key string, size int64, descr string, remoteStart uint64) error {
	var replyStatus string
	var transferredHeader string
	c := withRDMAHeaders(base, descr, size, remoteStart, &replyStatus, &transferredHeader)
	_, err := c.PutObject(context.Background(), &s3lib.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          strings.NewReader(""),
		ContentLength: aws.Int64(0),
	})
	if err != nil {
		return err
	}
	if replyStatus == "" {
		return fmt.Errorf("cuobjclient: gateway did not confirm RDMA offload (missing %s response header)", cumiddleware.HeaderRDMAReply)
	}
	rdmaStatus, err := strconv.Atoi(replyStatus)
	if err != nil {
		return fmt.Errorf("cuobjclient: invalid %s header %q: %w", cumiddleware.HeaderRDMAReply, replyStatus, err)
	}
	if rdmaStatus != http.StatusOK && rdmaStatus != http.StatusNoContent {
		return fmt.Errorf("cuobjclient: RDMA offload not successful, %s=%d", cumiddleware.HeaderRDMAReply, rdmaStatus)
	}
	if transferredHeader == "" {
		return fmt.Errorf("cuobjclient: missing %s response header", cumiddleware.HeaderRDMABytesTransferred)
	}
	transferred, err := strconv.ParseInt(transferredHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("cuobjclient: invalid %s header %q: %w", cumiddleware.HeaderRDMABytesTransferred, transferredHeader, err)
	}
	if transferred != size {
		return fmt.Errorf("cuobjclient: RDMA transferred %d bytes, want %d", transferred, size)
	}
	return nil
}

func doGet(base *s3lib.Client, bucket, key string, size int64, descr string, remoteStart uint64) error {
	var replyStatus string
	var transferredHeader string
	c := withRDMAHeaders(base, descr, size, remoteStart, &replyStatus, &transferredHeader)
	out, err := c.GetObject(context.Background(), &s3lib.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	// The RDMA GET path deliberately reports ContentLength 0 on the HTTP
	// response (the object bytes were already sent via RDMA, not the HTTP
	// body), so the transfer must be confirmed via the gateway's RDMA reply
	// header instead. A short/oversized transfer or a missing reply (offload
	// silently not applied) is caught here rather than treated as success.
	if replyStatus == "" {
		return fmt.Errorf("cuobjclient: gateway did not confirm RDMA offload (missing %s response header)", cumiddleware.HeaderRDMAReply)
	}
	rdmaStatus, err := strconv.Atoi(replyStatus)
	if err != nil {
		return fmt.Errorf("cuobjclient: invalid %s header %q: %w", cumiddleware.HeaderRDMAReply, replyStatus, err)
	}
	if rdmaStatus != http.StatusOK && rdmaStatus != http.StatusNoContent && rdmaStatus != http.StatusPartialContent {
		return fmt.Errorf("cuobjclient: RDMA offload not successful, %s=%d", cumiddleware.HeaderRDMAReply, rdmaStatus)
	}
	if transferredHeader == "" {
		return fmt.Errorf("cuobjclient: missing %s response header", cumiddleware.HeaderRDMABytesTransferred)
	}
	transferred, err := strconv.ParseInt(transferredHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("cuobjclient: invalid %s header %q: %w", cumiddleware.HeaderRDMABytesTransferred, transferredHeader, err)
	}
	if transferred != size {
		return fmt.Errorf("cuobjclient: RDMA transferred %d bytes, want %d", transferred, size)
	}
	_, err = io.Copy(io.Discard, out.Body)
	return err
}

// withRDMAHeaders returns a client that adds the legacy RDMA descriptor,
// size, and remote-address headers to every request. The headers are added
// via a Build-step middleware — which runs before the Finalize step that
// signs the request — so SigV4 covers them in SignedHeaders; an
// intermediary can no longer alter the RDMA controls without invalidating
// the signature. The caller's HTTPClient (with its own TLS/proxy/timeout
// configuration) is left untouched. Automatic request/response checksum
// calculation is disabled for these control requests: the SDK would
// otherwise checksum the empty HTTP body instead of the actual RDMA payload.
// If replyStatus/transferred are non-nil, they are set to the response
// HeaderRDMAReply and HeaderRDMABytesTransferred values (empty if absent).
func withRDMAHeaders(base *s3lib.Client, descr string, size int64, remoteStart uint64, replyStatus, transferred *string) *s3lib.Client {
	opts := base.Options()
	opts.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	opts.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	opts.APIOptions = append(opts.APIOptions, func(stack *smithymiddleware.Stack) error {
		if err := stack.Build.Add(smithymiddleware.BuildMiddlewareFunc("AddRDMAHeaders",
			func(ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler) (
				smithymiddleware.BuildOutput, smithymiddleware.Metadata, error) {
				if req, ok := in.Request.(*smithyhttp.Request); ok {
					req.Header.Set(cumiddleware.HeaderRDMADescr, descr)
					req.Header.Set(cumiddleware.HeaderRDMASize, strconv.FormatInt(size, 10))
					req.Header.Set(cumiddleware.HeaderRDMARemoteAddr, strconv.FormatUint(remoteStart, 10))
				}
				return next.HandleBuild(ctx, in)
			}), smithymiddleware.Before); err != nil {
			return err
		}
		if replyStatus == nil && transferred == nil {
			return nil
		}
		return stack.Deserialize.Add(smithymiddleware.DeserializeMiddlewareFunc("CaptureRDMAReply",
			func(ctx context.Context, in smithymiddleware.DeserializeInput, next smithymiddleware.DeserializeHandler) (
				smithymiddleware.DeserializeOutput, smithymiddleware.Metadata, error) {
				out, metadata, err := next.HandleDeserialize(ctx, in)
				if resp, ok := out.RawResponse.(*smithyhttp.Response); ok {
					if replyStatus != nil {
						*replyStatus = resp.Header.Get(cumiddleware.HeaderRDMAReply)
					}
					if transferred != nil {
						*transferred = resp.Header.Get(cumiddleware.HeaderRDMABytesTransferred)
					}
				}
				return out, metadata, err
			}), smithymiddleware.After)
	})
	return s3lib.New(opts)
}
