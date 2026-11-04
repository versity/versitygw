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

// CompleteMultipartUpload answered the way AWS does: 200 at once, whitespace while the backend assembles the parts,
// then the result or the error in the body. A backend on slow storage can take longer than a client's
// response-header timeout (minio-go: one minute); the client's retry would otherwise get the idempotent "still in
// progress" success before the object exists.

package controllers

import (
	"bufio"
	"context"
	"encoding/xml"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var completeKeepAlive = 10 * time.Second

// WithStreamedComplete returns the controller with CompleteMultipartUpload answered as a stream.
func (c S3ApiController) WithStreamedComplete() S3ApiController {
	c.streamComplete = true
	return c
}

func (c S3ApiController) streamCompleteMultipartUpload(ctx fiber.Ctx, input *s3.CompleteMultipartUploadInput, acct auth.Account, owner string) (*Response, error) {
	requestID, hostID := utils.EnsureRequestIDs(ctx)
	requestID, hostID = strings.Clone(requestID), strings.Clone(hostID)
	location := strings.Clone(utils.GenerateObjectLocation(ctx, c.virtualDomain, *input.Bucket, *input.Key))
	// strings read from the request point into fasthttp's buffers, which are reused once the handler returns
	for _, s := range []**string{&input.Bucket, &input.Key, &input.UploadId, &input.SSECustomerAlgorithm,
		&input.SSECustomerKey, &input.SSECustomerKeyMD5, &input.ChecksumCRC32, &input.ChecksumCRC32C,
		&input.ChecksumSHA1, &input.ChecksumSHA256, &input.ChecksumCRC64NVME, &input.ChecksumSHA512,
		&input.ChecksumMD5, &input.ChecksumXXHASH64, &input.ChecksumXXHASH3, &input.ChecksumXXHASH128,
		&input.IfMatch, &input.IfNoneMatch} {
		if *s != nil {
			v := strings.Clone(**s)
			*s = &v
		}
	}
	input.ChecksumType = types.ChecksumType(strings.Clone(string(input.ChecksumType)))

	//nolint:staticcheck // the posix backend reads the account under this plain string key
	bectx := context.WithValue(context.Background(), "account", acct)
	done := make(chan []byte, 1)
	go func() {
		res, _, err := c.be.CompleteMultipartUpload(bectx, input)
		done <- completeBody(res, err, location, requestID, hostID)
	}()

	ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
	ctx.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
		tick := time.NewTicker(completeKeepAlive)
		defer tick.Stop()
		// fasthttp sends the status line and headers with the first non-empty chunk
		w.WriteByte(' ')
		w.Flush()
		for {
			select {
			case body := <-done:
				w.Write(body)
				w.Flush()
				return
			case <-tick.C:
				// a gone client fails the flush; keep waiting so the assembly still finishes
				w.WriteByte(' ')
				w.Flush()
			}
		}
	})

	return &Response{
		MetaOpts: &MetaOptions{
			BucketOwner: owner,
		},
	}, nil
}

func completeBody(res s3response.CompleteMultipartUploadResult, err error, location, requestID, hostID string) []byte {
	if err == nil {
		res.Location = &location
		var body []byte
		if body, err = xml.Marshal(res); err == nil {
			return body
		}
	}
	if serr, ok := err.(s3err.S3Error); ok {
		return serr.XMLBody(requestID, hostID)
	}
	debuglogger.InternalError(err)
	return s3err.GetAPIError(s3err.ErrInternalError).XMLBody(requestID, hostID)
}
