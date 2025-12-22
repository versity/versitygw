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

package integration

import (
	"bytes"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func SignedStreamingPayload_invalid_encoding(s *S3Conf) error {
	testName := "SignedStreamingPayload_invalid_encoding"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "object"
		for i, test := range []struct {
			from   int
			to     int
			buffer []byte
		}{
			{0, 2, []byte{'j'}}, // invalid chunk size
			// missing/invalid delimiters
			{83, 85, nil},
			{83, 85, []byte("dd")},
			{103, 105, nil},
			{103, 105, []byte("something invalid")},
			// invalid trailing delimiter
			{187, 191, []byte("bbbb")},
			// only last character changed
			{190, 191, []byte("s")},
			// invalid chunksize delimiter (;)
			{2, 3, []byte(":")},
			// missing chunk-signature
			{3, 19, nil},
			// short signature
			{19, 24, nil},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(s, bucket, object, []byte("dummy data paylaod"), withModifyPayload(test.from, test.to, test.buffer))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetAPIError(s3err.ErrIncompleteBody), apiErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func SignedStreamingPayload_invalid_chunk_size(s *S3Conf) error {
	testName := "SignedStreamingPayload_invalid_chunk_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			chunkSize int64
			payload   []byte
			expectErr bool
		}{
			{10, bytes.Repeat([]byte{'b'}, 100), true},
			{1000, bytes.Repeat([]byte{'a'}, 200), false},
			{8192, bytes.Repeat([]byte{'c'}, 10000), false},
			{1000, bytes.Repeat([]byte{'c'}, 1024*64), true},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(s, bucket, object, test.payload, withChunkSize(test.chunkSize))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if !test.expectErr && apiErr != nil {
				return fmt.Errorf("test %v failed: expected no error, instead got: (%s) %s", i+1, apiErr.Code, apiErr.Message)
			}

			if test.expectErr {
				if err := compareS3ApiError(s3err.GetAPIError(s3err.ErrInvalidChunkSize), apiErr); err != nil {
					return fmt.Errorf("test %v failed: %w", i+1, err)
				}
			}
		}

		return nil
	})
}

func SignedStreamingPayload_decoded_content_length_mismatch(s *S3Conf) error {
	testName := "SignedStreamingPayload_decoded_content_length_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			cLength int64
			payload []byte
		}{
			{10, bytes.Repeat([]byte{'a'}, 8)},
			{10, bytes.Repeat([]byte{'a'}, 12)},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(s, bucket, object, test.payload, withCustomHeaders(map[string]string{
				"x-amz-decoded-content-length": fmt.Sprint(test.cLength),
			}))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetAPIError(s3err.ErrContentLengthMismatch), apiErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}
