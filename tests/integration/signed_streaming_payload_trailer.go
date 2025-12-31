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
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func SignedStreamingPayloadTrailer_malformed_trailer(s *S3Conf) error {
	testName := "SignedStreamingPayloadTrailer_malformed_trailer"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			trailerHdr       string
			trailingChecksum string
		}{
			{"x-amz-checksum-crc64nvme", "x-amz-invalid:invalid"},
			{"x-amz-checksum-crc64nvme", ""},
			// x-amz-trailer and trailing checksum mismatch
			{"x-amz-checksum-sha1", "x-amz-checksum-crc32:QWaN2w=="},
			{"x-amz-checksum-crc32c", "x-amz-checksum-sha1:YR/1TvTYOJz5gtqVFoBJBtmTibY="},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(s, bucket, object, []byte("dummy data"), withTrailingChecksum(test.trailingChecksum), withCustomHeaders(map[string]string{
				"x-amz-trailer": test.trailerHdr,
			}))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetAPIError(s3err.ErrMalformedTrailer), apiErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func SignedStreamingPayloadTrailer_incomplete_body(s *S3Conf) error {
	testName := "SignedStreamingPayloadTrailer_incomplete_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			modifFrom    int
			modifTo      int
			modifPayload []byte
		}{
			{175, 176, []byte("k")},
			{175, 177, []byte("cc")},
			{215, 216, []byte("bcd")},
			{220, 223, []byte("invalid")},
			{230, 235, []byte("abcd")},
			{241, 245, []byte("abcde")},
			{306, 308, []byte("pp")},
			{304, 308, []byte("erty")},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(
				s,
				bucket,
				object,
				[]byte("abcdefg"),
				withTrailingChecksum("x-amz-checksum-crc64nvme:SmzZ/LTp1CA="),
				withCustomHeaders(map[string]string{"x-amz-trailer": "x-amz-checksum-crc64nvme"}),
				withModifyPayload(test.modifFrom, test.modifTo, test.modifPayload),
			)
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

func SignedStreamingPayloadTrailer_missing_x_amz_trailer_header(s *S3Conf) error {
	testName := "SignedStreamingPayloadTrailer_missing_x_amz_trailer_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, apiErr, err := testSignedStreamingObjectPut(s, bucket, "my-object", []byte("hello"), withTrailingChecksum("x-amz-checksum-crc32:NhCmhg=="))
		if err != nil {
			return err
		}

		return compareS3ApiError(s3err.GetAPIError(s3err.ErrMalformedTrailer), apiErr)
	})
}

func SignedStreamingPayloadTrailer_invalid_checksum(s *S3Conf) error {
	testName := "SignedStreamingPayloadTrailer_invalid_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			trailerHdr       string
			trailingChecksum string
		}{
			{"x-amz-checksum-crc32", "x-amz-checksum-crc32:invalid"},
			{"x-amz-checksum-crc32c", "x-amz-checksum-crc32c:invalid"},
			{"x-amz-checksum-crc64nvme", "x-amz-checksum-crc64nvme:invalid"},
			{"x-amz-checksum-sha1", "x-amz-checksum-sha1:invalid"},
			{"x-amz-checksum-sha256", "x-amz-checksum-sha256:invalid"},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(s, bucket, object, []byte("dummy data"), withTrailingChecksum(test.trailingChecksum), withCustomHeaders(map[string]string{
				"x-amz-trailer": test.trailerHdr,
			}))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetInvalidTrailingChecksumHeaderErr(test.trailerHdr), apiErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func SignedStreamingPayloadTrailer_bad_digest(s *S3Conf) error {
	testName := "SignedStreamingPayloadTrailer_bad_digest"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			algo             types.ChecksumAlgorithm
			trailerHdr       string
			trailingChecksum string
		}{
			{types.ChecksumAlgorithmCrc32, "x-amz-checksum-crc32", "x-amz-checksum-crc32:NhCmhg=="},
			{types.ChecksumAlgorithmCrc32c, "x-amz-checksum-crc32c", "x-amz-checksum-crc32c:+Cy97w=="},
			{types.ChecksumAlgorithmCrc64nvme, "x-amz-checksum-crc64nvme", "x-amz-checksum-crc64nvme:QFRKMGE3tuw="},
			{types.ChecksumAlgorithmSha1, "x-amz-checksum-sha1", "x-amz-checksum-sha1:qvTGHdzF6KLavt4PO0gs2a6pQ00="},
			{types.ChecksumAlgorithmSha256, "x-amz-checksum-sha256", "x-amz-checksum-sha256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="},
		} {
			_, apiErr, err := testSignedStreamingObjectPut(s, bucket, object, []byte("some random data"), withTrailingChecksum(test.trailingChecksum), withCustomHeaders(map[string]string{
				"x-amz-trailer": test.trailerHdr,
			}))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetChecksumBadDigestErr(test.algo), apiErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func SignedStreamingPayloadTrailer_success(s *S3Conf) error {
	testName := "SignedStreamingPayloadTrailer_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, test := range []struct {
			checksumKey   string
			checksumValue string
		}{
			{"x-amz-checksum-crc32", "z3mWAA=="},
			{"x-amz-checksum-crc32c", "rxvjPA=="},
			{"x-amz-checksum-crc64nvme", "dYnI3/Fh0gM="},
			{"x-amz-checksum-sha1", "8O8FwCfmd5fCbCBvH09mrKMVoHU="},
			{"x-amz-checksum-sha256", "OoSow5X4zTIPl27MtdFdYT+9O3C367C75+Cb2MFtRBc="},
		} {
			headers, apiErr, err := testSignedStreamingObjectPut(
				s,
				bucket,
				object,
				[]byte("the object data"),
				withTrailingChecksum(fmt.Sprintf("%s:%s", test.checksumKey, test.checksumValue)),
				withCustomHeaders(map[string]string{
					"x-amz-trailer": test.checksumKey,
				}),
			)

			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
			if apiErr != nil {
				return fmt.Errorf("test %v failed: (%s) %s", i+1, apiErr.Code, apiErr.Message)
			}

			if headers[test.checksumKey] != test.checksumValue {
				return fmt.Errorf("test %v failed: expected %s header value to be %s, instead got %s", i+1, test.checksumKey, test.checksumValue, headers[test.checksumKey])
			}
		}

		return nil
	})
}
