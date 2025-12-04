package integration

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func UnsignedStreaminPayloadTrailer_malformed_trailer(s *S3Conf) error {
	testName := "UnsignedStreaminPayloadTrailer_malformed_trailer"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"
		for i, test := range []struct {
			trailer          string
			decContentLength string
			payload          string
		}{
			// missing trailer in the payload
			{"x-amz-checksum-crc64nvme", "5", "5\r\nhello\r\n0\r\n\r\n"},
			// empty checksum key
			{"x-amz-checksum-crc64nvme", "5", "5\r\nhello\r\n0\r\n:M3eFcAZSQlc=\r\n\r\n"},
			// missing x-amz-trailer
			{"", "5", "5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme:M3eFcAZSQlc=\r\n\r\n"},
			// invalid trailer in payload
			{"x-amz-checksum-crc64nvme", "5", "5\r\nhello\r\n0\r\ninvalid_trailer:M3eFcAZSQlc=\r\n\r\n"},
		} {
			reqHeaders := map[string]string{
				"x-amz-decoded-content-length": test.decContentLength,
			}
			if test.trailer != "" {
				reqHeaders["x-amz-trailer"] = test.trailer
			}

			_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, []byte(test.payload), reqHeaders)
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

func UnsignedStreamingPayloadTrailer_missing_invalid_dec_content_length(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_missing_invalid_dec_content_length"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "object"
		for i, clength := range []string{"", "abc", "12x"} {
			reqHeaders := map[string]string{
				"x-amz-trailer": "x-amz-checksum-crc64nvme",
			}
			if clength != "" {
				reqHeaders["x-amz-decoded-content-length"] = clength
			}
			body := []byte("5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme:M3eFcAZSQlc=\r\n\r\n")

			_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetAPIError(s3err.ErrMissingContentLength), apiErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func UnsignedStreamingPayloadTrailer_invalid_trailing_checksum(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_invalid_trailing_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"

		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "5",
			"x-amz-trailer":                "x-amz-checksum-crc64nvme",
		}

		body := []byte("5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme:invalid_checksum\r\n\r\n")

		_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
		if err != nil {
			return err
		}
		return compareS3ApiError(s3err.GetInvalidTrailingChecksumHeaderErr("x-amz-checksum-crc64nvme"), apiErr)
	})
}

func UnsignedStreamingPayloadTrailer_incorrect_trailing_checksum(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_incorrect_trailing_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"

		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "5",
			"x-amz-trailer":                "x-amz-checksum-crc64nvme",
		}

		// valid crc64nvme, but incorrect
		body := []byte("5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme:QFRKMGE3tuw=\r\n\r\n")

		_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
		if err != nil {
			return err
		}
		return compareS3ApiError(s3err.GetChecksumBadDigestErr("CRC64NVME"), apiErr)
	})
}

func UnsignedStreamingPayloadTrailer_multiple_checksum_headers(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_multiple_checksum_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		body := []byte("5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme:M3eFcAZSQlc=\r\n\r\n")

		for i, test := range []struct {
			key   string
			value string
		}{
			{"crc32", "NhCmhg=="},
			{"crc32c", "+Cy97w=="},
			{"crc64nvme", "QFRKMGE3tuw="},
			{"sha1", "qvTGHdzF6KLavt4PO0gs2a6pQ00="},
			{"sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="},
		} {
			reqHeaders := map[string]string{
				"x-amz-decoded-content-length":             "5",
				"x-amz-trailer":                            "x-amz-checksum-crc64nvme",
				fmt.Sprintf("x-amz-checksum-%s", test.key): test.value,
			}

			_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if err := compareS3ApiError(s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders), apiErr); err != nil {
				return err
			}
		}

		return nil
	})
}

func UnsignedStreamingPayloadTrailer_sdk_algo_and_trailer_mismatch(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_sdk_algo_and_trailer_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"

		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "5",
			"x-amz-trailer":                "x-amz-checksum-crc64nvme",
			"x-amz-sdk-checksum-algorithm": "sha1",
		}

		// valid crc64nvme, but incorrect
		body := []byte("5\r\nhello\r\n0\r\nx-amz-checksum-crc64nvme:M3eFcAZSQlc=\r\n\r\n")

		_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
		if err != nil {
			return err
		}
		return compareS3ApiError(s3err.GetInvalidChecksumHeaderErr("x-amz-sdk-checksum-algorithm"), apiErr)
	})
}

func UnsignedStreamingPayloadTrailer_incomplete_body(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_incomplete_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		for i, body := range [][]byte{
			[]byte("A\ndummy data\r\n0\r\n\r\n"),
			[]byte("A\r\ndummy data0\r\n\r\n"),
			[]byte("A\r\nXYZ\r\ndummy data\r\n0\r\n\r\n"),
			[]byte("B\r\ndummy data\r\n0\r\n\r\n"),
			[]byte("A\r\ndummy data\r\n0\r\n"),
			[]byte("A\r\ndummy data\r\n0\r\nx-amz-checksum-crc64nvme:dPVWc2vU1+Q=\r\n"),
			[]byte("A\r\n"),
			[]byte("A\r\nA\r\ndummy data\r\n0\r\n\r\n"),
			// invalid chunk size
			[]byte("invalid_chunk_size\r\ndummy data\r\n0\r\nx-amz-checksum-crc64nvme:dPVWc2vU1+Q=\r\n\r\n"),
			[]byte("A\r\ndummy data\r\nJ\r\nx-amz-checksum-crc64nvme:dPVWc2vU1+Q=\r\n\r\n"),
		} {
			reqHeaders := map[string]string{
				"x-amz-decoded-content-length": "10",
				"x-amz-trailer":                "x-amz-checksum-crc64nvme",
			}

			_, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
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

func UnsignedStreamingPayloadTrailer_no_trailer_should_calculate_crc64nvme(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_no_trailer_should_calculate_crc64nvme"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "11",
		}

		body := []byte("B\r\nhello world\r\n0\r\n\r\n")

		headers, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
		if err != nil {
			return err
		}
		if apiErr != nil {
			return fmt.Errorf("%s: %s", apiErr.Code, apiErr.Message)
		}

		csum := headers["x-amz-checksum-crc64nvme"]
		expectedCsum := "jSnVw/bqjr4="
		if csum != expectedCsum {
			return fmt.Errorf("expected the crc64nvme to be %s, instead got %s", expectedCsum, csum)
		}

		return nil
	})
}

func UnsignedStreamingPayloadTrailer_no_payload_trailer_only_headers(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_no_payload_trailer_only_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		body := []byte("7\r\nabcdefg\r\n0\r\n\r\n")

		for i, test := range []struct {
			key   string
			value string
		}{
			{"crc32", "MSpqpg=="},
			{"crc32c", "5if0QQ=="},
			{"crc64nvme", "SmzZ/LTp1CA="},
			{"sha1", "L7XhNBn8iSRoZeejJPR27GJOh0A="},
			{"sha256", "fRpUEnsiJQL1t5tfsIAwYRUqRPkrN+I8ZSe69mXU2po="},
		} {
			csumHdr := fmt.Sprintf("x-amz-checksum-%s", test.key)
			reqHeaders := map[string]string{
				"x-amz-decoded-content-length": "7",
				csumHdr:                        test.value,
			}

			headers, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body, reqHeaders)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if apiErr != nil {
				return fmt.Errorf("test %v failed: (%s) %s", i+1, apiErr.Code, apiErr.Message)
			}

			if headers[csumHdr] != test.value {
				return fmt.Errorf("expected the %s to be %s, instead got %s", csumHdr, test.value, headers[csumHdr])
			}
		}

		return nil
	})
}

func UnsignedStreamingPayloadTrailer_success_both_sdk_algo_and_trailer(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_success_both_sdk_algo_and_trailer"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"

		for i, test := range []struct {
			key   string
			value string
		}{
			{"crc32", "MSpqpg=="},
			{"crc32c", "5if0QQ=="},
			{"crc64nvme", "SmzZ/LTp1CA="},
			{"sha1", "L7XhNBn8iSRoZeejJPR27GJOh0A="},
			{"sha256", "fRpUEnsiJQL1t5tfsIAwYRUqRPkrN+I8ZSe69mXU2po="},
		} {
			csumHdr := fmt.Sprintf("x-amz-checksum-%s", test.key)
			reqHeaders := map[string]string{
				"x-amz-decoded-content-length": "7",
				"x-amz-sdk-checksum-algorithm": strings.ToUpper(test.key),
				"x-amz-trailer":                csumHdr,
			}
			body := bytes.NewBuffer([]byte("7\r\nabcdefg\r\n0\r\n"))

			_, err := body.WriteString(fmt.Sprintf("%s:%s\r\n\r\n", csumHdr, test.value))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			headers, apiErr, err := testUnsignedStreamingPayloadTrailerObjectPut(s, bucket, object, body.Bytes(), reqHeaders)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if apiErr != nil {
				return fmt.Errorf("test %v failed: (%s) %s", i+1, apiErr.Code, apiErr.Message)
			}

			if headers[csumHdr] != test.value {
				return fmt.Errorf("expected the %s to be %s, instead got %s", csumHdr, test.value, headers[csumHdr])
			}
		}

		return nil
	})
}

func UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_composite_checksum(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_composite_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		mp, err := createMp(s3client, bucket, object, withChecksumType(types.ChecksumTypeComposite), withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "7",
		}

		body := []byte("7\r\nabcdefg\r\n0\r\n\r\n")

		_, apiErr, err := testUnsignedStreamingPayloadTrailerUploadPart(s, bucket, object, mp.UploadId, body, reqHeaders)
		if err != nil {
			return err
		}

		return compareS3ApiError(s3err.GetChecksumTypeMismatchErr(types.ChecksumAlgorithmCrc32, "null"), apiErr)
	})
}

func UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_full_object(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_composite_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		mp, err := createMp(s3client, bucket, object, withChecksumType(types.ChecksumTypeFullObject), withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "7",
		}

		body := []byte("7\r\nabcdefg\r\n0\r\n\r\n")

		headers, apiErr, err := testUnsignedStreamingPayloadTrailerUploadPart(s, bucket, object, mp.UploadId, body, reqHeaders)
		if err != nil {
			return err
		}

		if apiErr != nil {
			return fmt.Errorf("(%s) %s", apiErr.Code, apiErr.Message)
		}

		expectedCsum := "MSpqpg=="
		actualCsum := headers["x-amz-checksum-crc32"]

		if expectedCsum != actualCsum {
			return fmt.Errorf("expected the crc32 checksum to be %s, instead got %s", expectedCsum, actualCsum)
		}
		return nil
	})
}

func UnsignedStreamingPayloadTrailer_UploadPart_trailer_and_mp_algo_mismatch(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_UploadPart_trailer_and_mp_algo_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		mp, err := createMp(s3client, bucket, object, withChecksumType(types.ChecksumTypeFullObject), withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		reqHeaders := map[string]string{
			"x-amz-decoded-content-length": "7",
			"x-amz-trailer":                "x-amz-checksum-sha256",
		}

		body := []byte("7\r\nabcdefg\r\n0\r\nx-amz-checksum-sha256:fRpUEnsiJQL1t5tfsIAwYRUqRPkrN+I8ZSe69mXU2po=\r\n\r\n")

		_, apiErr, err := testUnsignedStreamingPayloadTrailerUploadPart(s, bucket, object, mp.UploadId, body, reqHeaders)
		if err != nil {
			return err
		}

		return compareS3ApiError(s3err.GetChecksumTypeMismatchErr(types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha256), apiErr)
	})
}

func UnsignedStreamingPayloadTrailer_UploadPart_success_with_trailer(s *S3Conf) error {
	testName := "UnsignedStreamingPayloadTrailer_UploadPart_success_with_trailer"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"

		for i, test := range []struct {
			key   string
			value string
		}{
			{"crc32", "QWaN2w=="},
			{"crc32c", "R/I7iQ=="},
			{"crc64nvme", "dPVWc2vU1+Q="},
			{"sha1", "YR/1TvTYOJz5gtqVFoBJBtmTibY="},
			{"sha256", "eXuwq/95jXIAr3aF3KeQHt/8Ur8mUA1b2XKCZY7iQVI="},
		} {
			mp, err := createMp(s3client, bucket, object, withChecksum(types.ChecksumAlgorithm(strings.ToUpper(test.key))))
			if err != nil {
				return err
			}
			csumHdr := fmt.Sprintf("x-amz-checksum-%s", test.key)
			reqHeaders := map[string]string{
				"x-amz-decoded-content-length": "10",
				"x-amz-sdk-checksum-algorithm": test.key,
				"x-amz-trailer":                csumHdr,
			}
			body := bytes.NewBuffer([]byte("A\r\ndummy data\r\n0\r\n"))

			_, err = body.WriteString(fmt.Sprintf("%s:%s\r\n\r\n", csumHdr, test.value))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			headers, apiErr, err := testUnsignedStreamingPayloadTrailerUploadPart(s, bucket, object, mp.UploadId, body.Bytes(), reqHeaders)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			if apiErr != nil {
				return fmt.Errorf("test %v failed: (%s) %s", i+1, apiErr.Code, apiErr.Message)
			}

			if headers[csumHdr] != test.value {
				return fmt.Errorf("expected the %s to be %s, instead got %s", csumHdr, test.value, headers[csumHdr])
			}
		}

		return nil
	})
}
