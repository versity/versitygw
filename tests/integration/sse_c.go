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

package integration

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

const sseCustomerAlgorithm = "AES256"

var sseCustomerKey, sseCustomerKeyMD5 = func() (string, string) {
	key := bytes.Repeat([]byte{0x42}, 32)
	sum := md5.Sum(key)
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(sum[:])
}()

type sseCInvalidCase struct {
	algorithm, key, keyMD5 *string
	err                    s3err.S3Error
}

func sseCInvalidCases() []sseCInvalidCase {
	shortKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))
	wrongMD5 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	return []sseCInvalidCase{
		{algorithm: getPtr(sseCustomerAlgorithm),
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECMissingKey, "")},
		{key: &sseCustomerKey,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECMissingAlgorithm, "")},
		{keyMD5: &sseCustomerKeyMD5,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECMissingAlgorithm, "")},
		{key: &sseCustomerKey, keyMD5: &sseCustomerKeyMD5,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECMissingAlgorithm, "")},
		{algorithm: getPtr(sseCustomerAlgorithm), key: &sseCustomerKey,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECMissingKeyMD5, "")},
		{algorithm: getPtr("AES128"), key: &sseCustomerKey, keyMD5: &sseCustomerKeyMD5,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECInvalidAlgorithm, "AES128")},
		{algorithm: getPtr(sseCustomerAlgorithm), key: &shortKey, keyMD5: &sseCustomerKeyMD5,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECInvalidKey, "")},
		{algorithm: getPtr(sseCustomerAlgorithm), key: &sseCustomerKey, keyMD5: &wrongMD5,
			err: s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECKeyMD5Mismatch, "")},
	}
}

func PutObject_unsupported_sse_not_implemented(s *S3Conf) error {
	testName := "PutObject_unsupported_sse_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, method := range []types.ServerSideEncryption{
			types.ServerSideEncryptionAes256,
			types.ServerSideEncryptionAwsKms,
			types.ServerSideEncryptionAwsKmsDsse,
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:               &bucket,
				Key:                  getPtr("kms-obj"),
				Body:                 bytes.NewReader([]byte("data")),
				ServerSideEncryption: method,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented)); err != nil {
				return fmt.Errorf("encryption method %s: %w", method, err)
			}
		}
		return nil
	})
}

func PutObject_sse_c_requires_tls(s *S3Conf) error {
	testName := "PutObject_sse_c_requires_tls"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:               &bucket,
			Key:                  getPtr("tls-obj"),
			Body:                 bytes.NewReader([]byte("data")),
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgSSECRequiresTLS, ""))
	})
}

func PutObject_sse_c_invalid_headers(s *S3Conf) error {
	testName := "PutObject_sse_c_invalid_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, tc := range sseCInvalidCases() {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:               &bucket,
				Key:                  getPtr("my-obj"),
				Body:                 bytes.NewReader([]byte("data")),
				SSECustomerAlgorithm: tc.algorithm,
				SSECustomerKey:       tc.key,
				SSECustomerKeyMD5:    tc.keyMD5,
			})
			cancel()
			if err := checkApiErr(err, tc.err); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func HeadObject_sse_c_invalid_headers(s *S3Conf) error {
	testName := "HeadObject_sse_c_invalid_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		if _, err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		for i, tc := range sseCInvalidCases() {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:               &bucket,
				Key:                  &obj,
				SSECustomerAlgorithm: tc.algorithm,
				SSECustomerKey:       tc.key,
				SSECustomerKeyMD5:    tc.keyMD5,
			})
			cancel()
			// HEAD has no error body, so the SDK reports any 400 as BadRequest
			if err := checkSdkApiErr(err, "BadRequest"); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func CopyObject_sse_c_invalid_copy_source_headers(s *S3Conf) error {
	testName := "CopyObject_sse_c_invalid_copy_source_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "src-obj"
		if _, err := putObjects(s3client, []string{srcObj}, bucket); err != nil {
			return err
		}

		for i, tc := range sseCInvalidCases() {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:                         &bucket,
				Key:                            getPtr("dst-obj"),
				CopySource:                     getPtr(bucket + "/" + srcObj),
				CopySourceSSECustomerAlgorithm: tc.algorithm,
				CopySourceSSECustomerKey:       tc.key,
				CopySourceSSECustomerKeyMD5:    tc.keyMD5,
			})
			cancel()
			if err := checkApiErr(err, tc.err); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func PutObject_sse_c_not_implemented(s *S3Conf) error {
	testName := "PutObject_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:               &bucket,
			Key:                  getPtr("my-obj"),
			Body:                 bytes.NewReader([]byte("data")),
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PostObject_sse_c_not_implemented(s *S3Conf) error {
	testName := "PostObject_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         "my-obj",
			s3Conf:      s,
			fileContent: []byte("data"),
			policyConditions: []any{
				[]any{"eq", "$x-amz-server-side-encryption-customer-algorithm", sseCustomerAlgorithm},
				[]any{"eq", "$x-amz-server-side-encryption-customer-key", sseCustomerKey},
				[]any{"eq", "$x-amz-server-side-encryption-customer-key-md5", sseCustomerKeyMD5},
			},
			extraFields: map[string]string{
				"x-amz-server-side-encryption-customer-algorithm": sseCustomerAlgorithm,
				"x-amz-server-side-encryption-customer-key":       sseCustomerKey,
				"x-amz-server-side-encryption-customer-key-md5":   sseCustomerKeyMD5,
			},
		})
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetObject_sse_c_not_implemented(s *S3Conf) error {
	testName := "GetObject_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		if _, err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:               &bucket,
			Key:                  &obj,
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func HeadObject_sse_c_not_implemented(s *S3Conf) error {
	testName := "HeadObject_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		if _, err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:               &bucket,
			Key:                  &obj,
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		// HEAD responses carry no body, so only the code can be checked
		return checkSdkApiErr(err, "NotImplemented")
	})
}

func GetObjectAttributes_sse_c_not_implemented(s *S3Conf) error {
	testName := "GetObjectAttributes_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		if _, err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:               &bucket,
			Key:                  &obj,
			ObjectAttributes:     []types.ObjectAttributes{types.ObjectAttributesEtag},
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func CopyObject_sse_c_not_implemented(s *S3Conf) error {
	testName := "CopyObject_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "src-obj"
		if _, err := putObjects(s3client, []string{srcObj}, bucket); err != nil {
			return err
		}

		for i, input := range []*s3.CopyObjectInput{
			{
				SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
				SSECustomerKey:       &sseCustomerKey,
				SSECustomerKeyMD5:    &sseCustomerKeyMD5,
			},
			{
				CopySourceSSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
				CopySourceSSECustomerKey:       &sseCustomerKey,
				CopySourceSSECustomerKeyMD5:    &sseCustomerKeyMD5,
			},
		} {
			input.Bucket = &bucket
			input.Key = getPtr("dst-obj")
			input.CopySource = getPtr(bucket + "/" + srcObj)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, input)
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented)); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func CreateMultipartUpload_sse_c_not_implemented(s *S3Conf) error {
	testName := "CreateMultipartUpload_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:               &bucket,
			Key:                  getPtr("my-obj"),
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func UploadPart_sse_c_not_implemented(s *S3Conf) error {
	testName := "UploadPart_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:               &bucket,
			Key:                  &obj,
			UploadId:             mp.UploadId,
			PartNumber:           getPtr(int32(1)),
			Body:                 bytes.NewReader([]byte("data")),
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func UploadPartCopy_sse_c_not_implemented(s *S3Conf) error {
	testName := "UploadPartCopy_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, obj := "src-obj", "my-obj"
		if _, err := putObjects(s3client, []string{srcObj}, bucket); err != nil {
			return err
		}
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		for i, input := range []*s3.UploadPartCopyInput{
			{
				SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
				SSECustomerKey:       &sseCustomerKey,
				SSECustomerKeyMD5:    &sseCustomerKeyMD5,
			},
			{
				CopySourceSSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
				CopySourceSSECustomerKey:       &sseCustomerKey,
				CopySourceSSECustomerKeyMD5:    &sseCustomerKeyMD5,
			},
		} {
			input.Bucket = &bucket
			input.Key = &obj
			input.UploadId = mp.UploadId
			input.PartNumber = getPtr(int32(1))
			input.CopySource = getPtr(bucket + "/" + srcObj)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPartCopy(ctx, input)
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented)); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func CompleteMultipartUpload_sse_c_not_implemented(s *S3Conf) error {
	testName := "CompleteMultipartUpload_sse_c_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		part, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: getPtr(int32(1)),
			Body:       bytes.NewReader([]byte("data")),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: part.ETag, PartNumber: getPtr(int32(1))},
				},
			},
			SSECustomerAlgorithm: getPtr(sseCustomerAlgorithm),
			SSECustomerKey:       &sseCustomerKey,
			SSECustomerKeyMD5:    &sseCustomerKeyMD5,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}
