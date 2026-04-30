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

package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_DeleteObjects(t *testing.T) {
	validBody, err := xml.Marshal(s3response.DeleteObjects{
		Objects: []types.ObjectIdentifier{
			{Key: utils.GetStringPtr("obj")},
		},
	})
	assert.NoError(t, err)

	validRes := s3response.DeleteResult{
		Deleted: []types.DeletedObject{
			{Key: utils.GetStringPtr("key")},
		},
	}

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "check object access returns error",
			input: testInput{
				locals:       defaultLocals,
				body:         validBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLocked),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrObjectLocked),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals:       defaultLocals,
				beRes:        s3response.DeleteResult{},
				beErr:        s3err.GetAPIError(s3err.ErrNoSuchBucket),
				body:         validBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.DeleteResult{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectRemovedDeleteObjects,
						ObjectCount: 1,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals:       defaultLocals,
				body:         validBody,
				beRes:        validRes,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectRemovedDeleteObjects,
						ObjectCount: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				DeleteObjectsFunc: func(contextMoqParam context.Context, deleteObjectsInput *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
					return tt.input.beRes.(s3response.DeleteResult), tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
				GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, tt.input.extraMockErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.DeleteObjects,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

// mockMpFileReader wraps an io.Reader and satisfies utils.MpFileReader.
// It tracks the number of bytes delivered to callers so that Length returns
// the same value that finalFileReader.Length would return after a real upload.
type mockMpFileReader struct {
	r         io.Reader
	bytesRead int64
}

func (m *mockMpFileReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	m.bytesRead += int64(n)
	return n, err
}

func (m *mockMpFileReader) Length() int64 { return m.bytesRead }

func newMockFileReader(content string) *mockMpFileReader {
	return &mockMpFileReader{r: strings.NewReader(content)}
}

func TestS3ApiController_POSTObject(t *testing.T) {
	encodePOSTPolicyForControllerTest := func(t *testing.T, expiration time.Time, conditions []any) string {
		t.Helper()

		policy := map[string]any{
			"expiration": expiration.UTC().Format(time.RFC3339),
			"conditions": conditions,
		}

		b, err := json.Marshal(policy)
		assert.NoError(t, err)

		return base64.StdEncoding.EncodeToString(b)
	}
	postObjectLocalsForTest := func(parsed middlewares.PostObjectResult) map[utils.ContextKey]any {
		return map[utils.ContextKey]any{
			utils.ContextKeyIsRoot: true,
			utils.ContextKeyParsedAcl: auth.ACL{
				Owner: "root",
			},
			utils.ContextKeyAccount: auth.Account{
				Access: "root",
				Role:   auth.RoleAdmin,
			},
			utils.ContextKeyRegion:           "us-east-1",
			utils.ContextKeyObjectPostResult: parsed,
		}
	}
	marshalObjectTaggingForControllerTest := func(t *testing.T, tags []s3response.Tag) string {
		t.Helper()

		data, err := xml.Marshal(s3response.Tagging{
			TagSet: s3response.TagSet{
				Tags: tags,
			},
		})
		assert.NoError(t, err)

		return string(data)
	}

	validTaggingXML := marshalObjectTaggingForControllerTest(t, []s3response.Tag{
		{Key: "project", Value: "alpha team"},
	})
	baseFields := map[string]string{
		"key":             "uploads/photo.jpg",
		"file":            "ignored",
		"x-amz-signature": "ignored",
	}
	basePolicy := encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
		map[string]string{"bucket": "bucket"},
		[]any{"starts-with", "$key", "uploads/"},
	})
	baseFields["policy"] = basePolicy

	location := "http://example.com/bucket/uploads%2Fphoto.jpg"

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "missing key",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"policy":          basePolicy,
						"file":            "ignored",
						"x-amz-signature": "ignored",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.PostAuth.MissingField("key"),
			},
		},
		{
			name: "verify access fails",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyIsRoot: false,
					utils.ContextKeyParsedAcl: auth.ACL{
						Owner: "user",
					},
					utils.ContextKeyAccount: auth.Account{
						Access: "user",
						Role:   auth.RoleUser,
					},
					utils.ContextKeyRegion: "us-east-1",
					utils.ContextKeyObjectPostResult: middlewares.PostObjectResult{
						Fields: map[string]string{
							"key": "key",
						},
					},
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "user",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid policy",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key":             "uploads/photo.jpg",
						"policy":          "%%%not-base64%%%",
						"file":            "ignored",
						"x-amz-signature": "ignored",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.InvalidPolicyDocument.InvalidBase64Encoding(),
			},
		},
		{
			name: "policy evaluation fails on extra field",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key":             "uploads/photo.jpg",
						"policy":          basePolicy,
						"file":            "ignored",
						"x-amz-signature": "ignored",
						"unexpected":      "value",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.InvalidPolicyDocument.ExtraInputField("unexpected"),
			},
		},
		{
			name: "invalid tagging xml",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key": "uploads/photo.jpg",
						"policy": encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
							map[string]string{"bucket": "bucket"},
							[]any{"starts-with", "$key", "uploads/"},
							[]any{"eq", "$tagging", "invalid-xml"},
						}),
						"file":            "ignored",
						"x-amz-signature": "ignored",
						"tagging":         "invalid-xml",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "invalid checksum fields",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key": "uploads/photo.jpg",
						"policy": encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
							map[string]string{"bucket": "bucket"},
							[]any{"starts-with", "$key", "uploads/"},
							[]any{"eq", "$x-amz-checksum-crc32", "invalid_base64_string"},
						}),
						"file":                 "ignored",
						"x-amz-signature":      "ignored",
						"x-amz-checksum-crc32": "invalid_base64_string",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-crc32"),
			},
		},
		{
			name: "metadata too large",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key": "uploads/photo.jpg",
						"policy": encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
							map[string]string{"bucket": "bucket"},
							[]any{"starts-with", "$key", "uploads/"},
							[]any{"starts-with", "$x-amz-meta-big", ""},
						}),
						"file":            "ignored",
						"x-amz-signature": "ignored",
						"x-amz-meta-big":  strings.Repeat("a", 2050),
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMetadataTooLarge),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				beErr: s3err.GetAPIError(s3err.ErrNoSuchBucket),
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields:        baseFields,
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful redirect response",
			input: testInput{
				beRes: s3response.PutObjectOutput{
					ETag:      "etag-123",
					VersionID: "vid-123",
				},
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key": "uploads/photo.jpg",
						"policy": encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
							map[string]string{"bucket": "bucket"},
							[]any{"starts-with", "$key", "uploads/"},
							[]any{"eq", "$success_action_redirect", "https://client.example/upload-complete"},
						}),
						"file":                    "ignored",
						"x-amz-signature":         "ignored",
						"success_action_redirect": "https://client.example/upload-complete",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"Location": utils.GetStringPtr("https://client.example/upload-complete?bucket=bucket&etag=etag-123&key=uploads%2Fphoto.jpg"),
					},
					MetaOpts: &MetaOptions{
						BucketOwner:   "root",
						ContentLength: int64(len("payload")),
						ObjectETag:    utils.GetStringPtr("etag-123"),
						ObjectSize:    int64(len("payload")),
						EventName:     s3event.EventObjectCreatedPost,
						Status:        303,
					},
				},
			},
		},
		{
			name: "successful created response",
			input: testInput{
				beRes: s3response.PutObjectOutput{
					ETag:          "etag-123",
					VersionID:     "vid-123",
					ChecksumCRC32: utils.GetStringPtr("crc32-out"),
					ChecksumType:  types.ChecksumTypeComposite,
				},
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key": "uploads/photo.jpg",
						"policy": encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
							map[string]string{"bucket": "bucket"},
							[]any{"starts-with", "$key", "uploads/"},
							[]any{"eq", "$success_action_status", "201"},
							[]any{"eq", "$tagging", validTaggingXML},
							[]any{"eq", "$x-amz-meta-owner", "alice"},
							[]any{"eq", "$x-amz-checksum-crc32", "ww2FVQ=="},
							[]any{"eq", "$cache-control", "max-age=60"},
							[]any{"eq", "$content-type", "image/jpeg"},
							[]any{"eq", "$content-disposition", "inline"},
							[]any{"eq", "$content-encoding", "gzip"},
							[]any{"eq", "$content-language", "en-US"},
							[]any{"eq", "$expires", "Fri, 21 Mar 2026 00:00:00 GMT"},
						}),
						"file":                  "ignored",
						"x-amz-signature":       "ignored",
						"success_action_status": "201",
						"tagging":               validTaggingXML,
						"x-amz-meta-owner":      "alice",
						"x-amz-checksum-crc32":  "ww2FVQ==",
						"cache-control":         "max-age=60",
						"content-type":          "image/jpeg",
						"content-disposition":   "inline",
						"content-encoding":      "gzip",
						"content-language":      "en-US",
						"expires":               "Fri, 21 Mar 2026 00:00:00 GMT",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"Etag":                     utils.GetStringPtr("etag-123"),
						"Location":                 &location,
						"x-amz-checksum-crc32":     utils.GetStringPtr("crc32-out"),
						"x-amz-checksum-crc32c":    utils.GetStringPtr(""),
						"x-amz-checksum-crc64nvme": utils.GetStringPtr(""),
						"x-amz-checksum-sha1":      utils.GetStringPtr(""),
						"x-amz-checksum-sha256":    utils.GetStringPtr(""),
						"x-amz-checksum-sha512":    utils.GetStringPtr(""),
						"x-amz-checksum-md5":       utils.GetStringPtr(""),
						"x-amz-checksum-xxhash64":  utils.GetStringPtr(""),
						"x-amz-checksum-xxhash3":   utils.GetStringPtr(""),
						"x-amz-checksum-xxhash128": utils.GetStringPtr(""),
						"x-amz-checksum-type":      utils.GetStringPtr(string(types.ChecksumTypeComposite)),
						"x-amz-version-id":         utils.GetStringPtr("vid-123"),
					},
					Data: &s3response.PostResponse{
						Bucket:   "bucket",
						Key:      "uploads/photo.jpg",
						ETag:     "etag-123",
						Location: location,
					},
					MetaOpts: &MetaOptions{
						BucketOwner:   "root",
						ContentLength: int64(len("payload")),
						ObjectETag:    utils.GetStringPtr("etag-123"),
						ObjectSize:    int64(len("payload")),
						EventName:     s3event.EventObjectCreatedPost,
						Status:        http.StatusCreated,
					},
				},
			},
		},
		{
			name: "anonymous upload with policy is evaluated",
			input: testInput{
				locals: postObjectLocalsForTest(middlewares.PostObjectResult{
					Fields: map[string]string{
						"key": "uploads/anon.bin",
						"policy": encodePOSTPolicyForControllerTest(t, time.Now().Add(15*time.Minute), []any{
							map[string]string{"bucket": "bucket"},
							// key condition intentionally omitted -> ExtraInputField for "key"
						}),
						"file": "ignored",
					},
					FileRdr:       newMockFileReader("payload"),
					ContentLength: int64(len("payload")),
				}),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.InvalidPolicyDocument.ExtraInputField("key"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutObjectFunc: func(contextMoqParam context.Context, putObjectInput s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
					if tt.input.beErr != nil {
						return s3response.PutObjectOutput{}, tt.input.beErr
					}

					// Drain the body as a real backend would, so that FileRdr.Length()
					// reflects the actual bytes written after PutObject returns.
					body, err := io.ReadAll(putObjectInput.Body)
					assert.NoError(t, err)

					if tt.name == "anonymous upload succeeds without policy" {
						assert.Equal(t, "uploads/anon.bin", *putObjectInput.Key)
						assert.Equal(t, "anon-payload", string(body))
					}

					if tt.name == "successful created response" {
						assert.Equal(t, "bucket", *putObjectInput.Bucket)
						assert.Equal(t, "uploads/photo.jpg", *putObjectInput.Key)
						assert.Equal(t, "image/jpeg", *putObjectInput.ContentType)
						assert.Equal(t, "gzip", *putObjectInput.ContentEncoding)
						assert.Equal(t, "inline", *putObjectInput.ContentDisposition)
						assert.Equal(t, "en-US", *putObjectInput.ContentLanguage)
						assert.Equal(t, "max-age=60", *putObjectInput.CacheControl)
						assert.Equal(t, "Fri, 21 Mar 2026 00:00:00 GMT", *putObjectInput.Expires)
						assert.Equal(t, int64(len("payload")), *putObjectInput.ContentLength)
						assert.Equal(t, "project=alpha+team", *putObjectInput.Tagging)
						assert.Equal(t, map[string]string{"owner": "alice"}, putObjectInput.Metadata)
						assert.Equal(t, utils.GetStringPtr("ww2FVQ=="), putObjectInput.ChecksumCRC32)
						assert.Equal(t, "payload", string(body))
					}

					return tt.input.beRes.(s3response.PutObjectOutput), nil
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.POSTObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
				},
			)
		})
	}
}
