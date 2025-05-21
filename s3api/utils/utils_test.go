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

package utils

import (
	"bytes"
	"encoding/xml"
	"errors"
	"math/rand"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestCreateHttpRequestFromCtx(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}

	app := fiber.New()

	// Expected output, Case 1
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	req := ctx.Request()
	request, _ := http.NewRequest(string(req.Header.Method()), req.URI().String(), bytes.NewReader(req.Body()))

	// Case 2
	ctx2 := app.AcquireCtx(&fasthttp.RequestCtx{})
	req2 := ctx2.Request()
	req2.Header.Add("X-Amz-Mfa", "Some valid Mfa")

	request2, _ := http.NewRequest(string(req2.Header.Method()), req2.URI().String(), bytes.NewReader(req2.Body()))
	request2.Header.Add("X-Amz-Mfa", "Some valid Mfa")

	tests := []struct {
		name    string
		args    args
		want    *http.Request
		wantErr bool
		hdrs    []string
	}{
		{
			name: "Success-response",
			args: args{
				ctx: ctx,
			},
			want:    request,
			wantErr: false,
			hdrs:    []string{},
		},
		{
			name: "Success-response-With-Headers",
			args: args{
				ctx: ctx2,
			},
			want:    request2,
			wantErr: false,
			hdrs:    []string{"X-Amz-Mfa"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createHttpRequestFromCtx(tt.args.ctx, tt.hdrs, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateHttpRequestFromCtx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got.Header, tt.want.Header) {
				t.Errorf("CreateHttpRequestFromCtx() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserMetaData(t *testing.T) {
	type args struct {
		headers *fasthttp.RequestHeader
	}

	app := fiber.New()

	// Case 1
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	req := ctx.Request()

	tests := []struct {
		name         string
		args         args
		wantMetadata map[string]string
	}{
		{
			name: "Success-empty-response",
			args: args{
				headers: &req.Header,
			},
			wantMetadata: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMetadata := GetUserMetaData(tt.args.headers); !reflect.DeepEqual(gotMetadata, tt.wantMetadata) {
				t.Errorf("GetUserMetaData() = %v, want %v", gotMetadata, tt.wantMetadata)
			}
		})
	}
}

func Test_includeHeader(t *testing.T) {
	type args struct {
		hdr        string
		signedHdrs []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "include-header-falsy-case",
			args: args{
				hdr:        "Content-Type",
				signedHdrs: []string{"X-Amz-Acl", "Content-Encoding"},
			},
			want: false,
		},
		{
			name: "include-header-falsy-case",
			args: args{
				hdr:        "Content-Type",
				signedHdrs: []string{"X-Amz-Acl", "Content-Type"},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := includeHeader(tt.args.hdr, tt.args.signedHdrs); got != tt.want {
				t.Errorf("includeHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidBucketName(t *testing.T) {
	type args struct {
		bucket string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "IsValidBucketName-short-name",
			args: args{
				bucket: "a",
			},
			want: false,
		},
		{
			name: "IsValidBucketName-start-with-hyphen",
			args: args{
				bucket: "-bucket",
			},
			want: false,
		},
		{
			name: "IsValidBucketName-start-with-dot",
			args: args{
				bucket: ".bucket",
			},
			want: false,
		},
		{
			name: "IsValidBucketName-contain-invalid-character",
			args: args{
				bucket: "my@bucket",
			},
			want: false,
		},
		{
			name: "IsValidBucketName-end-with-hyphen",
			args: args{
				bucket: "bucket-",
			},
			want: false,
		},
		{
			name: "IsValidBucketName-end-with-dot",
			args: args{
				bucket: "bucket.",
			},
			want: false,
		},
		{
			name: "IsValidBucketName-valid-bucket-name",
			args: args{
				bucket: "my-bucket",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidBucketName(tt.args.bucket); got != tt.want {
				t.Errorf("IsValidBucketName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseUint(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    int32
		wantErr bool
	}{
		{
			name: "Parse-uint-empty-string",
			args: args{
				str: "",
			},
			want:    1000,
			wantErr: false,
		},
		{
			name: "Parse-uint-invalid-number-string",
			args: args{
				str: "bla",
			},
			want:    1000,
			wantErr: true,
		},
		{
			name: "Parse-uint-invalid-negative-number",
			args: args{
				str: "-5",
			},
			want:    1000,
			wantErr: true,
		},
		{
			name: "Parse-uint-success",
			args: args{
				str: "23",
			},
			want:    23,
			wantErr: false,
		},
		{
			name: "Parse-uint-greater-than-1000",
			args: args{
				str: "25000000",
			},
			want:    1000,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUint(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMaxKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseMaxKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterObjectAttributes(t *testing.T) {
	type args struct {
		attrs  map[s3response.ObjectAttributes]struct{}
		output s3response.GetObjectAttributesResponse
	}

	etag, objSize := "etag", int64(3222)
	delMarker := true

	tests := []struct {
		name string
		args args
		want s3response.GetObjectAttributesResponse
	}{
		{
			name: "keep only ETag",
			args: args{
				attrs: map[s3response.ObjectAttributes]struct{}{
					s3response.ObjectAttributesEtag: {},
				},
				output: s3response.GetObjectAttributesResponse{
					ObjectSize: &objSize,
					ETag:       &etag,
				},
			},
			want: s3response.GetObjectAttributesResponse{ETag: &etag},
		},
		{
			name: "keep multiple props",
			args: args{
				attrs: map[s3response.ObjectAttributes]struct{}{
					s3response.ObjectAttributesEtag:         {},
					s3response.ObjectAttributesObjectSize:   {},
					s3response.ObjectAttributesStorageClass: {},
				},
				output: s3response.GetObjectAttributesResponse{
					ObjectSize:  &objSize,
					ETag:        &etag,
					ObjectParts: &s3response.ObjectParts{},
					VersionId:   &etag,
				},
			},
			want: s3response.GetObjectAttributesResponse{
				ETag:       &etag,
				ObjectSize: &objSize,
			},
		},
		{
			name: "make sure LastModified, DeleteMarker and VersionId are removed",
			args: args{
				attrs: map[s3response.ObjectAttributes]struct{}{
					s3response.ObjectAttributesEtag: {},
				},
				output: s3response.GetObjectAttributesResponse{
					ObjectSize:   &objSize,
					ETag:         &etag,
					ObjectParts:  &s3response.ObjectParts{},
					VersionId:    &etag,
					LastModified: backend.GetTimePtr(time.Now()),
					DeleteMarker: &delMarker,
				},
			},
			want: s3response.GetObjectAttributesResponse{
				ETag: &etag,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterObjectAttributes(tt.args.attrs, tt.args.output); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterObjectAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidOwnership(t *testing.T) {
	type args struct {
		val types.ObjectOwnership
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid-BucketOwnerEnforced",
			args: args{
				val: types.ObjectOwnershipBucketOwnerEnforced,
			},
			want: true,
		},
		{
			name: "valid-BucketOwnerPreferred",
			args: args{
				val: types.ObjectOwnershipBucketOwnerPreferred,
			},
			want: true,
		},
		{
			name: "valid-ObjectWriter",
			args: args{
				val: types.ObjectOwnershipObjectWriter,
			},
			want: true,
		},
		{
			name: "invalid_value",
			args: args{
				val: types.ObjectOwnership("invalid_value"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidOwnership(tt.args.val); got != tt.want {
				t.Errorf("IsValidOwnership() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsChecksumAlgorithmValid(t *testing.T) {
	type args struct {
		alg types.ChecksumAlgorithm
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				alg: "",
			},
			wantErr: false,
		},
		{
			name: "crc32",
			args: args{
				alg: types.ChecksumAlgorithmCrc32,
			},
			wantErr: false,
		},
		{
			name: "crc32c",
			args: args{
				alg: types.ChecksumAlgorithmCrc32c,
			},
			wantErr: false,
		},
		{
			name: "sha1",
			args: args{
				alg: types.ChecksumAlgorithmSha1,
			},
			wantErr: false,
		},
		{
			name: "sha256",
			args: args{
				alg: types.ChecksumAlgorithmSha256,
			},
			wantErr: false,
		},
		{
			name: "crc64nvme",
			args: args{
				alg: types.ChecksumAlgorithmCrc64nvme,
			},
			wantErr: false,
		},
		{
			name: "invalid",
			args: args{
				alg: types.ChecksumAlgorithm("invalid_checksum_algorithm"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsChecksumAlgorithmValid(tt.args.alg); (err != nil) != tt.wantErr {
				t.Errorf("IsChecksumAlgorithmValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidChecksum(t *testing.T) {
	type args struct {
		checksum  string
		algorithm types.ChecksumAlgorithm
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "invalid-base64",
			args: args{
				checksum:  "invalid_base64_string",
				algorithm: types.ChecksumAlgorithmCrc32,
			},
			want: false,
		},
		{
			name: "invalid-crc32",
			args: args{
				checksum:  "YXNkZmFzZGZhc2Rm",
				algorithm: types.ChecksumAlgorithmCrc32,
			},
			want: false,
		},
		{
			name: "valid-crc32",
			args: args{
				checksum:  "ww2FVQ==",
				algorithm: types.ChecksumAlgorithmCrc32,
			},
			want: true,
		},
		{
			name: "invalid-crc32c",
			args: args{
				checksum:  "Zmdoa2doZmtnZmhr",
				algorithm: types.ChecksumAlgorithmCrc32c,
			},
			want: false,
		},
		{
			name: "valid-crc32c",
			args: args{
				checksum:  "DOsb4w==",
				algorithm: types.ChecksumAlgorithmCrc32c,
			},
			want: true,
		},
		{
			name: "invalid-sha1",
			args: args{
				checksum:  "YXNkZmFzZGZhc2RmYXNkZnNhZGZzYWRm",
				algorithm: types.ChecksumAlgorithmSha1,
			},
			want: false,
		},
		{
			name: "valid-sha1",
			args: args{
				checksum:  "L4q6V59Zcwn12wyLIytoE2c1ugk=",
				algorithm: types.ChecksumAlgorithmSha1,
			},
			want: true,
		},
		{
			name: "invalid-sha256",
			args: args{
				checksum:  "Zmdoa2doZmtnZmhrYXNkZmFzZGZhc2RmZHNmYXNkZg==",
				algorithm: types.ChecksumAlgorithmSha256,
			},
			want: false,
		},
		{
			name: "valid-sha256",
			args: args{
				checksum:  "d1SPCd/kZ2rAzbbLUC0n/bEaOSx70FNbXbIqoIxKuPY=",
				algorithm: types.ChecksumAlgorithmSha256,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidChecksum(tt.args.checksum, tt.args.algorithm); got != tt.want {
				t.Errorf("IsValidChecksum() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsChecksumTypeValid(t *testing.T) {
	type args struct {
		t types.ChecksumType
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid_FULL_OBJECT",
			args: args{
				t: types.ChecksumTypeFullObject,
			},
			wantErr: false,
		},
		{
			name: "valid_COMPOSITE",
			args: args{
				t: types.ChecksumTypeComposite,
			},
			wantErr: false,
		},
		{
			name: "invalid",
			args: args{
				t: types.ChecksumType("invalid_checksum_type"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsChecksumTypeValid(tt.args.t); (err != nil) != tt.wantErr {
				t.Errorf("IsChecksumTypeValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_checkChecksumTypeAndAlgo(t *testing.T) {
	type args struct {
		algo types.ChecksumAlgorithm
		t    types.ChecksumType
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "full_object-crc32",
			args: args{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeFullObject,
			},
			wantErr: false,
		},
		{
			name: "full_object-crc32c",
			args: args{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			wantErr: false,
		},
		{
			name: "full_object-sha1",
			args: args{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeFullObject,
			},
			wantErr: true,
		},
		{
			name: "full_object-sha256",
			args: args{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeFullObject,
			},
			wantErr: true,
		},
		{
			name: "full_object-crc64nvme",
			args: args{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
			wantErr: false,
		},
		{
			name: "full_object-crc32",
			args: args{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeFullObject,
			},
			wantErr: false,
		},
		{
			name: "composite-crc32",
			args: args{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			wantErr: false,
		},
		{
			name: "composite-crc32c",
			args: args{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeComposite,
			},
			wantErr: false,
		},
		{
			name: "composite-sha1",
			args: args{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			wantErr: false,
		},
		{
			name: "composite-sha256",
			args: args{
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			wantErr: false,
		},
		{
			name: "composite-crc64nvme",
			args: args{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeComposite,
			},
			wantErr: true,
		},
		{
			name: "composite-empty",
			args: args{
				t: types.ChecksumTypeComposite,
			},
			wantErr: true,
		},
		{
			name: "full_object-empty",
			args: args{
				t: types.ChecksumTypeFullObject,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkChecksumTypeAndAlgo(tt.args.algo, tt.args.t); (err != nil) != tt.wantErr {
				t.Errorf("checkChecksumTypeAndAlgo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseTagging(t *testing.T) {
	genRandStr := func(lgth int) string {
		b := make([]byte, lgth)
		for i := range b {
			b[i] = byte(rand.Intn(95) + 32) // 126 - 32 + 1 = 95 printable characters
		}
		return string(b)
	}
	getTagSet := func(lgth int) s3response.TaggingInput {
		res := s3response.TaggingInput{
			TagSet: s3response.TagSet{
				Tags: []s3response.Tag{},
			},
		}

		for i := 0; i < lgth; i++ {
			res.TagSet.Tags = append(res.TagSet.Tags, s3response.Tag{
				Key:   genRandStr(10),
				Value: genRandStr(20),
			})
		}

		return res
	}
	type args struct {
		data        s3response.TaggingInput
		overrideXML []byte
		limit       TagLimit
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr error
	}{
		{
			name: "valid tags within limit",
			args: args{
				data: s3response.TaggingInput{
					TagSet: s3response.TagSet{
						Tags: []s3response.Tag{
							{Key: "key1", Value: "value1"},
							{Key: "key2", Value: "value2"},
						},
					},
				},
				limit: TagLimitObject,
			},
			want:    map[string]string{"key1": "value1", "key2": "value2"},
			wantErr: nil,
		},
		{
			name: "malformed XML",
			args: args{
				overrideXML: []byte("invalid xml"),
				limit:       TagLimitObject,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrMalformedXML),
		},
		{
			name: "exceeds bucket tag limit",
			args: args{
				data:  getTagSet(51),
				limit: TagLimitBucket,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrBucketTaggingLimited),
		},
		{
			name: "exceeds object tag limit",
			args: args{
				data:  getTagSet(11),
				limit: TagLimitObject,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrObjectTaggingLimited),
		},
		{
			name: "invalid 0 length tag key",
			args: args{
				data: s3response.TaggingInput{
					TagSet: s3response.TagSet{
						Tags: []s3response.Tag{{Key: "", Value: "value1"}},
					},
				},
				limit: TagLimitObject,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrInvalidTagKey),
		},
		{
			name: "invalid long tag key",
			args: args{
				data: s3response.TaggingInput{
					TagSet: s3response.TagSet{
						Tags: []s3response.Tag{{Key: genRandStr(130), Value: "value1"}},
					},
				},
				limit: TagLimitObject,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrInvalidTagKey),
		},
		{
			name: "invalid long tag value",
			args: args{
				data: s3response.TaggingInput{
					TagSet: s3response.TagSet{
						Tags: []s3response.Tag{{Key: "key", Value: genRandStr(257)}},
					},
				},
				limit: TagLimitBucket,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrInvalidTagValue),
		},
		{
			name: "duplicate tag key",
			args: args{
				data: s3response.TaggingInput{
					TagSet: s3response.TagSet{
						Tags: []s3response.Tag{
							{Key: "key", Value: "value1"},
							{Key: "key", Value: "value2"},
						},
					},
				},
				limit: TagLimitObject,
			},
			want:    nil,
			wantErr: s3err.GetAPIError(s3err.ErrDuplicateTagKey),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data []byte
			if tt.args.overrideXML != nil {
				data = tt.args.overrideXML
			} else {
				var err error
				data, err = xml.Marshal(tt.args.data)
				if err != nil {
					t.Fatalf("error marshalling input: %v", err)
				}
			}
			got, err := ParseTagging(data, tt.args.limit)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected result %v, got %v", tt.want, got)
			}
		})
	}
}
