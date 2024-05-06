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
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
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
		attrs  map[types.ObjectAttributes]struct{}
		output s3response.GetObjectAttributesResult
	}
	etag, objSize := "etag", int64(3222)
	tests := []struct {
		name string
		args args
		want s3response.GetObjectAttributesResult
	}{
		{
			name: "keep only ETag",
			args: args{
				attrs: map[types.ObjectAttributes]struct{}{
					types.ObjectAttributesEtag: {},
				},
				output: s3response.GetObjectAttributesResult{
					ObjectSize: &objSize,
					ETag:       &etag,
				},
			},
			want: s3response.GetObjectAttributesResult{ETag: &etag},
		},
		{
			name: "keep multiple props",
			args: args{
				attrs: map[types.ObjectAttributes]struct{}{
					types.ObjectAttributesEtag:         {},
					types.ObjectAttributesObjectSize:   {},
					types.ObjectAttributesStorageClass: {},
				},
				output: s3response.GetObjectAttributesResult{
					ObjectSize:  &objSize,
					ETag:        &etag,
					ObjectParts: &s3response.ObjectParts{},
					VersionId:   &etag,
				},
			},
			want: s3response.GetObjectAttributesResult{
				ETag:       &etag,
				ObjectSize: &objSize,
				VersionId:  &etag,
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
