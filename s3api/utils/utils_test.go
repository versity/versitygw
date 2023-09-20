package utils

import (
	"bytes"
	"net/http"
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
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
	}{
		{
			name: "Success-response",
			args: args{
				ctx: ctx,
			},
			want:    request,
			wantErr: false,
		},
		{
			name: "Success-response-With-Headers",
			args: args{
				ctx: ctx2,
			},
			want:    request2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateHttpRequestFromCtx(tt.args.ctx, []string{"X-Amz-Mfa"})
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

	// Case 2
	ctx2 := app.AcquireCtx(&fasthttp.RequestCtx{})
	req2 := ctx2.Request()

	req2.Header.Add("X-Amz-Meta-Name", "Nick")
	req2.Header.Add("X-Amz-Meta-Age", "27")

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
		{
			name: "Success-non-empty-response",
			args: args{
				headers: &req2.Header,
			},
			wantMetadata: map[string]string{
				"Age":  "27",
				"Name": "Nick",
			},
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
