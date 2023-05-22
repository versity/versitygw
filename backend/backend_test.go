package backend

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/scoutgw/s3err"
)

func TestBackend_ListBuckets(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	type test struct {
		name    string
		c       Backend
		args    args
		wantErr bool
	}
	var tests []test
	tests = append(tests, test{
		name: "list-Bucket",
		c: &BackendMock{
			ListBucketsFunc: func() (*s3.ListBucketsOutput, error) {
				return &s3.ListBucketsOutput{
					Buckets: []types.Bucket{
						{
							Name: aws.String("t1"),
						},
					},
				}, s3err.GetAPIError(0)
			},
		},
		args: args{
			ctx: context.Background(),
		},
		wantErr: false,
	}, test{
		name: "list-Bucket-error",
		c: &BackendMock{
			ListBucketsFunc: func() (*s3.ListBucketsOutput, error) {
				return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
			},
		},
		args: args{
			ctx: context.Background(),
		},
		wantErr: true,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.c.ListBuckets(); (err.(s3err.APIError).Code != "") != tt.wantErr {
				t.Errorf("Backend.ListBuckets() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestBackend_HeadBucket(t *testing.T) {
	type args struct {
		ctx        context.Context
		BucketName string
	}
	type test struct {
		name    string
		c       Backend
		args    args
		wantErr bool
	}
	var tests []test
	tests = append(tests, test{
		name: "head-buckets-error",
		c: &BackendMock{
			HeadBucketFunc: func(bucket string) (*s3.HeadBucketOutput, error) {
				return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
			},
		},
		args: args{
			ctx:        context.Background(),
			BucketName: "b1",
		},
		wantErr: true,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.c.HeadBucket(tt.args.BucketName); (err.(s3err.APIError).Code != "") != tt.wantErr {
				t.Errorf("Backend.HeadBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestBackend_GetBucketAcl(t *testing.T) {
	type args struct {
		ctx        context.Context
		bucketName string
	}
	type test struct {
		name    string
		c       Backend
		args    args
		wantErr bool
	}
	var tests []test
	tests = append(tests, test{
		name: "get bucket acl error",
		c: &BackendMock{
			GetBucketAclFunc: func(bucket string) (*s3.GetBucketAclOutput, error) {
				return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
			},
		},
		args: args{
			ctx:        context.Background(),
			bucketName: "b1",
		},
		wantErr: true,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.c.GetBucketAcl(tt.args.bucketName); (err.(s3err.APIError).Code != "") != tt.wantErr {
				t.Errorf("Backend.GetBucketAcl() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestBackend_PutBucket(t *testing.T) {
	type args struct {
		ctx        context.Context
		bucketName string
	}
	type test struct {
		name    string
		c       Backend
		args    args
		wantErr bool
	}
	var tests []test
	tests = append(tests, test{
		name: "put bucket ",
		c: &BackendMock{
			PutBucketFunc: func(bucket string) error {
				return s3err.GetAPIError(0)
			},
		},
		args: args{
			ctx:        context.Background(),
			bucketName: "b1",
		},
		wantErr: false,
	}, test{
		name: "put bucket error",
		c: &BackendMock{
			PutBucketFunc: func(bucket string) error {
				return s3err.GetAPIError(s3err.ErrNotImplemented)
			},
		},
		args: args{
			ctx:        context.Background(),
			bucketName: "b2",
		},
		wantErr: true,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.PutBucket(tt.args.bucketName); (err.(s3err.APIError).Code != "") != tt.wantErr {
				t.Errorf("Backend.PutBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestBackend_DeleteBucket(t *testing.T) {
	type args struct {
		ctx        context.Context
		bucketName string
	}
	type test struct {
		name    string
		c       Backend
		args    args
		wantErr bool
	}
	var tests []test
	tests = append(tests, test{
		name: "Delete Bucket Error",
		c: &BackendMock{
			DeleteBucketFunc: func(bucket string) error {
				return s3err.GetAPIError(s3err.ErrNotImplemented)
			},
		},
		args: args{
			ctx:        context.Background(),
			bucketName: "b1",
		},
		wantErr: true,
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteBucket(tt.args.bucketName); (err.(s3err.APIError).Code != "") != tt.wantErr {
				t.Errorf("Backend.DeleteBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
