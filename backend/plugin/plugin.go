// Copyright 2025 Versity Software
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

package vgwplugin

import (
	"bufio"
	"context"
	"fmt"
	"plugin"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// The plugin backend is used to dynamically load a Go plugin at runtime.
// It loads the plugin and calls the InitPlugin function to initialize it.
// A config string option is passed to init the plugin, it is expected that the
// plugin will handle its own configuration and initialization from this.
// If the plugin cannot be loaded or initialized, it returns an error.
// The InitPlugin function should be defined in the plugin and should have
// the signature func(configfile string) (version int, err error).
// The plugin should also implement the backend.Backend interface functions.
// However, the plugin does not need to implement all functions of the
// backend.Backend interface. It can implement only the functions it needs.
// Any non-implemented functions will return an error indicating that
// the function is not implemented.
// The plugin file should be compiled with the same Go version as the
// application using it. The plugin file should be built with the
// -buildmode=plugin flag.
// Example: go build -buildmode=plugin -o myplugin.so myplugin.go
// See the following for caveats and details:
// https://pkg.go.dev/plugin#hdr-Warnings

// PluginBackend implements the backend.Backend interface using Go plugins.
type PluginBackend struct {
	p *plugin.Plugin
}

// NewPluginBackend creates a new PluginBackend. The path parameter should
// point to the compiled plugin file (e.g., .so file).
func NewPluginBackend(path, config string) (*PluginBackend, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}

	initSymbol, err := p.Lookup("InitPlugin")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup InitPlugin symbol: %w", err)
	}

	initFunc, ok := initSymbol.(func(string) (int, error))
	if !ok {
		return nil, fmt.Errorf("InitPlugin symbol is not a func() (int, error)")
	}

	version, err := initFunc(config)
	if err != nil {
		return nil, fmt.Errorf("InitPlugin failed: %w", err)
	}

	if version != backend.InterfaceVersion {
		return nil, fmt.Errorf("plugin interface version mismatch: gateway %v, plugin %v",
			backend.InterfaceVersion, version)
	}

	return &PluginBackend{p: p}, nil
}

func (p *PluginBackend) callPluginFunc(name string, args []any) ([]reflect.Value, error) {
	symbol, err := p.p.Lookup(name)
	if err != nil {
		return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
	}

	symbolValue := reflect.ValueOf(symbol)
	if symbolValue.Kind() != reflect.Func {
		return nil, fmt.Errorf("symbol %s is not a function", name)
	}

	numIn := symbolValue.Type().NumIn()
	if len(args) != numIn {
		return nil, fmt.Errorf("incorrect number of arguments for function %s, expected %d, got %d", name, numIn, len(args))
	}

	in := make([]reflect.Value, len(args))
	for i := range args {
		in[i] = reflect.ValueOf(args[i])
	}

	return symbolValue.Call(in), nil
}

func (p *PluginBackend) String() string { return "Plugin Gateway" }
func (p *PluginBackend) Shutdown()      {}

func (p *PluginBackend) ListBuckets(ctx context.Context, input s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
	results, err := p.callPluginFunc("ListBuckets", []any{ctx, input})
	if err != nil {
		return s3response.ListAllMyBucketsResult{}, err
	}

	return results[0].Interface().(s3response.ListAllMyBucketsResult), convertError(results[1])
}

func (p *PluginBackend) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	results, err := p.callPluginFunc("HeadBucket", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.HeadBucketOutput), convertError(results[1])
}

func (p *PluginBackend) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	results, err := p.callPluginFunc("GetBucketAcl", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().([]byte), convertError(results[1])
}

func (p *PluginBackend) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, defaultACL []byte) error {
	_, err := p.callPluginFunc("CreateBucket", []any{ctx, input, defaultACL})
	return err
}

func (p *PluginBackend) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	_, err := p.callPluginFunc("PutBucketAcl", []any{ctx, bucket, data})
	return err
}

func (p *PluginBackend) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := p.callPluginFunc("DeleteBucket", []any{ctx, bucket})
	return err
}

func (p *PluginBackend) PutBucketVersioning(ctx context.Context, bucket string, status types.BucketVersioningStatus) error {
	_, err := p.callPluginFunc("PutBucketVersioning", []any{ctx, bucket, status})
	return err
}

func (p *PluginBackend) GetBucketVersioning(ctx context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
	results, err := p.callPluginFunc("GetBucketVersioning", []any{ctx, bucket})
	if err != nil {
		return s3response.GetBucketVersioningOutput{}, err
	}

	return results[0].Interface().(s3response.GetBucketVersioningOutput), convertError(results[1])
}

func (p *PluginBackend) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	_, err := p.callPluginFunc("PutBucketPolicy", []any{ctx, bucket, policy})
	return err
}

func (p *PluginBackend) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	results, err := p.callPluginFunc("GetBucketPolicy", []any{ctx, bucket})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().([]byte), convertError(results[1])
}

func (p *PluginBackend) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	_, err := p.callPluginFunc("DeleteBucketPolicy", []any{ctx, bucket})
	return err
}

func (p *PluginBackend) PutBucketOwnershipControls(ctx context.Context, bucket string, ownership types.ObjectOwnership) error {
	_, err := p.callPluginFunc("PutBucketOwnershipControls", []any{ctx, bucket, ownership})
	return err
}

func (p *PluginBackend) GetBucketOwnershipControls(ctx context.Context, bucket string) (types.ObjectOwnership, error) {
	results, err := p.callPluginFunc("GetBucketOwnershipControls", []any{ctx, bucket})
	if err != nil {
		return "", err
	}

	return results[0].Interface().(types.ObjectOwnership), convertError(results[1])
}

func (p *PluginBackend) DeleteBucketOwnershipControls(ctx context.Context, bucket string) error {
	_, err := p.callPluginFunc("DeleteBucketOwnershipControls", []any{ctx, bucket})
	return err
}

func (p *PluginBackend) PutBucketCors(ctx context.Context, data []byte) error {
	_, err := p.callPluginFunc("PutBucketCors", []any{ctx, data})
	return err
}

func (p *PluginBackend) GetBucketCors(ctx context.Context, bucket string) ([]byte, error) {
	results, err := p.callPluginFunc("GetBucketCors", []any{ctx, bucket})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().([]byte), convertError(results[1])
}

func (p *PluginBackend) DeleteBucketCors(ctx context.Context, bucket string) error {
	_, err := p.callPluginFunc("DeleteBucketCors", []any{ctx, bucket})
	return err
}

func (p *PluginBackend) CreateMultipartUpload(ctx context.Context, input s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	results, err := p.callPluginFunc("CreateMultipartUpload", []any{ctx, input})
	if err != nil {
		return s3response.InitiateMultipartUploadResult{}, err
	}

	return results[0].Interface().(s3response.InitiateMultipartUploadResult), convertError(results[1])
}

func (p *PluginBackend) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	results, err := p.callPluginFunc("CompleteMultipartUpload", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.CompleteMultipartUploadOutput), convertError(results[1])
}

func (p *PluginBackend) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	_, err := p.callPluginFunc("AbortMultipartUpload", []any{ctx, input})
	return err
}

func (p *PluginBackend) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	results, err := p.callPluginFunc("ListMultipartUploads", []any{ctx, input})
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, err
	}

	return results[0].Interface().(s3response.ListMultipartUploadsResult), convertError(results[1])
}

func (p *PluginBackend) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	results, err := p.callPluginFunc("ListParts", []any{ctx, input})
	if err != nil {
		return s3response.ListPartsResult{}, err
	}

	return results[0].Interface().(s3response.ListPartsResult), convertError(results[1])
}

func (p *PluginBackend) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	results, err := p.callPluginFunc("UploadPart", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.UploadPartOutput), convertError(results[1])
}

func (p *PluginBackend) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	results, err := p.callPluginFunc("UploadPartCopy", []any{ctx, input})
	if err != nil {
		return s3response.CopyPartResult{}, err
	}

	return results[0].Interface().(s3response.CopyPartResult), convertError(results[1])
}

func (p *PluginBackend) PutObject(ctx context.Context, input s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	results, err := p.callPluginFunc("PutObject", []any{ctx, input})
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}

	return results[0].Interface().(s3response.PutObjectOutput), convertError(results[1])
}

func (p *PluginBackend) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	results, err := p.callPluginFunc("HeadObject", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.HeadObjectOutput), convertError(results[1])
}

func (p *PluginBackend) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	results, err := p.callPluginFunc("GetObject", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.GetObjectOutput), convertError(results[1])
}

func (p *PluginBackend) GetObjectAcl(ctx context.Context, input *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	results, err := p.callPluginFunc("GetObjectAcl", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.GetObjectAclOutput), convertError(results[1])
}

func (p *PluginBackend) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
	results, err := p.callPluginFunc("GetObjectAttributes", []any{ctx, input})
	if err != nil {
		return s3response.GetObjectAttributesResponse{}, err
	}

	return results[0].Interface().(s3response.GetObjectAttributesResponse), convertError(results[1])
}

func (p *PluginBackend) CopyObject(ctx context.Context, input s3response.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	results, err := p.callPluginFunc("CopyObject", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.CopyObjectOutput), convertError(results[1])
}

func (p *PluginBackend) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	results, err := p.callPluginFunc("ListObjects", []any{ctx, input})
	if err != nil {
		return s3response.ListObjectsResult{}, err
	}

	return results[0].Interface().(s3response.ListObjectsResult), convertError(results[1])
}

func (p *PluginBackend) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	results, err := p.callPluginFunc("ListObjectsV2", []any{ctx, input})
	if err != nil {
		return s3response.ListObjectsV2Result{}, err
	}

	return results[0].Interface().(s3response.ListObjectsV2Result), convertError(results[1])
}

func (p *PluginBackend) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	results, err := p.callPluginFunc("DeleteObject", []any{ctx, input})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(*s3.DeleteObjectOutput), convertError(results[1])
}

func (p *PluginBackend) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	results, err := p.callPluginFunc("DeleteObjects", []any{ctx, input})
	if err != nil {
		return s3response.DeleteResult{}, err
	}

	return results[0].Interface().(s3response.DeleteResult), convertError(results[1])
}

func (p *PluginBackend) PutObjectAcl(ctx context.Context, input *s3.PutObjectAclInput) error {
	_, err := p.callPluginFunc("PutObjectAcl", []any{ctx, input})
	return err
}

func (p *PluginBackend) ListObjectVersions(ctx context.Context, input *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
	results, err := p.callPluginFunc("ListObjectVersions", []any{ctx, input})
	if err != nil {
		return s3response.ListVersionsResult{}, err
	}

	return results[0].Interface().(s3response.ListVersionsResult), convertError(results[1])
}

func (p *PluginBackend) RestoreObject(ctx context.Context, input *s3.RestoreObjectInput) error {
	_, err := p.callPluginFunc("RestoreObject", []any{ctx, input})
	return err
}

func (p *PluginBackend) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) func(w *bufio.Writer) {
	results, err := p.callPluginFunc("SelectObjectContent", []any{ctx, input})
	if err != nil {
		return func(w *bufio.Writer) {}
	}

	return results[0].Interface().(func(w *bufio.Writer))
}

func (p *PluginBackend) GetBucketTagging(ctx context.Context, bucket string) (map[string]string, error) {
	results, err := p.callPluginFunc("GetBucketTagging", []any{ctx, bucket})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(map[string]string), convertError(results[1])
}

func (p *PluginBackend) PutBucketTagging(ctx context.Context, bucket string, tags map[string]string) error {
	_, err := p.callPluginFunc("PutBucketTagging", []any{ctx, bucket, tags})
	return err
}

func (p *PluginBackend) DeleteBucketTagging(ctx context.Context, bucket string) error {
	_, err := p.callPluginFunc("DeleteBucketTagging", []any{ctx, bucket})
	return err
}

func (p *PluginBackend) GetObjectTagging(ctx context.Context, bucket, object string) (map[string]string, error) {
	results, err := p.callPluginFunc("GetObjectTagging", []any{ctx, bucket, object})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().(map[string]string), convertError(results[1])
}

func (p *PluginBackend) PutObjectTagging(ctx context.Context, bucket, object string, tags map[string]string) error {
	_, err := p.callPluginFunc("PutObjectTagging", []any{ctx, bucket, object, tags})
	return err
}

func (p *PluginBackend) DeleteObjectTagging(ctx context.Context, bucket, object string) error {
	_, err := p.callPluginFunc("DeleteObjectTagging", []any{ctx, bucket, object})
	return err
}

func (p *PluginBackend) PutObjectLockConfiguration(ctx context.Context, bucket string, config []byte) error {
	_, err := p.callPluginFunc("PutObjectLockConfiguration", []any{ctx, bucket, config})
	return err
}

func (p *PluginBackend) GetObjectLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	results, err := p.callPluginFunc("GetObjectLockConfiguration", []any{ctx, bucket})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().([]byte), convertError(results[1])
}

func (p *PluginBackend) PutObjectRetention(ctx context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
	_, err := p.callPluginFunc("PutObjectRetention", []any{ctx, bucket, object, versionId, bypass, retention})
	return err
}

func (p *PluginBackend) GetObjectRetention(ctx context.Context, bucket, object, versionId string) ([]byte, error) {
	results, err := p.callPluginFunc("GetObjectRetention", []any{ctx, bucket, object, versionId})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().([]byte), convertError(results[1])
}

func (p *PluginBackend) PutObjectLegalHold(ctx context.Context, bucket, object, versionId string, status bool) error {
	_, err := p.callPluginFunc("PutObjectLegalHold", []any{ctx, bucket, object, versionId, status})
	return err
}

func (p *PluginBackend) GetObjectLegalHold(ctx context.Context, bucket, object, versionId string) (*bool, error) {
	results, err := p.callPluginFunc("GetObjectLegalHold", []any{ctx, bucket, object, versionId})
	if err != nil {
		return nil, err
	}

	val := results[0].Interface()

	if val == nil {
		return nil, convertError(results[1])
	}

	return val.(*bool), convertError(results[1])
}

func (p *PluginBackend) ChangeBucketOwner(ctx context.Context, bucket string, acl []byte) error {
	_, err := p.callPluginFunc("ChangeBucketOwner", []any{ctx, bucket, acl})
	return err
}

func (p *PluginBackend) ListBucketsAndOwners(ctx context.Context) ([]s3response.Bucket, error) {
	results, err := p.callPluginFunc("ListBucketsAndOwners", []any{ctx})
	if err != nil {
		return nil, err
	}

	return results[0].Interface().([]s3response.Bucket), convertError(results[1])
}

func convertError(result reflect.Value) error {
	if result.IsNil() {
		return nil
	}

	err, ok := result.Interface().(error)
	if !ok {
		return fmt.Errorf("expected error, got %T", result.Interface())
	}

	return err
}

var _ backend.Backend = &PluginBackend{}
