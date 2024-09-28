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
	"context"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
)

type S3Conf struct {
	awsID             string
	awsSecret         string
	awsRegion         string
	endpoint          string
	PartSize          int64
	Concurrency       int
	checksumDisable   bool
	pathStyle         bool
	debug             bool
	versioningEnabled bool
	azureTests        bool
}

func NewS3Conf(opts ...Option) *S3Conf {
	s := &S3Conf{}

	for _, opt := range opts {
		opt(s)
	}
	return s
}

type Option func(*S3Conf)

func WithAccess(ak string) Option {
	return func(s *S3Conf) { s.awsID = ak }
}
func WithSecret(sk string) Option {
	return func(s *S3Conf) { s.awsSecret = sk }
}
func WithRegion(r string) Option {
	return func(s *S3Conf) { s.awsRegion = r }
}
func WithEndpoint(e string) Option {
	return func(s *S3Conf) { s.endpoint = e }
}
func WithDisableChecksum() Option {
	return func(s *S3Conf) { s.checksumDisable = true }
}
func WithPathStyle() Option {
	return func(s *S3Conf) { s.pathStyle = true }
}
func WithPartSize(p int64) Option {
	return func(s *S3Conf) { s.PartSize = p }
}
func WithConcurrency(c int) Option {
	return func(s *S3Conf) { s.Concurrency = c }
}
func WithDebug() Option {
	return func(s *S3Conf) { s.debug = true }
}
func WithVersioningEnabled() Option {
	return func(s *S3Conf) { s.versioningEnabled = true }
}
func WithAzureMode() Option {
	return func(s *S3Conf) { s.azureTests = true }
}

func (c *S3Conf) getCreds() credentials.StaticCredentialsProvider {
	// TODO support token/IAM
	if c.awsSecret == "" {
		c.awsSecret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if c.awsSecret == "" {
		log.Fatal("no AWS_SECRET_ACCESS_KEY found")
	}

	return credentials.NewStaticCredentialsProvider(c.awsID, c.awsSecret, "")
}

func (c *S3Conf) GetClient() *s3.Client {
	return s3.NewFromConfig(c.Config())
}

func (c *S3Conf) Config() aws.Config {
	creds := c.getCreds()

	tr := &http.Transport{}
	client := &http.Client{Transport: tr}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(c.awsRegion),
		config.WithCredentialsProvider(creds),
		config.WithHTTPClient(client),
	}

	if c.checksumDisable {
		opts = append(opts,
			config.WithAPIOptions([]func(*middleware.Stack) error{v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware}))
	}

	if c.debug {
		opts = append(opts,
			config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogResponse|aws.LogRequestEventMessage|aws.LogResponseEventMessage))
	}

	cfg, err := config.LoadDefaultConfig(
		context.TODO(), opts...)
	if err != nil {
		log.Fatalln("error:", err)
	}

	if c.endpoint != "" && c.endpoint != "aws" {
		cfg.BaseEndpoint = &c.endpoint
	}

	return cfg
}

func (c *S3Conf) UploadData(r io.Reader, bucket, object string) error {
	uploader := manager.NewUploader(c.GetClient())
	uploader.PartSize = c.PartSize
	uploader.Concurrency = c.Concurrency

	upinfo := &s3.PutObjectInput{
		Body:   r,
		Bucket: &bucket,
		Key:    &object,
	}

	_, err := uploader.Upload(context.Background(), upinfo)
	return err
}

func (c *S3Conf) DownloadData(w io.WriterAt, bucket, object string) (int64, error) {
	downloader := manager.NewDownloader(c.GetClient())
	downloader.PartSize = c.PartSize
	downloader.Concurrency = c.Concurrency

	downinfo := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &object,
	}

	return downloader.Download(context.Background(), w, downinfo)
}
