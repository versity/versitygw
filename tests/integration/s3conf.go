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
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
)

type S3Conf struct {
	awsID             string
	awsSecret         string
	awsRegion         string
	endpoint          string
	hostStyle         bool
	checksumDisable   bool
	PartSize          int64
	Concurrency       int
	debug             bool
	versioningEnabled bool
	azureTests        bool
	tlsStatus         bool
	httpClient        *http.Client
}

func NewS3Conf(opts ...Option) *S3Conf {
	s := &S3Conf{}

	for _, opt := range opts {
		opt(s)
	}

	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tlsStatus,
		},
	}

	customHTTPClient := &http.Client{
		Transport: customTransport,
		Timeout:   shortTimeout,
	}

	s.httpClient = customHTTPClient

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
func WithHostStyle() Option {
	return func(s *S3Conf) { s.hostStyle = true }
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
func WithTLSStatus(ts bool) Option {
	return func(s *S3Conf) { s.tlsStatus = ts }
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
	return s3.NewFromConfig(c.Config(), func(o *s3.Options) {
		if c.hostStyle {
			o.BaseEndpoint = &c.endpoint
			o.UsePathStyle = false
		}
	})
}

func (c *S3Conf) GetPresignClient() *s3.PresignClient {
	return s3.NewPresignClient(c.GetClient())
}

func (c *S3Conf) GetAnonymousClient() *s3.Client {
	cfg := c.Config()
	cfg.Credentials = aws.AnonymousCredentials{}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if c.hostStyle {
			o.BaseEndpoint = &c.endpoint
			o.UsePathStyle = false
		}
	})
}

func (cfg *S3Conf) getUserClient(usr user) *s3.Client {
	config := *cfg
	config.awsID = usr.access
	config.awsSecret = usr.secret

	return config.GetClient()
}

func (c *S3Conf) Config() aws.Config {
	creds := c.getCreds()

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(c.awsRegion),
		config.WithCredentialsProvider(creds),
		config.WithHTTPClient(c.httpClient),
		config.WithRetryMaxAttempts(1),
	}

	opts = append(opts, config.WithHTTPClient(c.httpClient))

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
	uploader := transfermanager.New(c.GetClient(),
		func(options *transfermanager.Options) {
			options.PartSizeBytes = c.PartSize
			options.Concurrency = c.Concurrency
		})

	upinfo := &transfermanager.UploadObjectInput{
		Body:   r,
		Bucket: &bucket,
		Key:    &object,
	}

	_, err := uploader.UploadObject(context.Background(), upinfo)
	return err
}

func (c *S3Conf) DownloadData(w io.WriterAt, bucket, object string) (int64, error) {
	downloader := transfermanager.New(c.GetClient(),
		func(options *transfermanager.Options) {
			options.PartSizeBytes = c.PartSize
			options.Concurrency = c.Concurrency
		})

	downinfo := &transfermanager.DownloadObjectInput{
		Bucket:   &bucket,
		Key:      &object,
		WriterAt: w,
	}

	out, err := downloader.DownloadObject(context.Background(), downinfo)
	if err != nil {
		return 0, err
	}

	return *out.ContentLength, nil
}

func (c *S3Conf) getAdminCommand(args ...string) []string {
	if c.tlsStatus {
		return append([]string{"admin", "--allow-insecure"}, args...)
	}

	return append([]string{"admin"}, args...)
}
