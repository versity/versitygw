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

package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/s3proxy"
)

var (
	s3proxyAccess          string
	s3proxySecret          string
	s3proxyEndpoint        string
	s3proxyRegion          string
	s3proxyMetaBucket      string
	s3proxyDisableChecksum bool
	s3proxySslSkipVerify   bool
	s3proxyUsePathStyle    bool
	s3proxyDebug           bool
)

func s3Command() *cli.Command {
	return &cli.Command{
		Name:  "s3",
		Usage: "s3 storage backend",
		Description: `This runs the gateway like an s3 proxy redirecting requests
to an s3 storage backend service.`,
		Action: runS3,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "access",
				Usage:       "s3 proxy server access key id",
				Value:       "",
				Required:    true,
				EnvVars:     []string{"VGW_S3_ACCESS_KEY"},
				Destination: &s3proxyAccess,
				Aliases:     []string{"a"},
			},
			&cli.StringFlag{
				Name:        "secret",
				Usage:       "s3 proxy server secret access key",
				Value:       "",
				Required:    true,
				EnvVars:     []string{"VGW_S3_SECRET_KEY"},
				Destination: &s3proxySecret,
				Aliases:     []string{"s"},
			},
			&cli.StringFlag{
				Name:        "endpoint",
				Usage:       "s3 service endpoint, default AWS if not specified",
				Value:       "",
				EnvVars:     []string{"VGW_S3_ENDPOINT"},
				Destination: &s3proxyEndpoint,
			},
			&cli.StringFlag{
				Name:        "region",
				Usage:       "s3 service region, default 'us-east-1' if not specified",
				Value:       "us-east-1",
				EnvVars:     []string{"VGW_S3_REGION"},
				Destination: &s3proxyRegion,
			},
			&cli.StringFlag{
				Name:        "meta-bucket",
				Usage:       "s3 service meta bucket to store buckets acl/policy",
				EnvVars:     []string{"VGW_S3_META_BUCKET"},
				Destination: &s3proxyMetaBucket,
			},
			&cli.BoolFlag{
				Name:        "disable-checksum",
				Usage:       "disable gateway to server object checksums",
				Value:       false,
				EnvVars:     []string{"VGW_S3_DISABLE_CHECKSUM"},
				Destination: &s3proxyDisableChecksum,
			},
			&cli.BoolFlag{
				Name:        "ssl-skip-verify",
				Usage:       "skip ssl cert verification for s3 service",
				EnvVars:     []string{"VGW_S3_SSL_SKIP_VERIFY"},
				Value:       false,
				Destination: &s3proxySslSkipVerify,
			},
			&cli.BoolFlag{
				Name:        "use-path-style",
				Usage:       "use path style addressing for s3 proxy",
				EnvVars:     []string{"VGW_S3_USE_PATH_STYLE"},
				Value:       false,
				Destination: &s3proxyUsePathStyle,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Usage:       "output extra debug tracing",
				Value:       false,
				EnvVars:     []string{"VGW_S3_DEBUG"},
				Destination: &s3proxyDebug,
			},
		},
	}
}

func runS3(ctx *cli.Context) error {
	be, err := s3proxy.New(ctx.Context, s3proxyAccess, s3proxySecret, s3proxyEndpoint, s3proxyRegion,
		s3proxyMetaBucket, s3proxyDisableChecksum, s3proxySslSkipVerify, s3proxyUsePathStyle, s3proxyDebug)
	if err != nil {
		return fmt.Errorf("init s3 backend: %w", err)
	}
	return runGateway(ctx.Context, be)
}
