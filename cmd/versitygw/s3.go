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
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/s3proxy"
)

var (
	s3proxyAccess          string
	s3proxySecret          string
	s3proxyEndpoint        string
	s3proxyRegion          string
	s3proxyDisableChecksum bool
	s3proxySslSkipVerify   bool
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
				Destination: &s3proxyAccess,
				Aliases:     []string{"a"},
			},
			&cli.StringFlag{
				Name:        "secret",
				Usage:       "s3 proxy server secret access key",
				Value:       "",
				Required:    true,
				Destination: &s3proxySecret,
				Aliases:     []string{"s"},
			},
			&cli.StringFlag{
				Name:        "endpoint",
				Usage:       "s3 service endpoint, default AWS if not specified",
				Value:       "",
				Destination: &s3proxyEndpoint,
			},
			&cli.StringFlag{
				Name:        "region",
				Usage:       "s3 service region, default 'us-east-1' if not specified",
				Value:       "us-east-1",
				Destination: &s3proxyRegion,
			},
			&cli.BoolFlag{
				Name:        "disable-checksum",
				Usage:       "disable gateway to server object checksums",
				Value:       false,
				Destination: &s3proxyDisableChecksum,
			},
			&cli.BoolFlag{
				Name:        "ssl-skip-verify",
				Usage:       "skip ssl cert verification for s3 service",
				Value:       false,
				Destination: &s3proxySslSkipVerify,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Usage:       "output extra debug tracing",
				Value:       false,
				Destination: &s3proxyDebug,
			},
		},
	}
}

func runS3(ctx *cli.Context) error {
	be := s3proxy.New(s3proxyAccess, s3proxySecret, s3proxyEndpoint, s3proxyRegion,
		s3proxyDisableChecksum, s3proxySslSkipVerify, s3proxyDebug)
	return runGateway(ctx.Context, be)
}
