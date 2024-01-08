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
	"github.com/versity/versitygw/backend/azure"
)

var (
	azAccount, azKey, azServiceURL string
)

func azureCommand() *cli.Command {
	return &cli.Command{
		Name:        "azure",
		Usage:       "azure blob storage backend",
		Description: `direct translation from s3 objects to azure blobs`,
		Action:      runAzure,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "account",
				Usage:       "azure account name",
				EnvVars:     []string{"AZ_ACCOUNT_NAME"},
				Aliases:     []string{"a"},
				Destination: &azAccount,
			},
			&cli.StringFlag{
				Name:        "access-key",
				Usage:       "azure account key",
				EnvVars:     []string{"AZ_ACCESS_KEY"},
				Aliases:     []string{"k"},
				Destination: &azKey,
			},
			&cli.StringFlag{
				Name:        "url",
				Usage:       "azure service URL",
				EnvVars:     []string{"AZ_ENDPOINT"},
				Aliases:     []string{"u"},
				Destination: &azServiceURL,
			},
		},
	}
}

func runAzure(ctx *cli.Context) error {
	if azServiceURL == "" {
		// if not otherwise specified, use the typical form: http(s)://<account>.blob.core.windows.net/
		azServiceURL = fmt.Sprintf("https://%s.blob.core.windows.net/", azAccount)
	}

	be, err := azure.New(azAccount, azKey, azServiceURL)
	if err != nil {
		return fmt.Errorf("init azure: %v", err)
	}

	return runGateway(ctx.Context, be)
}
