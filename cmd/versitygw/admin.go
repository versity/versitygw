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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/urfave/cli/v2"
)

var (
	adminAccess string
	adminSecret string
	adminRegion string
)

func adminCommand() *cli.Command {
	return &cli.Command{
		Name:  "admin",
		Usage: "admin CLI tool",
		Description: `admin CLI tool for interacting with admin api.
		Here is the available api list:
		create-user
		`,
		Subcommands: []*cli.Command{
			{
				Name:   "create-user",
				Usage:  "Create a new user",
				Action: createUser,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "access",
						Usage:    "access value for the new user",
						Required: true,
						Aliases:  []string{"a"},
					},
					&cli.StringFlag{
						Name:     "secret",
						Usage:    "secret value for the new user",
						Required: true,
						Aliases:  []string{"s"},
					},
					&cli.StringFlag{
						Name:     "role",
						Usage:    "role for the new user",
						Required: true,
						Aliases:  []string{"r"},
					},
					&cli.StringFlag{
						Name:    "region",
						Usage:   "s3 region string for the user",
						Value:   "us-east-1",
						Aliases: []string{"rg"},
					},
				},
			},
		},
		Flags: []cli.Flag{
			// TODO: create a configuration file for this
			&cli.StringFlag{
				Name:        "adminAccess",
				Usage:       "admin access account",
				EnvVars:     []string{"ADMIN_ACCESS_KEY_ID", "ADMIN_ACCESS_KEY"},
				Aliases:     []string{"aa"},
				Destination: &adminAccess,
			},
			&cli.StringFlag{
				Name:        "adminSecret",
				Usage:       "admin secret access key",
				EnvVars:     []string{"ADMIN_SECRET_ACCESS_KEY", "ADMIN_SECRET_KEY"},
				Aliases:     []string{"as"},
				Destination: &adminSecret,
			},
			&cli.StringFlag{
				Name:        "adminRegion",
				Usage:       "s3 region string",
				Value:       "us-east-1",
				Destination: &adminRegion,
				Aliases:     []string{"ar"},
			},
		},
	}
}

func createUser(ctx *cli.Context) error {
	access, secret, role, region := ctx.String("access"), ctx.String("secret"), ctx.String("role"), ctx.String("region")
	if access == "" || secret == "" || region == "" {
		return fmt.Errorf("invalid input parameters for the new user")
	}
	if role != "admin" && role != "user" {
		return fmt.Errorf("invalid input parameter for role")
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost:7070/create-user?access=%v&secret=%v&role=%v&region=%v", access, secret, role, region), nil)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("%s", body)

	return nil
}
