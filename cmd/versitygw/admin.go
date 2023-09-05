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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
)

var (
	adminAccess   string
	adminSecret   string
	adminEndpoint string
)

func adminCommand() *cli.Command {
	return &cli.Command{
		Name:        "admin",
		Usage:       "admin CLI tool",
		Description: `Admin CLI tool for interacting with admin APIs.`,
		Subcommands: []*cli.Command{
			{
				Name:   "create-user",
				Usage:  "Create a new user",
				Action: createUser,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "access",
						Usage:    "access key id for the new user",
						Required: true,
						Aliases:  []string{"a"},
					},
					&cli.StringFlag{
						Name:     "secret",
						Usage:    "secret access key for the new user",
						Required: true,
						Aliases:  []string{"s"},
					},
					&cli.StringFlag{
						Name:     "role",
						Usage:    "role for the new user",
						Required: true,
						Aliases:  []string{"r"},
					},
				},
			},
			{
				Name:   "delete-user",
				Usage:  "Delete a user",
				Action: deleteUser,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "access",
						Usage:    "access key id of the user to be deleted",
						Required: true,
						Aliases:  []string{"a"},
					},
				},
			},
			{
				Name:   "list-users",
				Usage:  "List all the gateway users",
				Action: listUsers,
			},
		},
		Flags: []cli.Flag{
			// TODO: create a configuration file for this
			&cli.StringFlag{
				Name:        "access",
				Usage:       "admin access key id",
				EnvVars:     []string{"ADMIN_ACCESS_KEY_ID", "ADMIN_ACCESS_KEY"},
				Aliases:     []string{"a"},
				Required:    true,
				Destination: &adminAccess,
			},
			&cli.StringFlag{
				Name:        "secret",
				Usage:       "admin secret access key",
				EnvVars:     []string{"ADMIN_SECRET_ACCESS_KEY", "ADMIN_SECRET_KEY"},
				Aliases:     []string{"s"},
				Required:    true,
				Destination: &adminSecret,
			},
			&cli.StringFlag{
				Name:        "endpoint-url",
				Usage:       "admin apis endpoint url",
				Aliases:     []string{"er"},
				Required:    true,
				Destination: &adminEndpoint,
			},
		},
	}
}

func createUser(ctx *cli.Context) error {
	access, secret, role := ctx.String("access"), ctx.String("secret"), ctx.String("role")
	if access == "" || secret == "" {
		return fmt.Errorf("invalid input parameters for the new user")
	}
	if role != "admin" && role != "user" {
		return fmt.Errorf("invalid input parameter for role")
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/create-user?access=%v&secret=%v&role=%v", adminEndpoint, access, secret, role), nil)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", region, time.Now())
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
	defer resp.Body.Close()

	fmt.Printf("%s\n", body)

	return nil
}

func deleteUser(ctx *cli.Context) error {
	access := ctx.String("access")
	if access == "" {
		return fmt.Errorf("invalid input parameter for the new user")
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/delete-user?access=%v", adminEndpoint, access), nil)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", region, time.Now())
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
	defer resp.Body.Close()

	fmt.Printf("%s\n", body)

	return nil
}

func listUsers(ctx *cli.Context) error {
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/list-users", adminEndpoint), nil)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", region, time.Now())
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
	defer resp.Body.Close()

	var accs []auth.UserAcc
	if err := json.Unmarshal(body, &accs); err != nil {
		return err
	}

	jsonData, err := json.MarshalIndent(accs, "", "    ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))

	return nil
}
