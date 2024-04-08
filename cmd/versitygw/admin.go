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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3response"
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
					&cli.IntFlag{
						Name:    "user-id",
						Usage:   "userID for the new user",
						Aliases: []string{"ui"},
					},
					&cli.IntFlag{
						Name:    "group-id",
						Usage:   "groupID for the new user",
						Aliases: []string{"gi"},
					},
					&cli.IntFlag{
						Name:    "project-id",
						Usage:   "projectID for the new user",
						Aliases: []string{"pi"},
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
			{
				Name:  "change-bucket-owner",
				Usage: "Changes the bucket owner",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "bucket",
						Usage:    "the bucket name to change the owner",
						Required: true,
						Aliases:  []string{"b"},
					},
					&cli.StringFlag{
						Name:     "owner",
						Usage:    "the user access key id, who should be the bucket owner",
						Required: true,
						Aliases:  []string{"o"},
					},
				},
				Action: changeBucketOwner,
			},
			{
				Name:   "list-buckets",
				Usage:  "Lists all the gateway buckets and owners.",
				Action: listBuckets,
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
				EnvVars:     []string{"ADMIN_ENDPOINT_URL"},
				Aliases:     []string{"er"},
				Required:    true,
				Destination: &adminEndpoint,
			},
		},
	}
}

func createUser(ctx *cli.Context) error {
	access, secret, role := ctx.String("access"), ctx.String("secret"), ctx.String("role")
	userID, groupID, projectID := ctx.Int("user-id"), ctx.Int("group-id"), ctx.Int("projectID")
	if access == "" || secret == "" {
		return fmt.Errorf("invalid input parameters for the new user")
	}
	if role != string(auth.RoleAdmin) && role != string(auth.RoleUser) && role != string(auth.RoleUserPlus) {
		return fmt.Errorf("invalid input parameter for role: %v", role)
	}

	acc := auth.Account{
		Access:    access,
		Secret:    secret,
		Role:      auth.Role(role),
		UserID:    userID,
		GroupID:   groupID,
		ProjectID: projectID,
	}

	accJson, err := json.Marshal(acc)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/create-user", adminEndpoint), bytes.NewBuffer(accJson))
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256(accJson)
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s", body)
	}

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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s", body)
	}

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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s", body)
	}

	var accs []auth.Account
	if err := json.Unmarshal(body, &accs); err != nil {
		return err
	}

	printAcctTable(accs)

	return nil
}

const (
	// account table formatting
	minwidth int  = 2   // minimal cell width including any padding
	tabwidth int  = 0   // width of tab characters (equivalent number of spaces)
	padding  int  = 2   // padding added to a cell before computing its width
	padchar  byte = ' ' // ASCII char used for padding
	flags    uint = 0   // formatting control flags
)

func printAcctTable(accs []auth.Account) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, minwidth, tabwidth, padding, padchar, flags)
	fmt.Fprintln(w, "Account\tRole\tUserID\tGroupID\tProjectID")
	fmt.Fprintln(w, "-------\t----\t------\t-------\t---------")
	for _, acc := range accs {
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\n", acc.Access, acc.Role, acc.UserID, acc.GroupID, acc.ProjectID)
	}
	fmt.Fprintln(w)
	w.Flush()
}

func changeBucketOwner(ctx *cli.Context) error {
	bucket, owner := ctx.String("bucket"), ctx.String("owner")
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/change-bucket-owner/?bucket=%v&owner=%v", adminEndpoint, bucket, owner), nil)
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

	fmt.Println(string(body))

	return nil
}

func printBuckets(buckets []s3response.Bucket) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, minwidth, tabwidth, padding, padchar, flags)
	fmt.Fprintln(w, "Bucket\tOwner")
	fmt.Fprintln(w, "-------\t----")
	for _, acc := range buckets {
		fmt.Fprintf(w, "%v\t%v\n", acc.Name, acc.Owner)
	}
	fmt.Fprintln(w)
	w.Flush()
}

func listBuckets(ctx *cli.Context) error {
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/list-buckets", adminEndpoint), nil)
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s", body)
	}

	var buckets []s3response.Bucket
	if err := json.Unmarshal(body, &buckets); err != nil {
		return err
	}

	printBuckets(buckets)

	return nil
}
