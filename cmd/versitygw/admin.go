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
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3response"
)

var (
	adminAccess   string
	adminSecret   string
	adminRegion   string
	adminEndpoint string
	allowInsecure bool
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
				},
			},
			{
				Name:   "update-user",
				Usage:  "Updates a user account",
				Action: updateUser,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "access",
						Usage:    "user access key id to be updated",
						Required: true,
						Aliases:  []string{"a"},
					},
					&cli.StringFlag{
						Name:    "secret",
						Usage:   "secret access key for the new user",
						Aliases: []string{"s"},
					},
					&cli.StringFlag{
						Name:    "role",
						Usage:   "the new user role",
						Aliases: []string{"r"},
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
				Name:        "region",
				Usage:       "admin s3 region string",
				EnvVars:     []string{"ADMIN_REGION"},
				Value:       "us-east-1",
				Destination: &adminRegion,
				Aliases:     []string{"r"},
			},
			&cli.StringFlag{
				Name:        "endpoint-url",
				Usage:       "admin apis endpoint url",
				EnvVars:     []string{"ADMIN_ENDPOINT_URL"},
				Aliases:     []string{"er"},
				Required:    true,
				Destination: &adminEndpoint,
			},
			&cli.BoolFlag{
				Name:        "allow-insecure",
				Usage:       "disable tls certificate verification for the admin endpoint",
				EnvVars:     []string{"ADMIN_ALLOW_INSECURE"},
				Aliases:     []string{"ai"},
				Destination: &allowInsecure,
			},
		},
	}
}

func initHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecure},
	}
	return &http.Client{Transport: tr}
}

func createUser(ctx *cli.Context) error {
	access, secret, role := ctx.String("access"), ctx.String("secret"), ctx.String("role")
	userID, groupID := ctx.Int("user-id"), ctx.Int("group-id")
	if access == "" || secret == "" {
		return fmt.Errorf("invalid input parameters for the new user access/secret keys")
	}
	if role != string(auth.RoleAdmin) && role != string(auth.RoleUser) && role != string(auth.RoleUserPlus) {
		return fmt.Errorf("invalid input parameter for role: %v", role)
	}

	acc := auth.Account{
		Access:  access,
		Secret:  secret,
		Role:    auth.Role(role),
		UserID:  userID,
		GroupID: groupID,
	}

	accxml, err := xml.Marshal(acc)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/create-user", adminEndpoint), bytes.NewBuffer(accxml))
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256(accxml)
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := initHTTPClient()

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
		return parseApiError(body)
	}

	return nil
}

func deleteUser(ctx *cli.Context) error {
	access := ctx.String("access")
	if access == "" {
		return fmt.Errorf("invalid input parameter for the user access key")
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/delete-user?access=%v", adminEndpoint, access), nil)
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

	client := initHTTPClient()

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
		return parseApiError(body)
	}

	return nil
}

func updateUser(ctx *cli.Context) error {
	access, secret, userId, groupId, role := ctx.String("access"), ctx.String("secret"), ctx.Int("user-id"), ctx.Int("group-id"), auth.Role(ctx.String("role"))
	props := auth.MutableProps{}
	if ctx.IsSet("role") {
		if !role.IsValid() {
			return fmt.Errorf("invalid user role: %v", role)
		}
		props.Role = role
	}
	if ctx.IsSet("secret") {
		props.Secret = &secret
	}
	if ctx.IsSet("user-id") {
		props.UserID = &userId
	}
	if ctx.IsSet("group-id") {
		props.GroupID = &groupId
	}

	propsxml, err := xml.Marshal(props)
	if err != nil {
		return fmt.Errorf("failed to parse user attributes: %w", err)
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/update-user?access=%v", adminEndpoint, access), bytes.NewBuffer(propsxml))
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256(propsxml)
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := initHTTPClient()

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
		return parseApiError(body)
	}

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

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := initHTTPClient()

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
		return parseApiError(body)
	}

	var accs auth.ListUserAccountsResult
	if err := xml.Unmarshal(body, &accs); err != nil {
		return err
	}

	printAcctTable(accs.Accounts)

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
	fmt.Fprintln(w, "Account\tRole\tUserID\tGroupID")
	fmt.Fprintln(w, "-------\t----\t------\t-------")
	for _, acc := range accs {
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", acc.Access, acc.Role, acc.UserID, acc.GroupID)
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

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := initHTTPClient()

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
		return parseApiError(body)
	}

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

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := initHTTPClient()

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
		return parseApiError(body)
	}

	var result s3response.ListBucketsResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return err
	}

	printBuckets(result.Buckets)

	return nil
}

func parseApiError(body []byte) error {
	var apiErr smithy.GenericAPIError
	err := xml.Unmarshal(body, &apiErr)
	if err != nil {
		apiErr.Code = "InternalServerError"
		apiErr.Message = err.Error()
	}

	return &apiErr
}
