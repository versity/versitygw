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
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
					&cli.IntFlag{
						Name:    "project-id",
						Usage:   "projectID for the new user",
						Aliases: []string{"pi"},
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
			{
				Name:   "create-bucket",
				Usage:  "Create a new bucket with owner",
				Action: createBucket,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "owner",
						Usage:    "access key id of the bucket owner",
						Required: true,
						Aliases:  []string{"o"},
					},
					&cli.StringFlag{
						Name:     "bucket",
						Usage:    "bucket name",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "acl",
						Usage: "canned ACL to apply to the bucket",
					},
					&cli.StringFlag{
						Name:  "grant-full-control",
						Usage: "Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.",
					},
					&cli.StringFlag{
						Name:  "grant-read",
						Usage: "Allows grantee to list the objects in the bucket.",
					},
					&cli.StringFlag{
						Name:  "grant-read-acp",
						Usage: "Allows grantee to read the bucket ACL.",
					},
					&cli.StringFlag{
						Name: "grant-write",
						Usage: `Allows grantee to create new objects in the bucket.
							For the bucket and object owners of existing objects, also allows deletions and overwrites of those objects.`,
					},
					&cli.StringFlag{
						Name:  "grant-write-acp",
						Usage: "Allows grantee to write the ACL for the applicable bucket.",
					},
					&cli.StringFlag{
						Name:  "create-bucket-configuration",
						Usage: "bucket configuration (LocationConstraint, Tags)",
					},
					&cli.BoolFlag{
						Name:  "object-lock-enabled-for-bucket",
						Usage: "enable object lock for the bucket",
					},
					&cli.BoolFlag{
						Name:  "no-object-lock-enabled-for-bucket",
						Usage: "disable object lock for the bucket",
					},
					&cli.StringFlag{
						Name:  "object-ownership",
						Usage: "bucket object ownership setting",
						Value: "",
					},
				},
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
	userID, groupID, projectID := ctx.Int("user-id"), ctx.Int("group-id"), ctx.Int("project-id")
	if access == "" || secret == "" {
		return fmt.Errorf("invalid input parameters for the new user access/secret keys")
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
	access, secret, userId, groupId, projectID, role :=
		ctx.String("access"),
		ctx.String("secret"),
		ctx.Int("user-id"),
		ctx.Int("group-id"),
		ctx.Int("projectID"),
		auth.Role(ctx.String("role"))

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
	if ctx.IsSet("project-id") {
		props.ProjectID = &projectID
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

type createBucketInput struct {
	LocationConstraint *string
	Tags               []types.Tag
}

// parseCreateBucketPayload parses the
func parseCreateBucketPayload(input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return []byte{}, nil
	}

	// try to parse as json, if the input starts with '{'
	if input[0] == '{' {
		var raw createBucketInput
		err := json.Unmarshal([]byte(input), &raw)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON input: %w", err)
		}

		return xml.Marshal(s3response.CreateBucketConfiguration{
			LocationConstraint: raw.LocationConstraint,
			TagSet:             raw.Tags,
		})
	}

	var config s3response.CreateBucketConfiguration

	// parse as string - shorthand syntax
	inputParts, err := splitTopLevel(input)
	if err != nil {
		return nil, err
	}
	for _, part := range inputParts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "LocationConstraint=") {
			locConstraint := strings.TrimPrefix(part, "LocationConstraint=")
			config.LocationConstraint = &locConstraint
		} else if strings.HasPrefix(part, "Tags=") {
			tags, err := parseTagging(strings.TrimPrefix(part, "Tags="))
			if err != nil {
				return nil, err
			}

			config.TagSet = tags
		} else {
			return nil, fmt.Errorf("invalid component: %v", part)
		}
	}

	return xml.Marshal(config)
}

var errInvalidTagsSyntax = errors.New("invalid tags syntax")

// splitTopLevel splits a shorthand configuration string into top-level components.
// The function splits only on commas that are not nested inside '{}' or '[]'.
func splitTopLevel(s string) ([]string, error) {
	var parts []string
	start := 0
	depth := 0

	for i, r := range s {
		switch r {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}

	if depth != 0 {
		return nil, errors.New("invalid string format")
	}

	// add last segment
	if start < len(s) {
		parts = append(parts, s[start:])
	}

	return parts, nil
}

// parseTagging parses a tag set expressed in shorthand syntax into AWS CLI tags.
// Expected format:
//
//	[{Key=string,Value=string},{Key=string,Value=string}]
//
// The function validates bracket structure, splits tag objects at the top level,
// and delegates individual tag parsing to parseTag. It returns an error if the
// syntax is invalid or if any tag entry cannot be parsed.
func parseTagging(input string) ([]types.Tag, error) {
	if len(input) < 2 {
		return nil, errInvalidTagsSyntax
	}

	if input[0] != '[' || input[len(input)-1] != ']' {
		return nil, errInvalidTagsSyntax
	}
	// strip []
	input = input[1 : len(input)-1]

	tagComponents, err := splitTopLevel(input)
	if err != nil {
		return nil, errInvalidTagsSyntax
	}
	result := make([]types.Tag, 0, len(tagComponents))
	for _, tagComponent := range tagComponents {
		tagComponent = strings.TrimSpace(tagComponent)
		tag, err := parseTag(tagComponent)
		if err != nil {
			return nil, err
		}

		result = append(result, tag)
	}

	return result, nil
}

// parseTag parses a single tag definition in shorthand form.
// Expected format:
//
// {Key=string,Value=string}
func parseTag(input string) (types.Tag, error) {
	input = strings.TrimSpace(input)

	if len(input) < 2 {
		return types.Tag{}, errInvalidTagsSyntax
	}

	if input[0] != '{' || input[len(input)-1] != '}' {
		return types.Tag{}, errInvalidTagsSyntax
	}

	// strip {}
	input = input[1 : len(input)-1]

	components := strings.Split(input, ",")
	if len(components) != 2 {
		return types.Tag{}, errInvalidTagsSyntax
	}

	var key, value string

	for _, c := range components {
		c = strings.TrimSpace(c)

		switch {
		case strings.HasPrefix(c, "Key="):
			key = strings.TrimPrefix(c, "Key=")
		case strings.HasPrefix(c, "Value="):
			value = strings.TrimPrefix(c, "Value=")
		default:
			return types.Tag{}, errInvalidTagsSyntax
		}
	}

	if key == "" {
		return types.Tag{}, errInvalidTagsSyntax
	}

	return types.Tag{
		Key:   &key,
		Value: &value,
	}, nil
}

func createBucket(ctx *cli.Context) error {
	bucket, owner := ctx.String("bucket"), ctx.String("owner")

	payload, err := parseCreateBucketPayload(ctx.String("create-bucket-configuration"))
	if err != nil {
		return fmt.Errorf("invalid create bucket configuration: %w", err)
	}

	hashedPayload := sha256.Sum256(payload)
	hexPayload := hex.EncodeToString(hashedPayload[:])

	headers := map[string]string{
		"x-amz-content-sha256":     hexPayload,
		"x-vgw-owner":              owner,
		"x-amz-acl":                ctx.String("acl"),
		"x-amz-grant-full-control": ctx.String("grant-full-control"),
		"x-amz-grant-read":         ctx.String("grant-read"),
		"x-amz-grant-read-acp":     ctx.String("grant-read-acp"),
		"x-amz-grant-write":        ctx.String("grant-write"),
		"x-amz-grant-write-acp":    ctx.String("grant-write-acp"),
		"x-amz-object-ownership":   ctx.String("object-ownership"),
	}

	if ctx.Bool("object-lock-enabled-for-bucket") {
		headers["x-amz-bucket-object-lock-enabled"] = "true"
	}
	if ctx.Bool("no-object-lock-enabled-for-bucket") {
		headers["x-amz-bucket-object-lock-enabled"] = "false"
	}

	req, err := http.NewRequestWithContext(ctx.Context, http.MethodPatch, fmt.Sprintf("%s/%s/create", adminEndpoint, bucket), bytes.NewReader(payload))
	if err != nil {
		return err
	}

	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}

	signer := v4.NewSigner()
	err = signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: adminAccess, SecretAccessKey: adminSecret}, req, hexPayload, "s3", adminRegion, time.Now())
	if err != nil {
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
