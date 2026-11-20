// Copyright 2026 Versity Software
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

// Package azblobclient creates Azure Blob Storage clients from the
// account, key, SAS token and endpoint options shared by the azure
// backend and the azure IAM service.
package azblobclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// stripQueryFromURLErrors removes the query, which can hold a SAS token,
// from the URL of transport errors.
type stripQueryFromURLErrors struct{}

func (stripQueryFromURLErrors) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	var uerr *url.Error
	if errors.As(err, &uerr) {
		if u, perr := url.Parse(uerr.URL); perr == nil {
			u.RawQuery = ""
			uerr.URL = u.String()
		}
	}
	return resp, err
}

// Credentials describes how a client returned by New authenticates.
// Exactly one of SASToken, SharedKey and Default is set.
type Credentials struct {
	// ServiceURL is the blob service endpoint, defaulting to
	// https://<account>.blob.core.windows.net/ when none was provided.
	ServiceURL string
	SASToken   string
	SharedKey  *azblob.SharedKeyCredential
	Default    *azidentity.DefaultAzureCredential
}

// New returns a client for the blob service. A SAS token takes
// precedence, then an account name and key; with neither, the
// DefaultAzureCredential chain (environment, workload identity,
// managed identity, Azure CLI, ...) is used.
func New(accountName, accountKey, serviceURL, sasToken string) (*azblob.Client, Credentials, error) {
	svcURL := serviceURL
	if serviceURL == "" && accountName != "" {
		// if not otherwise specified, use the typical form:
		// http(s)://<account>.blob.core.windows.net/
		svcURL = fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
	}

	opts := &azblob.ClientOptions{ClientOptions: policy.ClientOptions{
		PerCallPolicies: []policy.Policy{stripQueryFromURLErrors{}},
	}}

	// A token copied with its leading "?" would otherwise be sent twice.
	sasToken = strings.TrimPrefix(sasToken, "?")
	if sasToken != "" {
		// Reject invalid queries before request construction can echo the token.
		if strings.ContainsFunc(sasToken, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, Credentials{}, errors.New("invalid SAS token: contains a control character")
		}
		if _, err := url.ParseQuery(sasToken); err != nil {
			return nil, Credentials{}, errors.New("invalid SAS token: malformed query")
		}
		client, err := azblob.NewClientWithNoCredential(svcURL+"?"+sasToken, opts)
		if err != nil {
			return nil, Credentials{}, fmt.Errorf("init client: %w", err)
		}
		return client, Credentials{ServiceURL: svcURL, SASToken: sasToken}, nil
	}

	if accountName == "" || accountKey == "" {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, Credentials{}, fmt.Errorf("init default credentials: %w", err)
		}
		client, err := azblob.NewClient(svcURL, cred, opts)
		if err != nil {
			return nil, Credentials{}, fmt.Errorf("init client: %w", err)
		}
		return client, Credentials{ServiceURL: svcURL, Default: cred}, nil
	}

	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, Credentials{}, fmt.Errorf("init credentials: %w", err)
	}

	client, err := azblob.NewClientWithSharedKeyCredential(svcURL, cred, opts)
	if err != nil {
		return nil, Credentials{}, fmt.Errorf("init client: %w", err)
	}

	return client, Credentials{ServiceURL: svcURL, SharedKey: cred}, nil
}
