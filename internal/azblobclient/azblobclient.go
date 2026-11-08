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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// stripQueryFromURLErrors removes the query, which can hold a SAS token,
// from the URL of transport errors. The service client and the
// per-container and per-blob clients must all run it: those clients are
// built outside New.
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

// retryOptions configures the retries of clients built with ClientOptions.
// The zero value keeps the SDK defaults; tests change it to fail fast.
var retryOptions policy.RetryOptions

// ClientOptions returns the options every blob client must use so a SAS
// token in the request URL cannot reach a transport error. The zero Retry
// value keeps the SDK defaults; tests in this package set retryOptions to
// fail fast.
func ClientOptions() policy.ClientOptions {
	return policy.ClientOptions{
		Retry:           retryOptions,
		PerCallPolicies: []policy.Policy{stripQueryFromURLErrors{}},
	}
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

	opts := &azblob.ClientOptions{ClientOptions: ClientOptions()}

	if sasToken != "" {
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
